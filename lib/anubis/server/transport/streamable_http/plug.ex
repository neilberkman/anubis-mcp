if Code.ensure_loaded?(Plug) do
  defmodule Anubis.Server.Transport.StreamableHTTP.Plug do
    @moduledoc """
    A Plug implementation for the Streamable HTTP transport.

    This plug handles the MCP Streamable HTTP protocol as specified in MCP 2025-03-26.
    It provides a single endpoint that supports both GET and POST methods:

    - GET: Opens an SSE stream for server-to-client communication
    - POST: Handles JSON-RPC messages from client to server
    - DELETE: Closes a session

    ## Usage in Phoenix Router

        pipeline :mcp do
          plug :accepts, ["json"]
        end

        scope "/mcp" do
          pipe_through :mcp
          forward "/", to: Anubis.Server.Transport.StreamableHTTP.Plug, server: :your_server_name
        end

    ## Configuration Options

    - `:server` - The server process name (required)
    - `:session_header` - Custom header name for session ID (default: "mcp-session-id")
    - `:request_timeout` - Request timeout in milliseconds (default: 30000)
    - `:subscriber_metadata` - A 1-arity function `(Plug.Conn.t() -> map())` called
      when an SSE stream is opened. Its return value is stored verbatim as the
      subscriber's opaque metadata (see
      `Anubis.Server.Transport.StreamableHTTP.register_sse_handler/3`) and can later
      be selected on with `send_message_to_subscribers/4` and `handler_count/2`.
      Tag subscribers by tenant, user, feature scope, etc. derived from the request.
      Defaults to `fn _conn -> %{} end`. Use a remote function capture
      (`&MyApp.sse_metadata/1`) so it survives compile-time plug option escaping.
    """

    @behaviour Plug

    use Anubis.Logging

    import Plug.Conn

    alias Anubis.MCP.Error
    alias Anubis.MCP.ID
    alias Anubis.MCP.Message
    alias Anubis.Server.Authorization
    alias Anubis.Server.Registry
    alias Anubis.Server.Supervisor, as: ServerSupervisor
    alias Anubis.Server.Transport.Session
    alias Anubis.Server.Transport.StreamableHTTP
    alias Anubis.SSE.Streaming
    alias Anubis.Telemetry
    alias Plug.Conn.Unfetched

    require Message

    @default_session_header "mcp-session-id"
    @default_timeout 30_000

    # Plug callbacks

    @impl Plug
    def init(opts) do
      server = Keyword.fetch!(opts, :server)
      session_header = Keyword.get(opts, :session_header, @default_session_header)
      request_timeout = Keyword.get(opts, :request_timeout, @default_timeout)
      subscriber_metadata = Keyword.get(opts, :subscriber_metadata, &default_subscriber_metadata/1)

      %{
        server: server,
        session_header: session_header,
        timeout: request_timeout,
        subscriber_metadata: subscriber_metadata
      }
    end

    defp default_subscriber_metadata(_conn), do: %{}

    defp resolve_subscriber_metadata(opts, conn) do
      fun = Map.get(opts, :subscriber_metadata, &default_subscriber_metadata/1)

      case fun.(conn) do
        metadata when is_map(metadata) ->
          metadata

        other ->
          Logging.transport_event(
            "invalid_subscriber_metadata",
            %{returned: inspect(other)},
            level: :warning
          )

          %{}
      end
    end

    @impl Plug
    def call(conn, opts) do
      opts = resolve_runtime_config(opts)

      if conn.request_path == "/.well-known/oauth-protected-resource" do
        handle_well_known(conn, opts)
      else
        case authorize(conn, opts) do
          {:ok, conn, claims} ->
            opts
            |> Map.put(:auth_claims, claims)
            |> then(&handle_request(conn, &1))

          {:halt, conn} ->
            conn
        end
      end
    end

    # MCP revision 2026-07-28 ("modern") removed sessions and the initialize
    # handshake: every request carries its protocol version, client identity
    # and capabilities in `params._meta`, and the server answers each one on
    # its own. Revisions up to 2025-11-25 ("legacy") establish a session with
    # `initialize`. This transport serves both on the same endpoint, selecting
    # by the `MCP-Protocol-Version` header exactly as the specification's
    # dual-era server does: a modern request is served statelessly, anything
    # else takes the session path it always took.
    @modern_version "2026-07-28"
    @meta_version "io.modelcontextprotocol/protocolVersion"
    @meta_client_info "io.modelcontextprotocol/clientInfo"
    @meta_client_capabilities "io.modelcontextprotocol/clientCapabilities"
    @meta_server_info "io.modelcontextprotocol/serverInfo"
    @modern_meta_keys [
      @meta_version,
      @meta_client_info,
      @meta_client_capabilities,
      "io.modelcontextprotocol/logLevel"
    ]
    @header_mismatch_code -32_020
    @unsupported_version_code -32_022
    @discover_ttl_ms 300_000
    @list_ttl_ms 60_000
    @cacheable_methods ~w(tools/list prompts/list resources/list resources/read resources/templates/list)

    defp handle_request(conn, opts) do
      case get_req_header(conn, "mcp-protocol-version") do
        [@modern_version | _] ->
          handle_modern(conn, opts)

        [] ->
          handle_legacy(conn, opts)

        [version | _] ->
          if version in supported_protocol_versions(opts.server) do
            handle_legacy(conn, opts)
          else
            Logging.transport_event("unsupported_protocol_version", %{version: version}, level: :warning)

            send_unsupported_version(conn, version, opts, nil)
          end
      end
    end

    defp handle_legacy(conn, opts) do
      case conn.method do
        "GET" -> handle_get(conn, opts)
        "POST" -> handle_post(conn, opts)
        "DELETE" -> handle_delete(conn, opts)
        _ -> send_error(conn, 405, "Method not allowed")
      end
    end

    # ---------------------------------------------------------------------------
    # Modern (2026-07-28) requests
    # ---------------------------------------------------------------------------

    defp handle_modern(%{method: "POST"} = conn, opts) do
      with :ok <- validate_accept_header(conn),
           {:ok, body, conn} <- maybe_read_request_body(conn, opts) do
        # The modern method set (`server/discover`, `subscriptions/listen`) is
        # not in the legacy decoder's vocabulary, and the legacy schemas do not
        # know the modern `_meta` keys, so a modern body is decoded as plain
        # JSON-RPC here; the session's own handler answers for the method.
        case parse_modern_message(body) do
          {:ok, message} ->
            case validate_modern_headers(conn, message) do
              :ok -> modern_message(conn, message, opts)
              {:error, detail} -> send_header_mismatch(conn, detail, extract_request_id(message))
            end

          {:error, :batch} ->
            send_jsonrpc_error(
              conn,
              Error.protocol(:invalid_request, %{message: "Batched requests are not supported"}),
              nil
            )

          {:error, reason} ->
            send_parse_failure(conn, body, reason)
        end
      else
        {:error, :invalid_accept_header} ->
          send_error(conn, 406, "Not Acceptable: Client must accept application/json")

        {:error, reason} ->
          Logging.transport_event("request_error", %{reason: reason}, level: :error)
          send_jsonrpc_error(conn, Error.protocol(:internal_error, %{reason: reason}), nil)
      end
    end

    # The modern revision has no GET stream and no DELETE; a modern client that
    # sends one gets the answer the specification prescribes.
    defp handle_modern(conn, _opts), do: send_error(conn, 405, "Method not allowed")

    defp parse_modern_message(body) when is_map(body), do: check_modern_message(body)

    defp parse_modern_message(body) when is_binary(body) do
      case decode_json(body) do
        {:ok, decoded} -> check_modern_message(decoded)
        {:error, _reason} -> {:error, :invalid_json}
      end
    end

    defp parse_modern_message(_body), do: {:error, :invalid_request}

    defp check_modern_message(list) when is_list(list), do: {:error, :batch}

    defp check_modern_message(%{"jsonrpc" => "2.0", "method" => method} = message) when is_binary(method) do
      {:ok, message}
    end

    defp check_modern_message(_message), do: {:error, :invalid_request}

    defp modern_message(conn, message, opts) do
      cond do
        Message.is_notification(message) ->
          Logging.transport_event("parsed_messages", %{method: message["method"], id: nil, session_id: nil})

          conn
          |> put_resp_content_type("application/json")
          |> send_resp(202, "{}")

        Message.is_request(message) ->
          Logging.transport_event("parsed_messages", %{
            method: message["method"],
            id: message["id"],
            session_id: nil
          })

          modern_request(conn, message, opts)

        true ->
          send_jsonrpc_error(
            conn,
            Error.protocol(:invalid_request, %{message: "Invalid message type"}),
            nil
          )
      end
    end

    # `server/discover` is the one modern method answered without touching the
    # server process: identity, capabilities and the versions this endpoint
    # speaks (the modern one plus every legacy one the server accepts).
    defp modern_request(conn, %{"method" => "server/discover"} = message, opts) do
      server = opts.server

      result =
        maybe_put_instructions(
          %{
            "resultType" => "complete",
            "supportedVersions" => discoverable_versions(server),
            "capabilities" => server.server_capabilities(),
            "_meta" => %{@meta_server_info => server.server_info()},
            "ttlMs" => @discover_ttl_ms,
            "cacheScope" => "private"
          },
          server
        )

      send_modern_result(conn, message["id"], result)
    end

    # Every other modern request is served through the legacy machinery on a
    # session that lives for exactly this request: a synthetic `initialize`
    # (client identity and capabilities read from `_meta`), the request itself,
    # and teardown. Nothing about the session reaches the client: no session
    # header is minted, so the next request starts clean again. The legacy
    # handlers, the authorization context and every tool run unchanged.
    defp modern_request(conn, message, opts) do
      session_id = ID.generate_session_id()
      context = build_request_context(conn, Map.get(opts, :auth_claims))

      case start_new_session(opts, session_id) do
        {:ok, session_pid} ->
          try do
            case Session.dispatch_request(session_pid, synthetic_initialize(message, opts), context,
                   timeout: opts.timeout
                 ) do
              {:ok, _initialized} ->
                Session.dispatch_notification(session_pid, initialized_notification(), context)

                case Session.dispatch_request(session_pid, strip_modern_meta(message), context, timeout: opts.timeout) do
                  {:ok, response} when is_binary(response) ->
                    send_modern_response(conn, message, response, opts.server)

                  {:ok, nil} ->
                    send_modern_result(conn, message["id"], %{"resultType" => "complete"})

                  {:error, error} ->
                    handle_request_error(conn, error, message)
                end

              {:error, error} ->
                handle_request_error(conn, error, message)
            end
          catch
            :exit, reason ->
              Logging.transport_event("session_call_failed", %{reason: reason}, level: :error)

              send_jsonrpc_error(
                conn,
                Error.protocol(:internal_error, %{message: "Server unavailable"}),
                extract_request_id(message)
              )
          after
            stop_session_process(opts, session_id)
          end

        {:error, reason} ->
          send_jsonrpc_error(conn, Error.wrap_reason(reason), extract_request_id(message))
      end
    end

    defp synthetic_initialize(message, opts) do
      meta = modern_meta(message)

      %{
        "jsonrpc" => "2.0",
        "id" => "modern-initialize",
        "method" => "initialize",
        "params" => %{
          "protocolVersion" => legacy_version_for(opts.server),
          "clientInfo" => Map.get(meta, @meta_client_info) || %{"name" => "modern-client", "version" => @modern_version},
          "capabilities" => Map.get(meta, @meta_client_capabilities) || %{}
        }
      }
    end

    defp initialized_notification, do: %{"jsonrpc" => "2.0", "method" => "notifications/initialized"}

    defp modern_meta(%{"params" => %{"_meta" => meta}}) when is_map(meta), do: meta
    defp modern_meta(_message), do: %{}

    # The modern `_meta` keys describe the request's era and its sender; the
    # legacy handlers neither expect nor validate them. Everything else in
    # `_meta` (a progress token, trace context) is passed through.
    defp strip_modern_meta(%{"params" => %{"_meta" => meta} = params} = message) when is_map(meta) do
      case Map.drop(meta, @modern_meta_keys) do
        empty when map_size(empty) == 0 -> %{message | "params" => Map.delete(params, "_meta")}
        rest -> %{message | "params" => Map.put(params, "_meta", rest)}
      end
    end

    defp strip_modern_meta(message), do: message

    # The newest legacy revision this server accepts; the synthetic initialize
    # negotiates it so the session behaves exactly as a current legacy client's.
    defp legacy_version_for(server) do
      server
      |> supported_protocol_versions()
      |> Enum.find(Anubis.Protocol.Registry.latest_version(), fn version ->
        Anubis.Protocol.Registry.get(version) != :error
      end)
    end

    defp discoverable_versions(server) do
      Enum.uniq([@modern_version | supported_protocol_versions(server)])
    end

    defp maybe_put_instructions(result, server) do
      if Anubis.exported?(server, :server_instructions, 0) do
        case server.server_instructions() do
          instructions when is_binary(instructions) and instructions != "" ->
            Map.put(result, "instructions", instructions)

          _ ->
            result
        end
      else
        result
      end
    end

    # A legacy response, re-shaped as a modern result: `resultType` (every
    # modern result carries one), the server's identity in `_meta`, and cache
    # hints on the list and read methods that require them. A legacy error
    # passes through unchanged, except that an unknown method is 404 as the
    # modern transport prescribes.
    defp send_modern_response(conn, message, response, server) do
      case decode_json(response) do
        {:ok, %{"result" => result} = envelope} when is_map(result) ->
          shaped = modernize_result(result, message["method"], server)

          conn
          |> put_resp_content_type("application/json")
          |> send_resp(200, encode_json!(Map.put(envelope, "result", shaped)))

        {:ok, %{"error" => %{"code" => -32_601}}} ->
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(404, response)

        _ ->
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(200, response)
      end
    end

    defp modernize_result(result, method, server) do
      result
      |> Map.put_new("resultType", "complete")
      |> Map.update("_meta", %{@meta_server_info => server.server_info()}, fn meta ->
        Map.put_new(meta, @meta_server_info, server.server_info())
      end)
      |> maybe_put_cache_hints(method)
    end

    defp maybe_put_cache_hints(result, method) when method in @cacheable_methods do
      result
      |> Map.put_new("ttlMs", @list_ttl_ms)
      |> Map.put_new("cacheScope", "private")
    end

    defp maybe_put_cache_hints(result, _method), do: result

    defp send_modern_result(conn, id, result) do
      body = %{"jsonrpc" => "2.0", "id" => id, "result" => result}

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, encode_json!(body))
    end

    # The mirrored request headers must agree with the body when they are
    # present; a header the client did not send is not held against it, so
    # clients from the revision's early days keep working.
    defp validate_modern_headers(conn, message) do
      with :ok <- check_header(conn, "mcp-method", message["method"], "Mcp-Method"),
           :ok <- check_header(conn, "mcp-name", modern_name(message), "Mcp-Name") do
        check_meta_version(message)
      end
    end

    defp check_header(conn, header, body_value, label) do
      case get_req_header(conn, header) do
        [] ->
          :ok

        [value | _] ->
          if decode_header_value(value) == body_value do
            :ok
          else
            {:error, "#{label} header value #{inspect(value)} does not match body value #{inspect(body_value)}"}
          end
      end
    end

    defp check_meta_version(message) do
      case Map.get(modern_meta(message), @meta_version) do
        nil -> :ok
        @modern_version -> :ok
        other -> {:error, "MCP-Protocol-Version header #{@modern_version} does not match body value #{inspect(other)}"}
      end
    end

    defp modern_name(%{"params" => %{"name" => name}}) when is_binary(name), do: name
    defp modern_name(%{"params" => %{"uri" => uri}}) when is_binary(uri), do: uri
    defp modern_name(_message), do: nil

    defp decode_header_value("=?base64?" <> rest) do
      with true <- String.ends_with?(rest, "?="),
           {:ok, decoded} <- rest |> String.trim_trailing("?=") |> Base.decode64() do
        decoded
      else
        _ -> "=?base64?" <> rest
      end
    end

    defp decode_header_value(value), do: value

    defp send_header_mismatch(conn, detail, id) do
      send_modern_error(conn, 400, id, @header_mismatch_code, "Header mismatch: #{detail}", nil)
    end

    defp send_unsupported_version(conn, requested, opts, id) do
      send_modern_error(conn, 400, id, @unsupported_version_code, "Unsupported protocol version", %{
        "supported" => discoverable_versions(opts.server),
        "requested" => requested
      })
    end

    defp send_modern_error(conn, status, id, code, message, data) do
      error = %{"code" => code, "message" => message}
      error = if data, do: Map.put(error, "data", data), else: error

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, encode_json!(%{"jsonrpc" => "2.0", "id" => id, "error" => error}))
    end

    defp supported_protocol_versions(server) do
      if Anubis.exported?(server, :supported_protocol_versions, 0) do
        server.supported_protocol_versions()
      else
        Anubis.Protocol.Registry.supported_versions()
      end
    end

    defp resolve_runtime_config(%{server: server} = opts) do
      session_config = ServerSupervisor.get_session_config(server)
      auth_config = ServerSupervisor.get_authorization_config(server)

      Map.merge(opts, %{
        registry_mod: session_config.registry_mod,
        registry_name: Registry.registry_name(server),
        transport: Registry.transport_name(server, :streamable_http),
        authorization: auth_config
      })
    end

    # GET request handler - establishes SSE connection

    defp handle_get(conn, %{transport: transport, session_header: session_header} = opts) do
      if wants_sse?(conn) do
        session_id = get_or_create_session_id(conn, session_header)
        metadata = resolve_subscriber_metadata(opts, conn)
        resume_from = parse_last_event_id(conn)

        case StreamableHTTP.register_sse_handler(transport, session_id, metadata) do
          :ok ->
            params =
              opts
              |> Map.put(:session_id, session_id)
              |> Map.put(:resume_from, resume_from)

            start_sse_streaming(conn, params)

          {:error, reason} ->
            Logging.transport_event("sse_registration_failed", %{reason: reason}, level: :error)

            send_error(conn, 500, "Could not establish SSE connection")
        end
      else
        send_error(conn, 406, "Accept header must include text/event-stream")
      end
    end

    # Parses the client's resumption cursor from the `Last-Event-ID` header.
    # Returns the event id as a non-negative integer, or `nil` when the header is
    # absent or not a well-formed cursor issued by this transport.
    defp parse_last_event_id(conn) do
      case get_req_header(conn, "last-event-id") do
        [value | _] ->
          case Integer.parse(value) do
            {id, ""} when id >= 0 -> id
            _ -> nil
          end

        [] ->
          nil
      end
    end

    # POST request handler - processes MCP messages directly to Session

    defp handle_post(conn, %{session_header: session_header} = opts) do
      with :ok <- validate_accept_header(conn),
           {:ok, body, conn} <- maybe_read_request_body(conn, opts) do
        case maybe_parse_messages(body) do
          {:ok, [message]} ->
            session_id = determine_session_id(conn, session_header, message)
            context = build_request_context(conn, Map.get(opts, :auth_claims))

            Logging.transport_event("parsed_messages", %{
              method: message["method"],
              id: message["id"],
              session_id: session_id
            })

            process_message(conn, message, session_id, context, opts)

          {:ok, _batch} ->
            send_jsonrpc_error(
              conn,
              Error.protocol(:invalid_request, %{message: "Batched requests are not supported"}),
              nil
            )

          {:error, reason} ->
            send_parse_failure(conn, body, reason)
        end
      else
        {:error, :invalid_accept_header} ->
          send_error(
            conn,
            406,
            "Not Acceptable: Client must accept application/json"
          )

        {:error, reason} ->
          Logging.transport_event("request_error", %{reason: reason}, level: :error)

          send_jsonrpc_error(
            conn,
            Error.protocol(:internal_error, %{reason: reason}),
            nil
          )
      end
    end

    defp send_parse_failure(conn, body, reason) do
      case reason do
        :parse_error ->
          send_jsonrpc_error(
            conn,
            Error.protocol(:parse_error, %{message: "Parse error"}),
            nil
          )

        :invalid_json ->
          send_jsonrpc_error(
            conn,
            Error.protocol(:parse_error, %{message: "Invalid JSON"}),
            nil
          )

        :invalid_request ->
          send_jsonrpc_error(
            conn,
            Error.protocol(:invalid_request, %{message: "Invalid Request"}),
            extract_request_id_from_body(body)
          )

        :method_not_found ->
          send_jsonrpc_error(
            conn,
            Error.protocol(:method_not_found, %{message: "Method not found"}),
            extract_request_id_from_body(body)
          )

        other ->
          Logging.transport_event("request_error", %{reason: other}, level: :error)

          send_jsonrpc_error(
            conn,
            Error.protocol(:internal_error, %{reason: other}),
            nil
          )
      end
    end

    defp process_message(conn, message, session_id, context, opts) do
      cond do
        Message.is_notification(message) ->
          handle_notification_message(conn, message, session_id, context, opts)

        Message.is_response(message) or Message.is_error(message) ->
          handle_response_message(conn, message, session_id, context, opts)

        Message.is_request(message) ->
          handle_request_message(conn, message, session_id, context, opts)

        true ->
          send_jsonrpc_error(
            conn,
            Error.protocol(:invalid_request, %{message: "Invalid message type"}),
            nil
          )
      end
    end

    defp handle_notification_message(conn, message, session_id, context, opts) do
      case find_or_restore_session(opts, session_id, context) do
        {:ok, session_pid} ->
          Session.dispatch_notification(session_pid, message, context)

          conn
          |> put_resp_content_type("application/json")
          |> send_resp(202, "{}")

        {:error, _} ->
          send_error(conn, 404, "Session not found")
      end
    end

    defp handle_response_message(conn, message, session_id, context, opts) do
      case find_or_restore_session(opts, session_id, context) do
        {:ok, session_pid} ->
          Session.dispatch_response(session_pid, message, context)

          conn
          |> put_resp_content_type("application/json")
          |> send_resp(202, "{}")

        {:error, _} ->
          send_error(conn, 404, "Session not found")
      end
    end

    defp handle_request_message(conn, message, session_id, context, opts) do
      case find_or_create_session(opts, session_id, message, context) do
        {:ok, session_pid} ->
          if wants_sse?(conn) do
            handle_sse_request(conn, session_pid, message, session_id, context, opts)
          else
            handle_json_request(conn, session_pid, message, session_id, context, opts)
          end

        {:error, reason} ->
          if reason == :not_found do
            send_error(conn, 404, "Session not found")
          else
            send_jsonrpc_error(
              conn,
              Error.wrap_reason(reason),
              extract_request_id(message)
            )
          end
      end
    end

    defp handle_json_request(conn, session_pid, message, session_id, context, %{session_header: session_header} = opts) do
      case Session.dispatch_request(session_pid, message, context, timeout: opts.timeout) do
        {:ok, response} when is_binary(response) ->
          conn
          |> put_resp_content_type("application/json")
          |> maybe_add_session_header(session_header, session_id)
          |> send_resp(200, response)

        {:ok, nil} ->
          conn
          |> put_resp_content_type("application/json")
          |> maybe_add_session_header(session_header, session_id)
          |> send_resp(200, "{}")

        {:error, error} ->
          handle_request_error(conn, error, message)
      end
    catch
      :exit, reason ->
        Logging.transport_event("session_call_failed", %{reason: reason}, level: :error)

        send_jsonrpc_error(
          conn,
          Error.protocol(:internal_error, %{message: "Server unavailable"}),
          extract_request_id(message)
        )
    end

    defp handle_sse_request(conn, session_pid, message, session_id, context, opts) do
      %{session_header: session_header} = opts

      case Session.dispatch_request(session_pid, message, context, timeout: opts.timeout) do
        {:ok, response} when is_binary(response) ->
          stream_response_on_conn(conn, response, session_id, session_header)

        {:ok, nil} ->
          conn
          |> put_resp_content_type("application/json")
          |> maybe_add_session_header(session_header, session_id)
          |> send_resp(200, "{}")

        {:error, error} ->
          handle_request_error(conn, error, message)
      end
    catch
      :exit, reason ->
        Logging.transport_event("session_call_failed", %{reason: reason}, level: :error)

        send_jsonrpc_error(
          conn,
          Error.protocol(:internal_error, %{message: "Server unavailable"}),
          extract_request_id(message)
        )
    end

    # Per MCP 2025-06-18 Streamable HTTP: a POST that opts into SSE response
    # gets its OWN stream on its OWN HTTP connection, scoped to that request.
    # Stream the response chunk on this conn and let Plug finalize the chunked
    # response. Never reuse the session-wide SSE handler (GET stream).
    defp stream_response_on_conn(conn, response, session_id, session_header) do
      conn = put_resp_header(conn, session_header, session_id)
      conn = Streaming.prepare_connection(conn)

      case Streaming.send_event(conn, response, nil) do
        {:ok, conn} ->
          conn

        {:error, reason} ->
          Logging.transport_event(
            "sse_post_send_failed",
            %{session_id: session_id, reason: inspect(reason)},
            level: :warning
          )

          conn
      end
    end

    defp handle_delete(conn, %{transport: transport, session_header: session_header} = opts) do
      case get_req_header(conn, session_header) do
        [session_id] when is_binary(session_id) and session_id != "" ->
          StreamableHTTP.unregister_sse_handler(transport, session_id)

          case StreamableHTTP.close_session_stream(transport, session_id) do
            :ok ->
              delete_session_from_store(session_id)
              stop_session_process(opts, session_id)

              conn
              |> put_resp_content_type("application/json")
              |> send_resp(200, "{}")

            {:error, reason} ->
              Logging.transport_event(
                "session_stream_delete_failed",
                %{session_id: session_id, reason: inspect(reason)},
                level: :error
              )

              send_error(conn, 500, "Failed to delete session stream")
          end

        _ ->
          send_error(conn, 400, "Session ID required")
      end
    end

    # Session management

    defp find_session(%{registry_mod: mod, registry_name: name}, session_id) do
      mod.lookup_session(name, session_id)
    end

    # Notifications and responses arrive on a session that already exists, but in
    # a multi-instance (horizontally scaled) deployment the request may be routed
    # to a node whose local registry has never seen it. A session persisted to
    # the configured `Session.Store` on one node is restored on another instead
    # of 404ing. When the store cannot restore it (or none is configured), the
    # client gets a 404 so it knows to re-`initialize` — the session is gone and
    # silently auto-initializing an empty one would hide that.
    defp find_or_restore_session(opts, session_id, _context) do
      case find_session(opts, session_id) do
        {:ok, pid} ->
          {:ok, pid}

        {:error, :not_found} ->
          case restore_session_from_store(opts, session_id) do
            {:ok, _} = ok -> ok
            {:error, _} -> {:error, :not_found}
          end
      end
    end

    defp find_or_create_session(opts, session_id, message, _context) do
      case find_session(opts, session_id) do
        {:ok, pid} ->
          {:ok, pid}

        {:error, :not_found} when Message.is_initialize(message) ->
          start_new_session(opts, session_id)

        {:error, :not_found} ->
          case restore_session_from_store(opts, session_id) do
            {:ok, _} = ok -> ok
            {:error, _} -> {:error, :not_found}
          end
      end
    end

    defp start_new_session(
           %{server: server, registry_mod: registry_mod, registry_name: registry_name} = opts,
           session_id,
           extra_opts \\ []
         ) do
      session_config = ServerSupervisor.get_session_config(server)
      session_name = Registry.resolve_session_name(registry_mod, registry_name, session_id)

      session_opts =
        [
          session_id: session_id,
          server_module: server,
          name: session_name,
          transport: session_config.transport,
          session_idle_timeout: session_config.session_idle_timeout || 1_800_000,
          timeout: opts.timeout,
          task_supervisor: session_config.task_supervisor,
          task_store: Map.get(session_config, :task_store)
        ] ++ extra_opts

      case ServerSupervisor.start_session(server, session_opts) do
        {:ok, pid} ->
          registry_mod.register_session(registry_name, session_id, pid)
          {:ok, pid}

        {:error, {:already_started, pid}} ->
          {:ok, pid}

        {:error, reason} ->
          {:error, reason}
      end
    end

    defp restore_session_from_store(opts, session_id) do
      case Anubis.get_session_store_adapter() do
        nil ->
          {:error, :no_session}

        store ->
          case store.load(session_id, []) do
            {:ok, stored_state} ->
              pre_initialized = stored_state["initialized"] == true
              start_new_session(opts, session_id, pre_initialized: pre_initialized)

            _ ->
              {:error, :no_session}
          end
      end
    end

    # Helper functions

    defp wants_sse?(conn) do
      conn
      |> get_req_header("accept")
      |> List.first("")
      |> String.contains?("text/event-stream")
    end

    defp validate_accept_header(conn) do
      accept_header =
        conn
        |> get_req_header("accept")
        |> List.first("")

      if String.contains?(accept_header, "application/json") do
        :ok
      else
        {:error, :invalid_accept_header}
      end
    end

    defp get_or_create_session_id(conn, session_header) do
      case get_req_header(conn, session_header) do
        [session_id] when is_binary(session_id) and session_id != "" ->
          session_id

        _ ->
          ID.generate_session_id()
      end
    end

    defp determine_session_id(conn, session_header, message) when Message.is_initialize(message) do
      case get_req_header(conn, session_header) do
        [session_id] when is_binary(session_id) and session_id != "" ->
          session_id

        _ ->
          ID.generate_session_id()
      end
    end

    defp determine_session_id(conn, session_header, _message) do
      get_or_create_session_id(conn, session_header)
    end

    defp maybe_parse_messages(body) when is_binary(body) do
      case Message.decode(body) do
        {:ok, messages} ->
          {:ok, messages}

        {:error, reason} ->
          Logging.transport_event(
            "parse_error",
            %{body_size: byte_size(body), reason: inspect(reason)},
            level: :error
          )

          {:error, reason}
      end
    end

    defp maybe_parse_messages(body) when is_map(body) do
      case Message.validate_message(body) do
        {:ok, message} -> {:ok, [message]}
        {:error, reason} -> {:error, reason}
      end
    end

    defp maybe_add_session_header(conn, session_header, session_id) do
      if get_req_header(conn, session_header) == [] do
        put_resp_header(conn, session_header, session_id)
      else
        conn
      end
    end

    defp maybe_read_request_body(%{body_params: %Unfetched{aspect: :body_params}} = conn, %{timeout: timeout}) do
      case Plug.Conn.read_body(conn, read_timeout: timeout) do
        {:ok, body, conn} -> {:ok, body, conn}
        {:error, reason} -> {:error, reason}
      end
    end

    defp maybe_read_request_body(%{body_params: body} = conn, _), do: {:ok, body, conn}

    defp encode_json!(data), do: JSON.encode!(data)

    defp decode_json(binary) when is_binary(binary) do
      case JSON.decode(binary) do
        {:ok, decoded} -> {:ok, decoded}
        {:error, reason} -> {:error, reason}
      end
    end

    defp send_error(conn, status, message) do
      data = %{data: %{message: message, http_status: status}}

      mcp_error =
        case status do
          404 -> Error.protocol(:invalid_request, data)
          405 -> Error.protocol(:method_not_found, data)
          406 -> Error.protocol(:invalid_request, data)
          _ -> Error.protocol(:internal_error, data)
        end

      {:ok, error_response} = Error.to_json_rpc(mcp_error, ID.generate_error_id())

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, error_response)
    end

    defp send_jsonrpc_error(conn, %Error{} = error, id) do
      error_id = id || ID.generate_error_id()
      {:ok, encoded_error} = Error.to_json_rpc(error, error_id)

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(400, encoded_error)
    end

    defp handle_request_error(conn, %Error{} = error, body) do
      send_jsonrpc_error(conn, error, extract_request_id(body))
    end

    defp handle_request_error(conn, reason, body) do
      Logging.transport_event("request_error", %{reason: reason}, level: :error)

      send_jsonrpc_error(
        conn,
        Error.wrap_reason(reason),
        extract_request_id(body)
      )
    end

    defp extract_request_id(%{"id" => request_id}), do: request_id
    defp extract_request_id(_), do: nil

    defp extract_request_id_from_body(%{"id" => request_id}), do: request_id

    defp extract_request_id_from_body(body) when is_binary(body) do
      case JSON.decode(body) do
        {:ok, %{"id" => request_id}} -> request_id
        _ -> nil
      end
    end

    defp extract_request_id_from_body(_), do: nil

    defp build_request_context(conn, auth_claims) do
      %{
        assigns: conn.assigns,
        type: :http,
        req_headers: conn.req_headers,
        query_params: fetch_query_params_safe(conn),
        remote_ip: conn.remote_ip,
        scheme: conn.scheme,
        host: conn.host,
        port: conn.port,
        request_path: conn.request_path,
        auth: auth_claims
      }
    end

    defp handle_well_known(conn, %{authorization: nil}) do
      send_error(conn, 404, "Not found")
    end

    defp handle_well_known(conn, %{authorization: auth_config}) do
      metadata = Authorization.build_resource_metadata(auth_config)

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, JSON.encode!(metadata))
    end

    defp authorize(conn, %{authorization: nil}), do: {:ok, conn, nil}

    defp authorize(conn, %{authorization: auth_config}) do
      case extract_bearer_token(conn) do
        {:ok, token} ->
          validate_bearer_token(conn, token, auth_config)

        {:error, :missing_token} ->
          www_auth = Authorization.build_www_authenticate(auth_config, :unauthorized)

          conn =
            conn
            |> put_resp_header("www-authenticate", www_auth)
            |> put_resp_content_type("application/json")
            |> send_resp(401, JSON.encode!(%{"error" => "unauthorized"}))
            |> halt()

          {:halt, conn}
      end
    end

    defp validate_bearer_token(conn, token, auth_config) do
      {validator_mod, validator_opts} = auth_config.validator
      _ = validator_opts

      Telemetry.execute(
        [:server, :authorization, :validate],
        %{system_time: System.system_time()},
        %{validator: validator_mod}
      )

      case validator_mod.validate_token(token, auth_config) do
        {:ok, raw_claims} ->
          claims = Authorization.normalize_claims(raw_claims)

          with :ok <- Authorization.validate_expiry(claims),
               :ok <- Authorization.validate_audience(claims, auth_config) do
            {:ok, conn, claims}
          else
            {:error, :token_expired} ->
              send_auth_error(conn, auth_config, 401, :unauthorized)

            {:error, :invalid_audience} ->
              send_auth_error(conn, auth_config, 401, :unauthorized)
          end

        {:error, _reason} ->
          send_auth_error(conn, auth_config, 401, :unauthorized)
      end
    end

    defp send_auth_error(conn, auth_config, 401, :unauthorized) do
      www_auth = Authorization.build_www_authenticate(auth_config, :unauthorized)

      conn =
        conn
        |> put_resp_header("www-authenticate", www_auth)
        |> put_resp_content_type("application/json")
        |> send_resp(401, JSON.encode!(%{"error" => "unauthorized"}))
        |> halt()

      {:halt, conn}
    end

    defp extract_bearer_token(conn) do
      conn
      |> get_req_header("authorization")
      |> List.first()
      |> parse_bearer_header()
    end

    defp parse_bearer_header(header) when is_binary(header) do
      case String.split(header, ~r/\s+/, parts: 2) do
        [scheme, token] ->
          if String.downcase(scheme) == "bearer" and token != "" do
            {:ok, String.trim(token)}
          else
            {:error, :missing_token}
          end

        _ ->
          {:error, :missing_token}
      end
    end

    defp parse_bearer_header(_), do: {:error, :missing_token}

    defp fetch_query_params_safe(conn) do
      case conn.query_params do
        %Unfetched{} -> nil
        params -> params
      end
    end

    defp start_sse_streaming(conn, params) do
      %{transport: transport, session_id: session_id, session_header: session_header} = params
      handler_pid = self()
      {event_store, retry} = StreamableHTTP.resumability_config(transport)

      conn
      |> put_resp_header(session_header, session_id)
      |> Streaming.prepare_connection()
      |> Streaming.start(transport, session_id,
        event_store: event_store,
        resume_from: Map.get(params, :resume_from),
        retry: retry,
        on_close: fn ->
          StreamableHTTP.unregister_sse_handler(transport, session_id, handler_pid)
        end
      )
    end

    defp delete_session_from_store(session_id) do
      if store = Anubis.get_session_store_adapter() do
        store.delete(session_id, [])
      end
    end

    defp stop_session_process(%{server: server, registry_mod: registry_mod}, session_id) do
      ServerSupervisor.stop_session(server, registry_mod, session_id)
    end
  end
end
