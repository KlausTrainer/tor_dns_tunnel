-module(tor_dns_tunnel_server).

-behaviour(gen_server).

%% API
-export([start_link/0, stop/0]).

%% gen_server callbacks
-export([
    init/1, handle_call/3, handle_info/2, handle_cast/2,
    code_change/3, terminate/2
]).

-define(DNS_SERVER, "208.67.220.220").

-define(MAX_RETRY_TIME, 10000).

-define(MIN_RETRY_TIMEOUT, 250).
-define(MAX_RETRY_TIMEOUT, 4000).

-record(state, {
    listen_socket,
    dns_server_socket,
    outstanding_requests,
    retry_timeout = 1000
}).

-record(outstanding_request, {
    address,
    port,
    timestamp
}).


%% External API

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


stop() ->
    catch gen_server:call(?MODULE, stop),
    ok.


%% gen_server callbacks

init([]) ->
    {ok, ListenSocket} = gen_udp:open(5354, [binary, {ip, {127,0,0,1}}, {reuseaddr, true}]),
    State = #state{
        listen_socket = ListenSocket,
        outstanding_requests = dict:new()
    },
    {ok, try_dns_server_connect(State)}.


handle_call(stop, _From, #state{dns_server_socket = DNSServerSocket} = State) ->
    gen_tcp:close(State#state.listen_socket),
    case is_port(DNSServerSocket) of
    true -> gen_tcp:close(State#state.listen_socket);
    false -> ok
    end,
    {stop, normal, ok, nil};

handle_call(_Req, From, State) ->
    error_logger:warning_msg("Received unexpected message from ~p.~n", [From]),
    {noreply, State}.


handle_cast(_Req, State) ->
    error_logger:warning_msg("Received unexpected message.~n"),
    {noreply, State}.


handle_info({udp, ListenSocket, RemoteAddress, RemotePort, <<Id:16, _/binary>> = Packet} = Request,
            #state{listen_socket = ListenSocket} = State) when byte_size(Packet) > 2 ->
    DNSServerSocket = State#state.dns_server_socket,
    OutstandingRequests = State#state.outstanding_requests,
    NewOutstandingRequests = case is_port(DNSServerSocket) of
    true ->
        ok = gen_tcp:send(DNSServerSocket, Packet),
        OutstandingRequest = #outstanding_request{
            address = RemoteAddress,
            port = RemotePort,
            timestamp = os:timestamp()
        },
        dict:store(Id, OutstandingRequest, OutstandingRequests);
    false ->
        case dict:find(Id, OutstandingRequests) of
        error ->
            erlang:send_after(?MIN_RETRY_TIMEOUT, self(), Request), % retry later
            OutstandingRequest = #outstanding_request{
                address = RemoteAddress,
                port = RemotePort,
                timestamp = os:timestamp()
            },
            dict:store(Id, OutstandingRequest, OutstandingRequests);
        {ok, #outstanding_request{address = RemoteAddress, port = RemotePort, timestamp = Timestamp}} ->
            case timer:now_diff(os:timestamp(), Timestamp) / 1000 > ?MAX_RETRY_TIME of
            false ->
                erlang:send_after(?MIN_RETRY_TIMEOUT, self(), Request),
                OutstandingRequests;
            true ->
                dict:erase(Id, OutstandingRequests)
            end
        end
    end,
    {noreply, State#state{outstanding_requests = NewOutstandingRequests}};

handle_info({tcp, DNSServerSocket, <<Id:16, _/binary>> = Packet},
            #state{dns_server_socket = DNSServerSocket} = State) when byte_size(Packet) > 2 ->
    OutstandingRequests = State#state.outstanding_requests,
    case dict:find(Id, OutstandingRequests) of
    error ->
        ok;
    {ok, #outstanding_request{address = RemoteAddress, port = RemotePort}} ->
        gen_udp:send(State#state.listen_socket, RemoteAddress, RemotePort, Packet)
    end,
    {noreply, State#state{outstanding_requests = dict:erase(Id, OutstandingRequests)}};

handle_info({tcp_closed, DNSServerSocket}, State) ->
    error_logger:info_msg("Socket ~p closed.~n", [DNSServerSocket]),
    gen_tcp:close(DNSServerSocket),
    {noreply, try_dns_server_connect(State)};

handle_info({tcp_error, DNSServerSocket, Error}, State) ->
    error_logger:error_msg("Error on socket ~p: ~p.~n", [DNSServerSocket, Error]),
    gen_tcp:close(DNSServerSocket),
    {noreply, try_dns_server_connect(State)};

handle_info(try_dns_server_connect, State) ->
    {noreply, try_dns_server_connect(State)}.


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


terminate(_Reason, #state{dns_server_socket = DNSServerSocket} = State) ->
    gen_tcp:close(State#state.listen_socket),
    case is_port(DNSServerSocket) of
    true -> gen_tcp:close(State#state.dns_server_socket);
    false -> ok
    end.


%% internal API

try_dns_server_connect(#state{retry_timeout = RetryTimeout} = State) ->
    case tor_dns_tunnel_socks5:connect(?DNS_SERVER, 53) of
    {ok, DNSServerSocket} ->
        inet:setopts(DNSServerSocket, [{active, true}, {packet, 2}]),
        State#state{dns_server_socket = DNSServerSocket, retry_timeout = ?MIN_RETRY_TIMEOUT};
    {error, Reason} ->
        error_logger:error_msg("Can't connect to DNS server ~p: ~p.~n", [?DNS_SERVER, Reason]),
        erlang:send_after(RetryTimeout, self(), try_dns_server_connect), % retry later
        NewRetryTimeout = RetryTimeout * 2,
        case NewRetryTimeout > ?MAX_RETRY_TIMEOUT of
        true ->
            State#state{dns_server_socket = undefined};
        false ->
            State#state{dns_server_socket = undefined, retry_timeout = NewRetryTimeout}
        end
    end.
