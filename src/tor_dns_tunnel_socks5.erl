-module(tor_dns_tunnel_socks5).

-define(VERSION, 5).
-define(CONNECT, 1).

-define(NO_AUTH, 0).
-define(UNACCEPTABLE, 16#FF).
-define(RESERVED, 0).

-define(ADDRESS_TYPE_IPV4, 1).
-define(ADDRESS_TYPE_IPV6, 4).
-define(ADDRESS_TYPE_DOMAINNAME, 3).

-define(SUCCEEDED, 0).

-define(PROXY_CONNECT_OPTIONS, [binary, {packet, 0}, {keepalive, true}, {nodelay, true}, {active, false}]).

% public API
-export([connect/2]).

connect(TargetHost, TargetPort) when is_binary(TargetHost), is_integer(TargetPort) ->
    connect(binary_to_list(TargetHost), TargetPort);
connect(TargetHost, TargetPort) when is_list(TargetHost), is_integer(TargetPort) ->
    ProxyHost = tor_dns_tunnel:get_app_env(socks_proxy_host),
    ProxyPort = tor_dns_tunnel:get_app_env(socks_proxy_port),
    ProxyConnectTimeout = tor_dns_tunnel:get_app_env(socks_proxy_connect_timeout),
    case gen_tcp:connect(ProxyHost, ProxyPort, ?PROXY_CONNECT_OPTIONS, ProxyConnectTimeout) of
    {ok, Socket} ->
        case handshake(Socket) of
        ok ->
            case connect(TargetHost, TargetPort, Socket) of
            ok ->
                {ok, Socket};
            Else ->
                gen_tcp:close(Socket),
                Else
            end;
        Else ->
            gen_tcp:close(Socket),
            Else
        end;
    Else ->
        Else
    end.

handshake(Socket) when is_port(Socket) ->
    ok = gen_tcp:send(Socket, <<?VERSION, 1, ?NO_AUTH>>),
    case gen_tcp:recv(Socket, 2) of
    {ok, <<?VERSION, ?NO_AUTH>>} ->
        ok;
    {ok, <<?VERSION, ?UNACCEPTABLE>>} ->
        {error, unacceptable};
    {error, Reason} ->
        {error, Reason}
    end.

connect(Host, Port, Socket) when is_list(Host), is_integer(Port), is_port(Socket) ->
    {AddressType, Address} = case inet:parse_address(Host) of
    {ok, {IP1, IP2, IP3, IP4}} ->
        {?ADDRESS_TYPE_IPV4, <<IP1,IP2,IP3,IP4>>};
    {ok, {IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}} ->
        {?ADDRESS_TYPE_IPV6, <<IP1,IP2,IP3,IP4,IP5,IP6,IP7,IP8>>};
    _ ->
        HostBin = list_to_binary(Host),
        HostBinLength = byte_size(HostBin),
        {?ADDRESS_TYPE_DOMAINNAME, <<HostBinLength,HostBin/binary>>}
    end,
    ok = gen_tcp:send(Socket,
        <<?VERSION, ?CONNECT, ?RESERVED, AddressType,
          Address/binary, Port:16>>),
    case gen_tcp:recv(Socket, 0) of
    {ok, <<?VERSION, ?SUCCEEDED, ?RESERVED, _/binary>>} -> ok;
    {ok, <<?VERSION, Rep, ?RESERVED, _/binary>>} -> {error, reply(Rep)};
    {error, Reason} -> {error, Reason}
    end.

reply(0) -> succeeded;
reply(1) -> server_fail;
reply(2) -> disallowed_by_ruleset;
reply(3) -> network_unreachable;
reply(4) -> host_unreachable;
reply(5) -> connection_refused;
reply(6) -> ttl_expired;
reply(7) -> command_not_supported;
reply(8) -> address_type_not_supported.
