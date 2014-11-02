-module(tor_dns_tunnel).

-export([start/0, stop/0]).

start() ->
    application:start(?MODULE).

stop() ->
    application:start(?MODULE).

