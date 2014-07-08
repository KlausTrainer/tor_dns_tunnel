-module(tor_dns_tunnel_sup).
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% supervisor callbacks
-export([init/1]).


%% External API

-spec start_link() -> {ok, pid()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).


%% supervisor callbacks

init([]) ->
    Processes = [
        {
            tor_dns_tunnel_server,
            {tor_dns_tunnel_server, start_link, []},
            permanent, 2000, worker, dynamic
        }
    ],
    {ok, {{one_for_one, 5, 10}, Processes}}.
