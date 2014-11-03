-module(tor_dns_tunnel).

% public API
-export([start/0, stop/0]).
-export([get_app_env/1, get_app_env/2]).

start() ->
    application:start(?MODULE).

stop() ->
    application:start(?MODULE).

%% @doc The official way to get the values set in gcm's environment.
%% Will return `undefined' if the given option is unset.
-spec get_app_env(atom()) -> term().
get_app_env(Opt) ->
    get_app_env(Opt, undefined).

%% @doc The official way to get the values set in gcm's environment.
%% Will return `Default' if the given option is unset.
-spec get_app_env(atom(), term()) -> term().
get_app_env(Opt, Default) ->
    case application:get_env(?MODULE, Opt) of
    undefined -> Default;
    {ok, Value} -> Value
    end.
