-module(tor_dns_tunnel_cache).
-behaviour(gen_server).

% public API
-export([start_link/0, stop/1]).
-export([get/2, put/4]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_info/2, handle_cast/2]).
-export([code_change/3, terminate/2]).

-type cache() :: pid().
-type key() :: term().
-type item() :: term().


-spec get(cache(), key()) -> {ok, item()} | not_found.
get(Cache, Key) ->
    gen_server:call(Cache, {get, Key}, infinity).


-spec put(cache(), key(), item(), non_neg_integer()) -> ok.
put(Cache, Key, Item, TTL) ->
    ok = gen_server:cast(Cache, {put, Key, Item, TTL}).


-spec start_link() -> {ok, cache()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


-spec stop(cache()) -> ok.
stop(Cache) ->
    catch gen_server:call(Cache, stop),
    ok.


init([]) ->
    {ok, ets:new(cache_by_items, [set, private])}.


handle_cast({put, Key, Item, TTL}, State) ->
    case ets:lookup(State, Key) of
    [{Key, {_Item, _Timestamp, OldTimer}}] -> cancel_timer(Key, OldTimer);
    _ -> ok
    end,
    true = ets:insert(State, {Key, {Item, os:timestamp(), set_timer(Key, TTL)}}),
    {noreply, State}.


handle_call({get, Key}, _From, State) ->
    case ets:lookup(State, Key) of
    [{Key, {Item, Timestamp, _Timer}}] ->
        {reply, {ok, Item, Timestamp}, State};
    [] ->
        {reply, not_found, State}
    end;


handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.


handle_info({expired, Key}, State) ->
    ets:delete(State, Key),
    {noreply, State}.


terminate(_Reason, State) ->
    true = ets:delete(State).


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


set_timer(Key, Interval) ->
    erlang:send_after(Interval * 1000, self(), {expired, Key}).


cancel_timer(Key, Timer) ->
    case erlang:cancel_timer(Timer) of
    false ->
        receive {expired, Key} -> ok after 0 -> ok end;
    _TimeLeft ->
        ok
    end.
