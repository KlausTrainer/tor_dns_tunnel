-module(tor_dns_tunnel_cache).
-behaviour(gen_server).

% public API
-export([start_link/0, stop/1]).
-export([get/2, put/2]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_info/2, handle_cast/2]).
-export([code_change/3, terminate/2]).

-include_lib("kernel/src/inet_dns.hrl").

-type cache() :: pid().

-spec get(cache(), binary()) -> {ok, binary()} | not_found.
get(Cache, Packet) ->
    {ok, #dns_rec{qdlist = Questions} = DNSRecord} = inet_dns:decode(Packet),
    case Questions of
    [#dns_query{domain = Domain, type = Type, class = in}] ->
        case gen_server:call(Cache, {get, {Domain, Type}}, infinity) of
        {ok, CachedDNSRecord, Timestamp} ->
            Answers = CachedDNSRecord#dns_rec.anlist,
            ElapsedTimeInSeconds = timer:now_diff(os:timestamp(), Timestamp) div 1000000,

            StillValid = lists:all(fun(CachedAnswer) ->
                CachedAnswer#dns_rr.ttl - ElapsedTimeInSeconds >= 0
            end, Answers),

            case StillValid of
            true ->
                NewAnswers = lists:map(fun(CachedAnswer) ->
                    CachedAnswer#dns_rr{ttl = CachedAnswer#dns_rr.ttl - ElapsedTimeInSeconds}
                end, Answers),
                NewHeader = CachedDNSRecord#dns_rec.header#dns_header{id = DNSRecord#dns_rec.header#dns_header.id},
                {ok, inet_dns:encode(CachedDNSRecord#dns_rec{header = NewHeader, anlist = NewAnswers})};
            false ->
                not_found
            end;
        not_found ->
            not_found
        end;
    _ ->
        not_found
    end.


-spec put(cache(), binary()) -> ok.
put(Cache, Packet) ->
    {ok, #dns_rec{qdlist = Questions} = DNSRecord} = inet_dns:decode(Packet),
    case Questions of
    [#dns_query{class = in} = Question] ->
        case is_valid_response(Question, DNSRecord#dns_rec.anlist) of
        true ->
            #dns_query{domain = Domain, type = Type} = Question,
            gen_server:cast(Cache, {put, {Domain, Type}, DNSRecord});
        false ->
            ok
        end;
    _ ->
        ok
    end.


-spec start_link() -> {ok, cache()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


-spec stop(cache()) -> ok.
stop(Cache) ->
    catch gen_server:call(Cache, stop),
    ok.


init([]) ->
    {ok, ets:new(?MODULE, [set, private])}.


handle_cast({put, Key, DNSRecord}, State) ->
    case ets:lookup(State, Key) of
    [{Key, {_DNSRecord, _Timestamp, OldTimer}}] -> cancel_timer(Key, OldTimer);
    _ -> ok
    end,
    NewTimer = set_timer(Key, min_ttl(DNSRecord#dns_rec.anlist)),
    ets:insert(State, {Key, {DNSRecord, os:timestamp(), NewTimer}}),
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
    ets:delete(State).


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% internal API

is_valid_response(Question, Answers) ->
    lists:all(fun(Answer) ->
        Question#dns_query.domain =:= Answer#dns_rr.domain
            andalso Question#dns_query.type =:= Answer#dns_rr.type
            andalso Question#dns_query.class =:= Answer#dns_rr.class
    end, Answers).


min_ttl(Answers) ->
    MinTTLAnswer = hd(lists:sort(fun(A1, A2) ->
        A1#dns_rr.ttl =< A2#dns_rr.ttl
    end, Answers)),
    MinTTLAnswer#dns_rr.ttl.


set_timer(Domain, Interval) ->
    erlang:send_after(Interval * 1000, self(), {expired, Domain}).


cancel_timer(Domain, Timer) ->
    case erlang:cancel_timer(Timer) of
    false ->
        receive {expired, Domain} -> ok after 0 -> ok end;
    _TimeLeft ->
        ok
    end.
