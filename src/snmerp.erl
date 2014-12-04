%%
%% snmerp simple snmpv2 client
%%
%% Copyright 2014 Alex Wilson <alex@uq.edu.au>, The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

%% @author Alex Wilson <alex@uq.edu.au>
%% @doc snmerp public api
-module(snmerp).

-include("include/SNMPv2.hrl").
-include_lib("kernel/include/inet.hrl").
-include_lib("snmp/include/snmp_types.hrl").

-record(snmerp, {
	mibs :: snmerp_mib:mibs(),
	sock :: term(),
	ip :: inet:ip_address(),
	community :: string(),
	timeout :: integer(),
	max_bulk :: integer(),
	retries :: integer()}).

-opaque client() :: #snmerp{}.
-export_type([client/0]).

-type req_option() :: {timeout, Ms :: integer()} | {max_bulk, integer()} | {retries, integer()}.
-type req_options() :: [req_option()].
-type option() :: {community, string()} | {mibs, snmerp_mib:mibs()} | req_option().
-type options() :: [option()].

-type oid() :: tuple().
-type name() :: string().
-type index() :: integer() | [integer()].
-type var() :: oid() | name() | {name(), index()}.

-type value() :: binary() | integer() | oid() | inet:ip_address() | null | not_found.

-export([open/2, close/1]).
-export([get/2, get/3]).
-export([walk/2, walk/3]).
-export([set/3, set/4]).
-export([table/3, table/4]).

-spec open(inet:ip_address() | inet:hostname(), options()) -> {ok, client()} | {error, term()}.
open(Address, Options) ->
	Ip = case is_tuple(Address) of
		true -> Address;
		false ->
			case inet_res:getbyname(Address, a) of
				{ok, #hostent{h_addr_list = [HAddr | _]}} -> HAddr;
				_ -> error(bad_hostname)
			end
	end,
	{ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
	Community = proplists:get_value(community, Options, "public"),
	Mibs = case proplists:get_value(mibs, Options) of
		undefined ->
			{ok, M} = snmerp_mib:add_dir(filename:join([code:priv_dir(snmerp), "mibs"]), snmerp_mib:empty()),
			M;
		M -> M
	end,
	Timeout = proplists:get_value(timeout, Options, 5000),
	MaxBulk = proplists:get_value(max_bulk, Options, 20),
	Retries = proplists:get_value(retries, Options, 3),
	{ok, #snmerp{ip = Ip, sock = Sock, community = Community, mibs = Mibs, timeout = Timeout, max_bulk = MaxBulk, retries = Retries}}.

-spec get(client(), var()) -> {ok, value()} | {error, term()}.
get(S = #snmerp{}, Var) ->
	get(S, Var, []).

-spec get(client(), var(), req_options()) -> {ok, value()} | {error, term()}.
get(S = #snmerp{}, Var, Opts) ->
	Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
	Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
	Oid = var_to_oid(Var, S),
	ReqVbs = [#'VarBind'{name = Oid, v = {unSpecified,'NULL'}}],
	ReqPdu = {'get-request', #'PDU'{'variable-bindings' = ReqVbs}},
	case request_pdu(ReqPdu, Timeout, Retries, S) of
		{ok, #'PDU'{'variable-bindings' = Vbs}} ->
			case Vbs of
				[#'VarBind'{name = Oid, v = V}] ->
					{ok, v_to_value(V, Oid, S)};
				_ ->
					{error, {unexpected_varbinds, Vbs}}
			end;
		Err -> Err
	end.

-spec set(client(), var(), value()) -> ok | {error, term()}.
set(S = #snmerp{}, Var, Value) ->
	set(S, Var, Value, []).

-spec set(client(), var(), value(), req_options()) -> ok | {error, term()}.
set(S = #snmerp{}, Var, Value, Opts) ->
	Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
	Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
	Oid = var_to_oid(Var, S),
	V = value_to_v(Value, Oid, S),
	ReqVbs = [#'VarBind'{name = Oid, v = V}],
	ReqPdu = {'set-request', #'PDU'{'variable-bindings' = ReqVbs}},
	case request_pdu(ReqPdu, Timeout, Retries, S) of
		{ok, #'PDU'{}} -> ok;
		Err -> Err
	end.

-spec walk(client(), var()) -> {ok, [{index(), value()}]} | {error, term()}.
walk(S = #snmerp{}, Var) ->
	walk(S, Var, []).

-spec walk(client(), var(), req_options()) -> {ok, [{index(), value()}]} | {error, term()}.
walk(S = #snmerp{}, Var, Opts) ->
	Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
	Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
	MaxBulk = proplists:get_value(max_bulk, Opts, S#snmerp.max_bulk),
	Oid = var_to_oid(Var, S),
	VFun = v_to_value_fun(Oid, S),
	case walk_next(S, Oid, Oid, Timeout, Retries, MaxBulk) of
		{ok, Vbs} ->
			{OutValuesRev, _} = lists:foldl(fun(#'VarBind'{name = VbOid, v = V}, {Values, Seen}) ->
				Index = oid_index(Oid, VbOid),
				case gb_sets:is_element(Index, Seen) of
					true -> {Values, Seen};
					false ->
						Values2 = [{Index, VFun(V, Oid, S)} | Values],
						Seen2 = gb_sets:add_element(Index, Seen),
						{Values2, Seen2}
				end
			end, {[], gb_sets:empty()}, Vbs),
			{ok, lists:reverse(OutValuesRev)};
		Err -> Err
	end.

walk_next(S = #snmerp{}, BaseOid, Oid, Timeout, Retries, MaxBulk) ->
	ReqVbs = [#'VarBind'{name = Oid, v = {unSpecified,'NULL'}}],
	ReqPdu = {'get-bulk-request', #'BulkPDU'{'non-repeaters' = 0, 'max-repetitions' = MaxBulk, 'variable-bindings' = ReqVbs}},
	case request_pdu(ReqPdu, Timeout, Retries, S) of
		{ok, #'PDU'{'variable-bindings' = Vbs}} ->
			{InPrefix, OutOfPrefix} = lists:splitwith(
				fun(#'VarBind'{name = ThisOid}) -> is_tuple_prefix(BaseOid, ThisOid) end, Vbs),
			case OutOfPrefix of
				[] ->
					LastVb = lists:last(InPrefix),
					NextOid = LastVb#'VarBind'.name,
					case walk_next(S, BaseOid, NextOid, Timeout, Retries, MaxBulk) of
						{ok, Rest} -> {ok, InPrefix ++ Rest};
						Err -> Err
					end;
				_ ->
					{ok, InPrefix}
			end;
		Err -> Err
	end.

-spec table(client(), var(), req_options()) -> {ok, Columns :: [string()], Rows :: [tuple()]} | {error, term()}.
table(S = #snmerp{}, Var, Opts) ->
	TableOid = var_to_oid(Var, S),

	{_TblInfo, _AugMes, ColMes} = snmerp_mib:table_info(tuple_to_list(TableOid), S#snmerp.mibs),

	ColumnNames = [atom_to_list(Me#me.aliasname) || Me <- ColMes],
	ColumnOids = [list_to_tuple(Me#me.oid) || Me <- ColMes],
	ColumnIdxs = trie:new(lists:zip([tuple_to_list(C) || C <- ColumnOids], lists:seq(1, length(ColumnOids)))),
	BaseRow = list_to_tuple([null || _ <- lists:seq(1, length(ColumnOids))]),
	BaseRowArray = array:new([{default, BaseRow}]),
	SortedColumnOids = [FirstOid | _] = lists:sort(ColumnOids),

	Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
	Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
	MaxBulk = proplists:get_value(max_bulk, Opts, S#snmerp.max_bulk),
	case table_next(S, SortedColumnOids, FirstOid, Timeout, Retries, MaxBulk, BaseRowArray, ColumnIdxs) of
		{ok, RowArray} -> {ok, ColumnNames, array:sparse_to_list(RowArray)};
		Err -> Err
	end.

-spec table(client(), var(), [var()], req_options()) -> {ok, Rows :: [tuple()]} | {error, term()}.
table(S = #snmerp{}, Var, Columns, Opts) ->
	TableOid = var_to_oid(Var, S),

	{_TblInfo, AugMes, _ColMes} = snmerp_mib:table_info(tuple_to_list(TableOid), S#snmerp.mibs),
	ColSet = trie:new([tuple_to_list(TableOid)] ++ [Me#me.oid || Me <- AugMes]),

	ColumnOids = [var_to_oid(C, S) || C <- Columns],
	ColumnIdxs = trie:new(lists:zip([tuple_to_list(T) || T <- ColumnOids], lists:seq(1, length(ColumnOids)))),
	BaseRow = list_to_tuple([null || _ <- lists:seq(1, length(ColumnOids))]),
	BaseRowArray = array:new([{default, BaseRow}]),
	SortedColumnOids = [FirstOid | _] = lists:sort(ColumnOids),

	case lists:dropwhile(is_prefixed_fun(ColSet), ColumnOids) of
		[NonMatch | _] -> error({column_outside_table, NonMatch, TableOid});
		[] ->
			Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
			Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
			MaxBulk = proplists:get_value(max_bulk, Opts, S#snmerp.max_bulk),
			case table_next(S, SortedColumnOids, FirstOid, Timeout, Retries, MaxBulk, BaseRowArray, ColumnIdxs) of
				{ok, RowArray} -> {ok, array:sparse_to_list(RowArray)};
				Err -> Err
			end
	end.

is_prefixed_fun(Set) ->
	fun(K) ->
		case trie:find_prefix_longest(tuple_to_list(K), Set) of
			{ok, _, _} -> true;
			_ -> false
		end
	end.

table_next(S = #snmerp{}, Oids, Oid, Timeout, Retries, MaxBulk, RowArray, ColumnIdxs) ->
	ReqVbs = [#'VarBind'{name = Oid, v = {unSpecified,'NULL'}}],
	ReqPdu = {'get-bulk-request', #'BulkPDU'{'non-repeaters' = 0, 'max-repetitions' = MaxBulk, 'variable-bindings' = ReqVbs}},
	case request_pdu(ReqPdu, Timeout, Retries, S) of
		{ok, #'PDU'{'variable-bindings' = Vbs}} ->
			table_next_vbs(S, Oids, Timeout, Retries, MaxBulk, RowArray, ColumnIdxs, Vbs);
		Err -> Err
	end.

table_next_vbs(S = #snmerp{}, Oids = [Oid | RestOids], Timeout, Retries, MaxBulk, RowArray, ColumnIdxs, Vbs) ->
	{InPrefix, OutOfPrefix} = lists:splitwith(
		fun(#'VarBind'{name = ThisOid}) -> is_tuple_prefix(Oid, ThisOid) end, Vbs),
	{ok, _, ColumnIdx} = trie:find_prefix_longest(tuple_to_list(Oid), ColumnIdxs),
	VFun = v_to_value_fun(Oid, S),
	RowArray2 = lists:foldl(fun(#'VarBind'{name = ThisOid, v = V}, RA) ->
		RowIdx = oid_single_index(Oid, ThisOid),
		Row = array:get(RowIdx, RA),
		Row2 = setelement(ColumnIdx, Row, VFun(V, ThisOid, S)),
		array:set(RowIdx, Row2, RA)
	end, RowArray, InPrefix),
	case OutOfPrefix of
		[] ->
			LastVb = lists:last(InPrefix),
			NewOid = LastVb#'VarBind'.name,
			table_next(S, Oids, NewOid, Timeout, Retries, MaxBulk, RowArray2, ColumnIdxs);

		[FirstOut | _] ->
			case RestOids of
				[NextOid | _] ->
					case is_tuple_prefix(NextOid, FirstOut) of
						true -> table_next_vbs(S, RestOids, Timeout, Retries, MaxBulk, RowArray2, ColumnIdxs, OutOfPrefix);
						false -> table_next(S, RestOids, NextOid, Timeout, Retries, MaxBulk, RowArray2, ColumnIdxs)
					end;
				[] ->
					{ok, RowArray2}
			end
	end.

-spec close(client()) -> ok.
close(#snmerp{sock = Sock}) ->
	gen_udp:close(Sock).

%% @internal
-spec is_tuple_prefix(tuple(), tuple()) -> boolean().
is_tuple_prefix(Tuple1, Tuple2) when is_tuple(Tuple1) and is_tuple(Tuple2) ->
	MinLen = tuple_size(Tuple1),
	case (tuple_size(Tuple2) >= MinLen) of
		true ->
			not lists:any(fun(N) -> element(N,Tuple1) =/= element(N,Tuple2) end, lists:seq(1, MinLen));
		false ->
			false
	end.

%% @internal
-spec oid_single_index(oid(), oid()) -> integer().
oid_single_index(BaseOid, Oid) when is_tuple(BaseOid) and is_tuple(Oid) ->
	IdxList = [element(N, Oid) || N <- lists:seq(tuple_size(BaseOid) + 1, tuple_size(Oid))],
	Bin = lists:foldl(fun(I, Bin) ->
		<<Bin/binary, I:32/big>>
	end, <<>>, IdxList),
	binary:decode_unsigned(Bin).

%% @internal
-spec oid_index(oid(), oid()) -> integer() | oid().
oid_index(BaseOid, Oid) when is_tuple(BaseOid) and is_tuple(Oid) ->
	IdxList = [element(N, Oid) || N <- lists:seq(tuple_size(BaseOid) + 1, tuple_size(Oid))],
	case IdxList of
		[Idx] -> Idx;
		_ -> list_to_tuple(IdxList)
	end.

%% @internal
-spec request_pdu({atom(), #'PDU'{} | #'BulkPDU'{}}, integer(), integer(), client()) -> {ok, #'PDU'{}} | {error, term()}.
request_pdu(_, _, 0, _) -> {error, timeout};
request_pdu({PduType, Pdu}, Timeout, Retries, S = #snmerp{sock = Sock, ip = Ip, community = Com}) ->
	<<_:1, RequestId:31/big>> = crypto:rand_bytes(4),
	Pdu2 = case Pdu of
		#'PDU'{} ->
			Pdu#'PDU'{'request-id' = RequestId, 'error-status' = noError, 'error-index' = 0};
		#'BulkPDU'{} ->
			Pdu#'BulkPDU'{'request-id' = RequestId}
	end,
	{ok, PduBin} = 'SNMPv2':encode('PDUs', {PduType, Pdu2}),
	Msg = #'Message'{version = 'version-2c', community = Com, data = PduBin},
	{ok, MsgBin} = 'SNMPv2':encode('Message', Msg),
	ok = inet:setopts(Sock, [{active, once}]),
	ok = gen_udp:send(Sock, Ip, 161, MsgBin),
	case recv_reqid(Timeout, Sock, Ip, 161, RequestId) of
		{ok, {'response', ResponsePdu}} ->
			#'PDU'{'error-status' = ErrSt} = ResponsePdu,
			case ErrSt of
				'noError' -> {ok, ResponsePdu};
				_ -> {error, ErrSt}
			end;
		{ok, {RespPduType, _}} ->
			{error, {unexpected_pdu, RespPduType}};
		{error, timeout} ->
			request_pdu({PduType, Pdu}, Timeout, Retries - 1, S);
		Err ->
			Err
	end.

%% @internal
-spec recv_reqid(integer(), term(), inet:ip_address(), integer(), integer()) -> {ok, {atom(), #'PDU'{}}} | {error, term()}.
recv_reqid(Timeout, Sock, Ip, Port, ReqId) ->
	receive
		{udp, Sock, Ip, Port, ReplyBin} ->
			case 'SNMPv2':decode('Message', ReplyBin) of
				{ok, #'Message'{version = 'version-2c', data = PduBin}} ->
					case 'SNMPv2':decode('PDUs', PduBin) of
						{ok, {PduType, Pdu = #'PDU'{'request-id' = ReqId}}} ->
							{ok, {PduType, Pdu}};
						{ok, {_PduType, #'PDU'{}}} ->
							ok = inet:setopts(Sock, [{active, once}]),
							recv_reqid(Timeout, Sock, Ip, Port, ReqId);
						_ ->
							{error, bad_pdu_decode}
					end;
				_ ->
					{error, bad_message_decode}
			end
	after Timeout ->
		{error, timeout}
	end.

-spec v_to_value_fun(oid(), client()) -> fun((term()) -> value()).
v_to_value_fun(Oid, S) ->
	case snmerp_mib:oid_prefix_enum(tuple_to_list(Oid), S#snmerp.mibs) of
		not_found ->
			case snmerp_mib:oid_to_prefix_me(Oid, S#snmerp.mibs) of
				#me{entrytype = EntType}
						when (EntType =:= variable) or (EntType =:= table_column) ->
					fun
						({value, {simple, {'integer-value', Int}}}, _, _) -> Int;
						(V, OOid, SS) -> v_to_value(V, OOid, SS) end;
				_ ->
					fun(V, OOid, SS) -> v_to_value(V, OOid, SS) end
			end;
		Enum ->
			fun ({value, {simple, {'integer-value', Int}}}, _, _) ->
				proplists:get_value(Int, Enum, Int) end
	end.

-spec v_to_value(term(), oid(), client()) -> value().
v_to_value({'unSpecified', _}, _, _) -> null;
v_to_value({'noSuchObject', _}, _, _) -> not_found;
v_to_value('noSuchObject', _, _) -> not_found;
v_to_value({'noSuchInstance', _}, _, _) -> not_found;
v_to_value('noSuchInstance', _, _) -> not_found;
v_to_value({value, {simple, {'string-value', Str}}}, _, _) when is_binary(Str) -> Str;
v_to_value({value, {simple, {'integer-value', Int}}}, Oid, S) when is_integer(Int) ->
	case snmerp_mib:oid_prefix_enum(tuple_to_list(Oid), S#snmerp.mibs) of
		not_found -> Int;
		Enum -> proplists:get_value(Int, Enum, Int)
	end;
v_to_value({value, {simple, {'objectID-value', Oid}}}, _, _) when is_tuple(Oid) -> Oid;
v_to_value({value, {'application-wide', {'counter-value', Int}}}, _, _) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'timeticks-value', Int}}}, _, _) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'big-counter-value', Int}}}, _, _) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'unsigned-integer-value', Int}}}, _, _) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'ipAddress-value', IpBin}}}, _, _) when is_binary(IpBin) ->
	<<A,B,C,D>> = IpBin, {A,B,C,D};
v_to_value({value, V}, _, _) -> error({unknown_value_type, V}).

-spec value_to_v(value(), oid(), client()) -> term().
value_to_v(null, _, _) ->
	{'unSpecified', 'NULL'};
value_to_v(Binary, _, _) when is_binary(Binary) ->
	{value, {simple, {'string-value', Binary}}};
value_to_v({A,B,C,D}, _, _) when (A >= 0) and (A < 256) and (B >= 0) and (B < 256) and
						(C >= 0) and (C < 256) and (D >= 0) and (D < 256) ->
	{value, {'application-wide', {'ipAddress-value', <<A,B,C,D>>}}};
value_to_v(Tuple, _, _) when is_tuple(Tuple) ->
	{value, {simple, {'objectID-value', Tuple}}};
value_to_v(Int, _, _) when is_integer(Int) ->
	{value, {simple, {'integer-value', Int}}};
value_to_v(Str, Oid, S) when is_atom(Str) ->
	case snmerp_mib:oid_prefix_enum(tuple_to_list(Oid), S#snmerp.mibs) of
		not_found -> error({unknown_value_type, Str});
		Enum ->
			case [{I, St} || {I, St} <- Enum, St =:= Str] of
				[{Int, Str}] -> {value, {simple, {'integer-value', Int}}};
				_ -> error({unknown_enum_value, Str})
			end
	end;
value_to_v(Other, _, _) ->
	error({unknown_value_type, Other}).

-spec var_to_oid(var(), client()) -> oid().
var_to_oid(Name, #snmerp{mibs = Mibs}) when is_list(Name) ->
	case snmerp_mib:name_to_oid(Name, Mibs) of
		not_found -> error(bad_var_name);
		Oid -> list_to_tuple(Oid)
	end;
var_to_oid({Name, Index}, #snmerp{mibs = Mibs}) when is_list(Name) ->
	Appendage = case Index of
		I when is_integer(I) -> [I];
		L when is_list(L) -> L
	end,
	case snmerp_mib:name_to_oid(Name, Mibs) of
		not_found -> error(bad_var_name);
		Oid -> list_to_tuple(Oid ++ Appendage)
	end;
var_to_oid(OidTuple, #snmerp{}) when is_tuple(OidTuple) ->
	OidTuple.
