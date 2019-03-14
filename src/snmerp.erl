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
%% @doc Super-simple SNMP client.
%%
%% A simple SNMP client without any processes or global state. Minimal
%% configuration, and absolutely no config files.
-module(snmerp).

-include_lib("kernel/include/inet.hrl").
-include_lib("snmp/include/snmp_types.hrl").

-ifndef(EDOC).
-include("include/SNMPv2.hrl").
-include("include/SNMPv3.hrl").
-endif.

-record(snmerp, {
	mibs :: snmerp_mib:mibset(),
	sock :: term(),
	ip :: inet:ip_address(),
	timeout :: integer(),
	max_bulk :: integer(),
	retries :: integer(),
	disp_str :: boolean(),
	snmp_ver :: integer(),
	community :: string(),
	username :: string(),
	engine_id :: string(),
	engine_boots :: integer(),
	engine_time :: integer(),
	engine_time_at :: integer(),
	auth_protocol :: atom(),
	auth_password :: string(),
	auth_key :: string(),
	priv_protocol :: atom(),
	priv_password :: string(),
	priv_key :: binary(),
	context :: string()}).

-opaque client() :: #snmerp{}.
-export_type([client/0]).

-type req_option() :: {timeout, Ms :: integer()} | {max_bulk, integer()} | {retries, integer()} | trust_me.
-type req_options() :: [req_option()].
-type option() :: {community, string()} | {mibs, snmerp_mib:mibset()} | {strings, list | binary} | req_option().
-type options() :: [option()].

-type oid() :: tuple().
-type name() :: string().
-type index() :: integer() | [integer()].
-type var() :: oid() | name() | {name(), index()}.
-type enum_value() :: atom().

-type value() :: binary() | string() | integer() | enum_value() | oid() | inet:ip_address() | null | not_found.

-export([open/2, close/1]).
-export([configure/2]).
-export([get/2, get/3]).
-export([walk/2, walk/3]).
-export([set/3, set/4]).
-export([table/3, table/4]).

-export([get_community/1]).
-export([discover/2]).

-define(i32(Int), (Int bsr 24) band 255, (Int bsr 16) band 255, (Int bsr 8) band 255, Int band 255).
-define(i64(Int), (Int bsr 56) band 255, (Int bsr 48) band 255, (Int bsr 40) band 255, (Int bsr 32) band 255, (Int bsr 24) band 255, (Int bsr 16) band 255, (Int bsr 8) band 255, Int band 255).


%% @doc Creates an SNMP client.
%%
%% The client record returned by this function must be provided to other snmerp:
%% functions.
-spec open(inet:ip_address() | inet:hostname(), options()) -> {ok, client()} | {error, term()}.
open(Address, Options) ->
	Ip = case is_tuple(Address) of
		true -> Address;
		false ->
			case inet_res:getbyname(Address, a) of
				{ok, #hostent{h_addr_list = [HAddr | _]}} -> HAddr;
				_ -> undefined
			end
	end,
	case Ip of
		undefined ->
			{error, bad_hostname};
		_ ->

			{ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
			Mibs = case proplists:get_value(mibs, Options) of
				undefined -> snmerp_mib:default();
				M -> M
			end,
			Timeout = proplists:get_value(timeout, Options, 5000),
			MaxBulk = proplists:get_value(max_bulk, Options, 20),
			Retries = proplists:get_value(retries, Options, 3),
			DispStr = proplists:get_value(strings, Options, binary) =:= list,
			case proplists:get_value(snmp_version, Options, 2) of
				2 ->
					Community = proplists:get_value(community, Options, "public"),
					{ok, #snmerp{ip = Ip, sock = Sock, snmp_ver = 2, community = Community, mibs = Mibs, timeout = Timeout, max_bulk = MaxBulk, retries = Retries, disp_str = DispStr}};
				3 ->
					Username = proplists:get_value(username, Options),
					AuthProtocol = proplists:get_value(auth_protocol, Options, none),
					AuthPassword = proplists:get_value(auth_password, Options, []),
					Context = proplists:get_value(context, Options, []),
					PrivProtocol = proplists:get_value(priv_protocol, Options, none),
					PrivPassword = proplists:get_value(priv_password, Options, []),
					%% could convert passwords to keys here?
					{ok, #snmerp{ip = Ip, sock = Sock, snmp_ver = 3, username = Username,
						     auth_protocol = AuthProtocol, auth_password = AuthPassword,
						     priv_protocol = PrivProtocol, priv_password = PrivPassword,
						     context = Context, mibs = Mibs,
						     timeout = Timeout, max_bulk = MaxBulk, retries = Retries, disp_str = DispStr}}
			end

	end.

%% @doc Set options on a client after creation
%%
%% Note: this cannot change the mibs loaded.
-spec configure(client(), option()) -> client().
configure(S = #snmerp{}, {timeout, V}) when is_integer(V) ->
	S#snmerp{timeout = V};
configure(S = #snmerp{}, {max_bulk, V}) when is_integer(V) ->
	S#snmerp{max_bulk = V};
configure(S = #snmerp{}, {retries, V}) when is_integer(V) ->
	S#snmerp{retries = V};
configure(S = #snmerp{snmp_ver = 2}, {community, V}) when is_list(V) ->
	S#snmerp{community = V};
configure(S = #snmerp{snmp_ver = 3}, {context, V}) when is_list(V) ->
	S#snmerp{context = V};
configure(S = #snmerp{}, {strings, binary}) ->
	S#snmerp{disp_str = false};
configure(S = #snmerp{}, {strings, list}) ->
	S#snmerp{disp_str = true};
configure(_S = #snmerp{}, Opt) ->
	error({unsupported_option, Opt}).

%% @private
-spec get_community(client()) -> string().
get_community(#snmerp{snmp_ver = 2, community = C}) -> C.


%% @doc Get a single object
-spec get(client(), var()) -> {ok, value()} | {error, term()}.
get(S = #snmerp{}, Var) ->
	get(S, Var, []).

%% @doc Get a single object
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

%% @doc Set the value of a single object.
-spec set(client(), var(), value()) -> ok | {error, term()}.
set(S = #snmerp{}, Var, Value) ->
	set(S, Var, Value, []).

%% @doc Set the value of a single object.
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

%% @doc Walk a sub-tree of objects, returning all within.
-spec walk(client(), var()) -> {ok, [{index(), value()}]} | {error, term()}.
walk(S = #snmerp{}, Var) ->
	walk(S, Var, []).

%% @doc Walk a sub-tree of objects, returning all within.
-spec walk(client(), var(), req_options()) -> {ok, [{index(), value()}]} | {error, term()}.
walk(S = #snmerp{}, Var, Opts) ->
	Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
	Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
	MaxBulk = proplists:get_value(max_bulk, Opts, S#snmerp.max_bulk),
	Oid = var_to_oid(Var, S),
	VFun = v_to_value_fun(Oid, S),
	case walk_next(S, Oid, Oid, Timeout, Retries, MaxBulk) of
		{ok, Vbs} ->
			OutValues = lists:map(fun(#'VarBind'{name = VbOid, v = V}) ->
				Index = oid_index(Oid, VbOid),
				{Index, VFun(V, Oid, S)}
			end, Vbs),
			{ok, OutValues};
		Err -> Err
	end.

walk_next(S = #snmerp{}, BaseOid, Oid, Timeout, Retries, MaxBulk) ->
	ReqVbs = [#'VarBind'{name = Oid, v = {unSpecified,'NULL'}}],
	ReqPdu = {'get-bulk-request', #'BulkPDU'{'non-repeaters' = 0, 'max-repetitions' = MaxBulk, 'variable-bindings' = ReqVbs}},
	case request_pdu(ReqPdu, Timeout, Retries, S) of
		{ok, #'PDU'{'variable-bindings' = Vbs}} ->
			LastVb = lists:last(Vbs),
			NextOid = LastVb#'VarBind'.name,
			case is_tuple_prefix(BaseOid, NextOid) of
				true ->
					case walk_next(S, BaseOid, NextOid, Timeout, Retries, MaxBulk) of
						{ok, Rest} -> {ok, Vbs ++ Rest};
						Err -> Err
					end;
				false ->
					InPrefix = lists:takewhile(
						fun(#'VarBind'{name = ThisOid}) -> is_tuple_prefix(BaseOid, ThisOid) end, Vbs),
					{ok, InPrefix}
			end;
		Err -> Err
	end.

%% @doc Returns the columns and rows of a table of objects.
-spec table(client(), var(), req_options()) -> {ok, Columns :: [string()], Rows :: [tuple()]} | {error, term()}.
table(S = #snmerp{}, Var, Opts) ->
	TableOid = var_to_oid(Var, S),

	{_TblInfo, _AugMes, ColMes} = snmerp_mib:table_info(tuple_to_list(TableOid), S#snmerp.mibs),

	ColumnNames = [atom_to_list(Me#me.aliasname) || Me <- ColMes],
	ColumnOids = [list_to_tuple(Me#me.oid) || Me <- ColMes],
	ColumnIdxs = trie:new(lists:zip([tuple_to_list(C) || C <- ColumnOids], lists:seq(2, length(ColumnOids)+1))),
	BaseRow = list_to_tuple([null || _ <- lists:seq(1, length(ColumnOids)+1)]),
	BaseRowArray = array:new([{default, BaseRow}]),
	SortedColumnOids = [FirstOid | _] = lists:sort(ColumnOids),

	Timeout = proplists:get_value(timeout, Opts, S#snmerp.timeout),
	Retries = proplists:get_value(retries, Opts, S#snmerp.retries),
	MaxBulk = proplists:get_value(max_bulk, Opts, S#snmerp.max_bulk),
	case table_next(S, SortedColumnOids, FirstOid, Timeout, Retries, MaxBulk, BaseRowArray, ColumnIdxs) of
		{ok, RowArray} -> {ok, ColumnNames, array:sparse_to_list(RowArray)};
		Err -> Err
	end.

%% @doc Returns the rows of a table of objects, selecting particular columns.
-spec table(client(), var(), [var()], req_options()) -> {ok, Rows :: [tuple()]} | {error, term()}.
table(S = #snmerp{}, Var, Columns, Opts) ->
	CheckCols = not lists:member(trust_me, Opts),
	TableOid = var_to_oid(Var, S),

	{_TblInfo, AugMes, _ColMes} = snmerp_mib:table_info(tuple_to_list(TableOid), S#snmerp.mibs),
	ColSet = trie:new([tuple_to_list(TableOid)] ++ [Me#me.oid || Me <- AugMes]),

	ColumnOids = [var_to_oid(C, S) || C <- Columns],
	ColumnIdxs = trie:new(lists:zip([tuple_to_list(T) || T <- ColumnOids], lists:seq(2, length(ColumnOids)+1))),
	BaseRow = list_to_tuple([null || _ <- lists:seq(1, length(ColumnOids)+1)]),
	BaseRowArray = array:new([{default, BaseRow}]),
	SortedColumnOids = [FirstOid | _] = lists:sort(ColumnOids),

	case lists:dropwhile(is_prefixed_fun(ColSet), ColumnOids) of
		[NonMatch | _] when CheckCols ->
			error({column_outside_table, NonMatch, TableOid});
		_ ->
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
	{ok, _, ColumnIdx} = trie:find_prefix_longest(tuple_to_list(Oid), ColumnIdxs),

	LastVb = lists:last(Vbs),
	case is_tuple_prefix(Oid, LastVb#'VarBind'.name) of
		true ->
			InPrefix = Vbs, OutOfPrefix = [];
		false ->
			{InPrefix, OutOfPrefix} = lists:splitwith(
				fun(#'VarBind'{name = ThisOid}) -> is_tuple_prefix(Oid, ThisOid) end, Vbs)
	end,

	VFun = v_to_value_fun(Oid, S),
	RowArray2 = lists:foldl(fun(#'VarBind'{name = ThisOid, v = V}, RA) ->
		RowIdx = oid_single_index(Oid, ThisOid),
		Row = array:get(RowIdx, RA),
		Row2 = case element(1, Row) of
			null -> RealIdx = oid_index(Oid, ThisOid), setelement(1, Row, RealIdx);
			_ -> Row
		end,
		Row3 = setelement(ColumnIdx, Row2, VFun(V, ThisOid, S)),
		array:set(RowIdx, Row3, RA)
	end, RowArray, InPrefix),

	case OutOfPrefix of
		[] ->
			NewOid = LastVb#'VarBind'.name,
			table_next(S, Oids, NewOid, Timeout, Retries, MaxBulk, RowArray2, ColumnIdxs);

		_ ->
			case RestOids of
				[NextOid | _] ->
					case lists:dropwhile(fun(ThisOid) -> not is_tuple_prefix(NextOid, ThisOid) end, OutOfPrefix) of
						NextVbs when (length(NextVbs) > 0) ->
							table_next_vbs(S, RestOids, Timeout, Retries, MaxBulk,
								RowArray2, ColumnIdxs, NextVbs);
						_ ->
							table_next(S, RestOids, NextOid, Timeout, Retries,
								MaxBulk, RowArray2, ColumnIdxs)
					end;
				[] ->
					{ok, RowArray2}
			end
	end.

%% @doc Close and clean up an SNMP client.
-spec close(client()) -> ok.
close(#snmerp{sock = Sock}) ->
	gen_udp:close(Sock).

%% @private
-spec is_tuple_prefix(tuple(), tuple()) -> boolean().
is_tuple_prefix(Tuple1, Tuple2) when is_tuple(Tuple1) and is_tuple(Tuple2) ->
	MinLen = tuple_size(Tuple1),
	case (tuple_size(Tuple2) >= MinLen) of
		true ->
			not lists:any(fun(N) -> element(N,Tuple1) =/= element(N,Tuple2) end, lists:seq(1, MinLen));
		false ->
			false
	end.

%% @private
-spec oid_single_index(oid(), oid()) -> integer().
oid_single_index(BaseOid, Oid) when is_tuple(BaseOid) and is_tuple(Oid) ->
	IdxList = [element(N, Oid) || N <- lists:seq(tuple_size(BaseOid) + 1, tuple_size(Oid))],
	Bin = lists:foldl(fun(I, Bin) ->
		<<Bin/binary, I:32/big>>
	end, <<>>, IdxList),
	binary:decode_unsigned(Bin).

%% @private
-spec oid_index(oid(), oid()) -> integer() | oid().
oid_index(BaseOid, Oid) when is_tuple(BaseOid) and is_tuple(Oid) ->
	IdxList = [element(N, Oid) || N <- lists:seq(tuple_size(BaseOid) + 1, tuple_size(Oid))],
	case IdxList of
		[Idx] -> Idx;
		_ -> list_to_tuple(IdxList)
	end.

snmpv3_auth_data(#snmerp{ auth_protocol = Proto, auth_key = Key }) ->
	case Proto of
		sha -> { sha, [0,0,0,0,0,0,0,0,0,0,0,0], Key, 12 };
		sha256 -> { sha256, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], Key, 24 };
		_ -> { none, [], [], 0 }
	end.

snmpv3_priv_data(#snmerp{ priv_protocol = none }, _EngineBoots, _EngineTime, _Salt) ->
	{ none, [], [], [] };
snmpv3_priv_data(#snmerp{ priv_protocol = Proto, priv_key = FullPrivKey }, EngineBoots, EngineTime, Salt) ->
	Len = case Proto of
		aes -> 16;
		aes256 -> 32
	end,
	IV = list_to_binary([?i32(EngineBoots), ?i32(EngineTime) | Salt]),
	{PrivKey, _} = split_binary(FullPrivKey, Len),
	{ aes_cfb128, Salt, IV, PrivKey }.

snmpv3_header(MsgID, S = #snmerp{}) ->
	AuthFlag = case S#snmerp.auth_protocol of
		none -> 0;
		_ -> 1
	end,
	PrivFlag = case S#snmerp.priv_protocol of
		none -> 0;
		_ -> 2
	end,
	Flags = 4 bor AuthFlag bor PrivFlag,
	#'V3Message_header'{msgID = MsgID, msgMaxSize = 65000, msgFlags = [Flags], msgSecurityModel = 3}.


%% @private
-spec request_pdu({atom(), #'PDU'{} | #'BulkPDU'{}}, integer(), integer(), client()) -> {ok, #'PDU'{}} | {error, term()}.
request_pdu(_, _, 0, _) -> {error, timeout};
request_pdu({PduType, Pdu}, Timeout, Retries, S = #snmerp{sock = Sock, ip = Ip, snmp_ver = 2, community = Com}) ->
	<<_:1, RequestId:31/big>> = crypto:strong_rand_bytes(4),
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
	case recv_reqid_v2(Timeout, Sock, Ip, 161, RequestId) of
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
	end;
request_pdu({PduType, Pdu}, Timeout, Retries, S = #snmerp{sock = Sock, ip = Ip, snmp_ver = 3}) ->
	%% get auth and privacy details
	EngineBoots = S#snmerp.engine_boots,
	{MegaSecs, Secs, _} = erlang:now(),
	TimeDiff = ((MegaSecs * 1000000) + Secs) - S#snmerp.engine_time_at,
	EngineTime = S#snmerp.engine_time + TimeDiff,
	<<_:1, RequestId:31/big>> = crypto:strong_rand_bytes(4),

	{ HMACAlgo, HMACBlank, HMACKey, HMACLen } = snmpv3_auth_data(S),
	%% should generate 64 random bits during snmerp:open and add sequential request ids to that
	%% probably
	{ Cipher, Salt, IV, PrivKey } = snmpv3_priv_data(S, EngineBoots, EngineTime, [?i64(RequestId)]),

	%% encode the pdu
	Pdu2 = case Pdu of
		#'PDU'{} ->
			Pdu#'PDU'{'request-id' = RequestId, 'error-status' = noError, 'error-index' = 0};
		#'BulkPDU'{} ->
			Pdu#'BulkPDU'{'request-id' = RequestId}
	end,
	{ok, PduBin} = 'SNMPv2':encode('PDUs', {PduType, Pdu2}),

	%% construct message parts
	ScopedPdu = #'ScopedPDU'{contextEngineID = S#snmerp.engine_id, contextName = S#snmerp.context, data = PduBin},
	Header = snmpv3_header(RequestId, S),
	Usm = #'USM'{ engineID = S#snmerp.engine_id,
			   engineBoots = EngineBoots,
			   engineTime = EngineTime,
			   username = S#snmerp.username,
			   auth = HMACBlank,
			   privacy = list_to_binary(Salt) },

	%% encrypt the scoped pdu, if we have a privacy protocol
	PrivScopedPdu = case Cipher of
		aes_cfb128 ->
			{ok, ScopedPduBin} = 'SNMPv3':encode('ScopedPDU', ScopedPdu),
			{encrypted, binary_to_list(crypto:block_encrypt(aes_cfb128, PrivKey, IV, ScopedPduBin))};
		none ->	{scopedPDU, ScopedPdu}
	end,

	{ok, UsmBin} = 'SNMPv3':encode('USM', Usm),
	Msg = #'V3Message'{version = 'version-3', header = Header, msgSecurityParameters = UsmBin, data = PrivScopedPdu},
	{ok, MsgBin} = 'SNMPv3':encode('V3Message', Msg),

	%% sign the message, if we have an authentication protocol
	{ok, AuthMsgBin} = case HMACAlgo of
		none ->	{ok, MsgBin};
		_ ->
			HMAC = crypto:hmac(HMACAlgo, HMACKey, MsgBin, HMACLen),
			AuthUsm = Usm#'USM' { auth = binary_to_list(HMAC) },
			{ok, AuthUsmBin} = 'SNMPv3':encode('USM', AuthUsm),
			AuthMsg = Msg#'V3Message' { msgSecurityParameters = AuthUsmBin },
			'SNMPv3':encode('V3Message', AuthMsg)
	end,

	ok = inet:setopts(Sock, [{active, once}]),
	ok = gen_udp:send(Sock, Ip, 161, AuthMsgBin),
	case recv_reqid_v3(S, Timeout, Sock, Ip, 161, RequestId) of
		{ok, {'response', ResponsePdu}} ->
			#'PDU'{'error-status' = ErrSt} = ResponsePdu,
			case ErrSt of
				'noError' -> {ok, ResponsePdu};
				_ -> {error, ErrSt}
			end;
		{ok, {'report', ReportPdu}} ->
			#'PDU'{'variable-bindings' = Vbs} = ReportPdu,
			UnknownUser = var_to_oid({"usmStatsUnknownUserNames", 0}, S),
			ClockSkew = var_to_oid({"usmStatsNotInTimeWindows", 0}, S),
			BadAuthKey = var_to_oid({"usmStatsWrongDigests", 0}, S),
			BadPrivKey = var_to_oid({"usmStatsDecryptionErrors", 0}, S),
			case Vbs of
				[#'VarBind'{'name' = UnknownUser}] -> {error, bad_username};
				[#'VarBind'{'name' = ClockSkew}] -> {error, bad_clock};
				[#'VarBind'{'name' = BadAuthKey}] -> {error, bad_authkey};
				[#'VarBind'{'name' = BadPrivKey}] -> {error, bad_privkey};
				_ -> {error, bad_config}
			end;
		{ok, {RespPduType, _}} ->
			{error, {unexpected_pdu, RespPduType}};
		{error, timeout} ->
			request_pdu({PduType, Pdu}, Timeout, Retries - 1, S);
		Err ->
			Err
	end.



%% @private
-spec recv_reqid_v2(integer(), term(), inet:ip_address(), integer(), integer()) -> {ok, {atom(), #'PDU'{}}} | {error, term()}.
recv_reqid_v2(Timeout, Sock, Ip, Port, ReqId) ->
	receive
		{udp, Sock, Ip, Port, ReplyBin} ->
			case 'SNMPv2':decode('Message', ReplyBin) of
				{ok, #'Message'{version = 'version-2c', data = PduBin}} ->
					case 'SNMPv2':decode('PDUs', PduBin) of
						{ok, {PduType, Pdu = #'PDU'{'request-id' = ReqId}}} ->
							{ok, {PduType, Pdu}};
						{ok, {_PduType, #'PDU'{}}} ->
							ok = inet:setopts(Sock, [{active, once}]),
							recv_reqid_v2(Timeout, Sock, Ip, Port, ReqId);
						_ ->
							{error, bad_pdu_decode}
					end;
				_ ->
					{error, bad_message_decode}
			end
	after Timeout ->
		{error, timeout}
	end.

%% @private
-spec recv_reqid_v3(client(), integer(), term(), inet:ip_address(), integer(), integer()) -> {ok, {atom(), #'PDU'{}}} | {error, term()}.
recv_reqid_v3(S, Timeout, Sock, Ip, Port, ReqId) ->

	receive
		{udp, Sock, Ip, Port, ReplyBin} ->
			case 'SNMPv3':decode('V3Message', ReplyBin) of
				{ok, #'V3Message'{version = 'version-3', header = Header, msgSecurityParameters = UsmBin, data = {_DataType, Data}} = Msg} ->
					{ok, Usm} = 'SNMPv3':decode('USM', UsmBin),

					<<FlagBits>> = Header#'V3Message_header'.msgFlags,
					AuthFlag = (FlagBits band 1) == 1,
					PrivFlag = (FlagBits band 2) == 2,

					%% check authentication
					{ HMACAlgo, HMACBlank, HMACKey, HMACLen } = snmpv3_auth_data(S),
					AuthResult = case {HMACAlgo, AuthFlag} of
						{none, _} -> ok;
						{_, false} -> missing_auth;
						{_, true} ->
							AuthUsm = Usm#'USM' { auth = HMACBlank },
							{ok, AuthUsmBin} = 'SNMPv3':encode('USM', AuthUsm),
							AuthMsg = Msg#'V3Message' { msgSecurityParameters = AuthUsmBin },
							{ok, AuthMsgBin} = 'SNMPv3':encode('V3Message', AuthMsg),
							HMAC = crypto:hmac(HMACAlgo, HMACKey, AuthMsgBin, HMACLen),
							case Usm#'USM'.auth of
								HMAC -> ok;
								_ -> io:format("HMAC mismatch: ~p vs ~p~n", [HMAC, Usm#'USM'.auth]), {error, bad_hmac}
							end
					end,

					Salt = binary_to_list(Usm#'USM'.privacy),
					{ Cipher, _Salt, IV, PrivKey } = snmpv3_priv_data(S, Usm#'USM'.engineBoots, Usm#'USM'.engineTime, Salt),

					case AuthResult of
						{error, _} ->	AuthResult;
						_ ->
							%% decrypt
							{PduBin, ProtStatus} = case {Cipher, PrivFlag} of
								{none, _} ->
									{Data#'ScopedPDU'.data, AuthResult};
								{_, false} ->
									{Data#'ScopedPDU'.data, missing_priv};
								_ ->
									Decrypt = crypto:block_decrypt(Cipher, PrivKey, IV, Data),
									{ok, ScopedPDU} = 'SNMPv3':decode('ScopedPDU', Decrypt),
									{ScopedPDU#'ScopedPDU'.data, AuthResult}
							end,

							case 'SNMPv2':decode('PDUs', PduBin) of
								{ok, {'report', Pdu}} ->
									{ok, {'report', Pdu}};
								{ok, {PduType, Pdu = #'PDU'{'request-id' = ReqId}}} ->
									case ProtStatus of
										ok -> {ok, {PduType, Pdu}};
										_ -> {error, ProtStatus}
									end;
								{ok, {_PduType, #'PDU'{}}} ->
									ok = inet:setopts(Sock, [{active, once}]),
									recv_reqid_v3(S, Timeout, Sock, Ip, Port, ReqId);
								_ ->
									{error, bad_pdu_decode}
							end
					end;
				_ ->
					{error, bad_message_decode}
			end
	after Timeout ->
		{error, timeout}
	end.

%% @doc Password to key conversion and key localization for v3 clients
-spec create_key(client(), atom(), string(), string()) -> string().
create_key(_S = #snmerp{}, none, _EngineID, _Password) ->
	[];
create_key(_S = #snmerp{}, HashAlg, EngineID, Password) ->
	%% good enough for now
	snmp:passwd2localized_key(HashAlg, Password, EngineID).

%% @doc Engine ID and time/boot counter discovery for v3 clients
-spec discover(client(), integer()) -> {ok, client()} | {error, term()}.
discover(S = #snmerp{sock = Sock, ip = Ip, snmp_ver = 3}, Timeout) ->
	<<_:1, RequestId:31/big>> = crypto:strong_rand_bytes(4),

	Pdu = #'PDU'{'request-id' = RequestId, 'error-status' = noError, 'error-index' = 0, 'variable-bindings' = []},
	{ok, PduBin} = 'SNMPv2':encode('PDUs', {'get-request', Pdu}),

	ScopedPdu = #'ScopedPDU'{contextEngineID = [], contextName = [], data = PduBin},
	Header = #'V3Message_header'{msgID = RequestId, msgMaxSize = 65000, msgFlags = [0], msgSecurityModel = 3},

	Usm = #'USM'{ engineID = [], engineBoots = 0, engineTime = 0, username = S#snmerp.username, auth = [], privacy = [] },
	{ok, UsmBin} = 'SNMPv3':encode('USM', Usm),

	Msg = #'V3Message'{version = 'version-3', header = Header, msgSecurityParameters = UsmBin, data = {scopedPDU, ScopedPdu}},
	{ok, MsgBin} = 'SNMPv3':encode('V3Message', Msg),

	ok = inet:setopts(Sock, [{active, once}]),
	ok = gen_udp:send(Sock, Ip, 161, MsgBin),
	receive
		{udp, Sock, Ip, 161, ReplyBin} ->
			case 'SNMPv3':decode('V3Message', ReplyBin) of
				{ok, #'V3Message'{version = 'version-3', header = _Header, msgSecurityParameters = RspUsmBin, data = {scopedPDU, Spdu}}} ->
					{ok, RspUsm} = 'SNMPv3':decode('USM', RspUsmBin),
					case 'SNMPv2':decode('PDUs', Spdu#'ScopedPDU'.data) of
						{ok, {_PduType, _Pdu = #'PDU'{'request-id' = RequestId}}} ->
							EngineID = Spdu#'ScopedPDU'.contextEngineID,
							AuthKey = create_key(S, S#snmerp.auth_protocol, EngineID, S#snmerp.auth_password),
							PrivKey = create_key(S, S#snmerp.auth_protocol, EngineID, S#snmerp.priv_password),
							{MegaSecs, Secs, _} = erlang:now(),
							{ok, S#snmerp{ engine_id = Spdu#'ScopedPDU'.contextEngineID,
								       engine_boots = RspUsm#'USM'.engineBoots,
								       engine_time = RspUsm#'USM'.engineTime,
								       engine_time_at = (MegaSecs * 1000000) + Secs,
								       auth_key = AuthKey,
								       priv_key = list_to_binary(PrivKey) }};
						_ ->
							{error, bad_pdu_decode}
					end;
				_ ->
					{error, bad_message_decode}
			end
	after Timeout ->
		{error, timeout}
	end;
discover(S = #snmerp{}, _Timeout) ->
	{ok, S}.

-spec v_to_value_fun(oid(), client()) -> fun((term(), oid(), client()) -> value()).
v_to_value_fun(Oid, S) ->
	case snmerp_mib:oid_prefix_enum(tuple_to_list(Oid), S#snmerp.mibs) of
		not_found ->
			case snmerp_mib:oid_to_prefix_me(tuple_to_list(Oid), S#snmerp.mibs) of
				#me{entrytype = EntType}
						when (EntType =:= variable) or (EntType =:= table_column) ->
					fun
						({value, {simple, {'integer-value', Int}}}, _, _) -> Int;
						(V, OOid, SS) -> v_to_value(V, OOid, SS) end;
				_ ->
					(fun v_to_value/3)
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
v_to_value({value, {simple, {'string-value', Str}}}, Oid, S = #snmerp{disp_str = true}) when is_binary(Str) ->
	case snmerp_mib:oid_is_string(tuple_to_list(Oid), S#snmerp.mibs) of
		true -> binary_to_list(Str);
		false -> Str
	end;
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
value_to_v(Str, _, _) when is_list(Str) ->
	{value, {simple, {'string-value', list_to_binary(Str)}}};
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
