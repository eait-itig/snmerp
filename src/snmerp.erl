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
					{ok, v_to_value(V)};
				_ ->
					{error, {unexpected_varbinds, Vbs}}
			end;
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
	case walk_next(S, Oid, Oid, Timeout, Retries, MaxBulk) of
		{ok, Vbs} ->
			{OutValuesRev, _} = lists:foldl(fun(#'VarBind'{name = VbOid, v = V}, {Values, Seen}) ->
				Index = oid_index(Oid, VbOid),
				case gb_sets:is_element(Index, Seen) of
					true -> {Values, Seen};
					false ->
						Values2 = [{Index, v_to_value(V)} | Values],
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

-spec v_to_value(term()) -> value().
v_to_value({'unSpecified', _}) -> null;
v_to_value({'noSuchObject', _}) -> not_found;
v_to_value('noSuchObject') -> not_found;
v_to_value({'noSuchInstance', _}) -> not_found;
v_to_value('noSuchInstance') -> not_found;
v_to_value({value, {simple, {'string-value', Str}}}) when is_binary(Str) -> Str;
v_to_value({value, {simple, {'integer-value', Int}}}) when is_integer(Int) -> Int;
v_to_value({value, {simple, {'objectID-value', Oid}}}) when is_tuple(Oid) -> Oid;
v_to_value({value, {'application-wide', {'counter-value', Int}}}) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'timeticks-value', Int}}}) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'big-counter-value', Int}}}) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'unsigned-integer-value', Int}}}) when is_integer(Int) -> Int;
v_to_value({value, {'application-wide', {'ipAddress-value', IpBin}}}) when is_binary(IpBin) ->
	<<A,B,C,D>> = IpBin, {A,B,C,D};
v_to_value({value, V}) -> error({unknown_value_type, V}).

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
