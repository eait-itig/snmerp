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
%% @doc Functions to create and manipulate MIB sets.
%%
%% MIB sets can be provided to the snmerp client module to resolve
%% names and metadata about requested objects.
-module(snmerp_mib).

-include_lib("snmp/include/snmp_types.hrl").

-export([empty/0, add_file/2, add_dir/2, name_to_oid/2, oid_to_prefix_me/2,
	oid_to_me/2, oid_prefix_enum/2, table_info/2, default/0]).

-record(mibdat, {
	name2oid = trie:new() :: trie:trie(),
	oid2me = trie:new() :: trie:trie(),
	tables = trie:new() :: trie:trie(),
	enums = trie:new() :: trie:trie()}).

-opaque mibset() :: #mibdat{}.
-type oid() :: [integer()].
-type name() :: string().
-type me() :: #me{}.
-type enum() :: [{integer(), atom()}].
-export_type([mibset/0]).

%% @doc Returns an empty MIB set
-spec empty() -> mibset().
empty() ->
	#mibdat{}.

%% @doc Returns the default MIB set (with SNMPv2-MIB only)
-spec default() -> mibset().
default() ->
	case snmerp_mib:add_dir(filename:join([code:priv_dir(snmerp), "mibs"]), snmerp_mib:empty()) of
		{ok, Mibs} -> Mibs;
		{error, Err} -> error(Err)
	end.

%% @doc Resolves a string name to an OID
-spec name_to_oid(name(), mibset()) -> oid() | not_found.
name_to_oid(Name, #mibdat{name2oid = Name2Oid}) ->
	case trie:find(Name, Name2Oid) of
		{ok, Oid} -> Oid;
		_ -> not_found
	end.

%% @private
-spec table_info(oid(), mibset()) -> {#table_info{}, Augmented :: [me()], Columns :: [me()]} | not_found.
table_info(Oid, #mibdat{tables = Tables}) ->
	case trie:find(Oid, Tables) of
		{ok, Mes} ->
			{[TblMe | AugmentMes], ColMes} = lists:partition(fun(Me) -> Me#me.entrytype =:= table end, Mes),
			TblInfo = proplists:get_value(table_info, TblMe#me.assocList),
			{TblInfo, AugmentMes, ColMes};
		_ -> not_found
	end.

%% @private
-spec oid_to_prefix_me(oid(), mibset()) -> me() | not_found.
oid_to_prefix_me(Oid, #mibdat{oid2me = Oid2Me}) ->
	case trie:find_prefix_longest(Oid, Oid2Me) of
		{ok, _FoundOid, Me} -> Me;
		_ -> not_found
	end.

%% @private
-spec oid_prefix_enum(oid(), mibset()) -> enum() | not_found.
oid_prefix_enum(Oid, #mibdat{enums = Enums}) ->
	case trie:find_prefix_longest(Oid, Enums) of
		{ok, _FoundOid, Enum} -> Enum;
		_ -> not_found
	end.

%% @private
-spec oid_to_me(oid(), mibset()) -> me() | not_found.
oid_to_me(Oid, #mibdat{oid2me = Oid2Me}) ->
	case trie:find(Oid, Oid2Me) of
		{ok, Me} -> Me;
		_ -> not_found
	end.

-spec add_names_enums(#mib{}, mibset()) -> mibset().
add_names_enums(#mib{mes = Mes}, D = #mibdat{}) ->
	lists:foldl(fun
		(Me = #me{entrytype = Type}, DD = #mibdat{})
				when (Type =:= table) or (Type =:= table_column) or (Type =:= variable) ->
			#me{aliasname = NameAtom, oid = Oid, asn1_type = Asn1Type} = Me,
			#mibdat{name2oid = Name2Oid, oid2me = Oid2Me, enums = Enums} = DD,
			Name2Oid2 = trie:store(atom_to_list(NameAtom), Oid, Name2Oid),
			Oid2Me2 = trie:store(Oid, Me, Oid2Me),
			Enums2 = case Asn1Type of
				#asn1_type{} ->
					case proplists:get_value(enums, Asn1Type#asn1_type.assocList) of
						undefined -> Enums;
						RawEnum ->
							Enum = [{V, K} || {K,V} <- RawEnum],
							trie:store(Oid, Enum, Enums)
					end;
				_ -> Enums
			end,
			DD#mibdat{name2oid = Name2Oid2, oid2me = Oid2Me2, enums = Enums2};
		(_, DD) -> DD
	end, D, Mes).

-spec add_table_entries(#mib{}, mibset()) -> mibset().
add_table_entries(#mib{mes = Mes}, D = #mibdat{}) ->
	lists:foldl(fun
		(Me = #me{entrytype = table_entry}, DD = #mibdat{}) ->
			#me{aliasname = NameAtom, mfa = MFA} = Me,
			#mibdat{name2oid = Name2Oid} = DD,
			{snmp_generic,table_func,[{TableAtom,_}]} = MFA,
			TableOid = trie:fetch(atom_to_list(TableAtom), Name2Oid),
			Name2Oid2 = trie:store(atom_to_list(NameAtom), TableOid, Name2Oid),
			DD#mibdat{name2oid = Name2Oid2};
		(_, DD) -> DD
	end, D, Mes).

-spec add_table_columns(#mib{}, mibset()) -> mibset().
add_table_columns(#mib{mes = Mes}, D = #mibdat{}) ->
	lists:foldl(fun
		(Me = #me{entrytype = Type}, DD = #mibdat{})
				when (Type =:= table) or (Type =:= table_column) ->
			#me{oid = Oid, assocList = Assocs} = Me,
			#mibdat{name2oid = Name2Oid, tables = Tbls} = DD,
			Tbls2 = case proplists:get_value(table_name, Assocs) of
				undefined when (Type =:= table) ->
					TableInfo = proplists:get_value(table_info, Assocs),
					TTbls = case TableInfo#table_info.index_types of
						{augments, {ParentTblAtom, _}} ->
							ParentOid = trie:fetch(atom_to_list(ParentTblAtom), Name2Oid),
							trie:append(ParentOid, Me, Tbls);
						_ -> Tbls
					end,
					trie:append(Oid, Me, TTbls);
				undefined -> Tbls;
				TblNameAtom ->
					TblOid = trie:fetch(atom_to_list(TblNameAtom), Name2Oid),
					trie:append(TblOid, Me, Tbls)
			end,
			DD#mibdat{tables = Tbls2};
		(_, DD) -> DD
	end, D, Mes).

%% @doc Adds a .bin file to a MIB set.
-spec add_file(Path :: string(), mibset()) -> {ok, mibset()} | {error, Reason :: term()}.
add_file(Path, D = #mibdat{}) ->
	case file:read_file(Path) of
		{ok, Bin} ->
			case (catch binary_to_term(Bin)) of
				{'EXIT', Reason} -> {error, Reason};
				Mib = #mib{} ->
					D2 = add_names_enums(Mib, D),
					D3 = add_table_entries(Mib, D2),
					D4 = add_table_columns(Mib, D3),
					{ok, D4}
			end;
		{error, Reason} -> {error, Reason}
	end.

%% @doc Adds a directory of .bin files to a MIB set.
-spec add_dir(Path :: string(), mibset()) -> {ok, mibset()} | {error, Reason :: term()}.
add_dir(Path, D = #mibdat{}) ->
	case file:list_dir(Path) of
		{ok, Fnames} ->
			Mibs = lists:foldl(fun(Fn, Acc) ->
				case lists:suffix(".bin", Fn) of
					true ->
						case file:read_file(filename:join([Path, Fn])) of
							{ok, Bin} ->
								case (catch binary_to_term(Bin)) of
									{'EXIT', _Reason} -> Acc;
									Mib = #mib{} -> [Mib | Acc]
								end;
							_ -> Acc
						end;
					false -> Acc
				end
			end, [], Fnames),
			D2 = lists:foldl(fun add_names_enums/2, D, Mibs),
			D3 = lists:foldl(fun add_table_entries/2, D2, Mibs),
			D4 = lists:foldl(fun add_table_columns/2, D3, Mibs),
			{ok, D4};
		{error, Reason} -> {error, Reason}
	end.
