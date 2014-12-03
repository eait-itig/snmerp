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
%% @doc snmerp mib api
-module(snmerp_mib).

-include_lib("snmp/include/snmp_types.hrl").

-export([empty/0, add_file/2, add_dir/2, name_to_oid/2, oid_to_prefix_me/2, oid_to_me/2]).

-record(mibdat, {
	name2oid = trie:new() :: trie:trie(),
	oid2me = trie:new() :: trie:trie()}).

-opaque mibs() :: #mibdat{}.
-type oid() :: [integer()].
-type name() :: string().
-type me() :: #me{}.
-export_type([mibs/0]).

-spec empty() -> mibs().
empty() ->
	#mibdat{}.

-spec name_to_oid(name(), mibs()) -> oid() | not_found.
name_to_oid(Name, #mibdat{name2oid = Name2Oid}) ->
	case trie:find(Name, Name2Oid) of
		{ok, Oid} -> Oid;
		_ -> not_found
	end.

-spec oid_to_prefix_me(oid(), mibs()) -> me() | not_found.
oid_to_prefix_me(Oid, #mibdat{oid2me = Oid2Me}) ->
	case trie:find_prefix_longest(Oid, Oid2Me) of
		{ok, _FoundOid, Me} -> Me;
		_ -> not_found
	end.

-spec oid_to_me(oid(), mibs()) -> me() | not_found.
oid_to_me(Oid, #mibdat{oid2me = Oid2Me}) ->
	case trie:find(Oid, Oid2Me) of
		{ok, Me} -> Me;
		_ -> not_found
	end.

-spec add_file(Path :: string(), mibs()) -> {ok, mibs()} | {error, Reason :: term()}.
add_file(Path, D = #mibdat{}) ->
	case file:read_file(Path) of
		{ok, Bin} ->
			case (catch binary_to_term(Bin)) of
				{'EXIT', Reason} -> {error, Reason};
				#mib{mes = Mes} ->
					D2 = lists:foldl(fun
						(Me = #me{entrytype = EntType}, DD = #mibdat{})
								when (EntType =:= variable) or (EntType =:= table) or (EntType =:= table_column) ->
							#me{oid = Oid, aliasname = NameAtom} = Me,
							#mibdat{name2oid = Name2Oid, oid2me = Oid2Me} = DD,
							Name2Oid2 = trie:store(atom_to_list(NameAtom), Oid, Name2Oid),
							Oid2Me2 = trie:store(Oid, Me, Oid2Me),
							DD#mibdat{name2oid = Name2Oid2, oid2me = Oid2Me2};
						(#me{}, DD = #mibdat{}) ->
							DD
					end, D, Mes),
					{ok, D2}
			end;
		{error, Reason} -> {error, Reason}
	end.

-spec add_dir(Path :: string(), mibs()) -> {ok, mibs()} | {error, Reason :: term()}.
add_dir(Path, D = #mibdat{}) ->
	case file:list_dir(Path) of
		{ok, Fnames} ->
			D2 = lists:foldl(fun(Fn, DD) ->
				case lists:suffix(".bin", Fn) of
					true ->
						case add_file(filename:join([Path, Fn]), DD) of
							{ok, DD2} -> DD2;
							_ -> DD
						end;
					false -> DD
				end
			end, D, Fnames),
			{ok, D2};
		{error, Reason} -> {error, Reason}
	end.
