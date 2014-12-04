Super-simple SNMP client for Erlang.

For when you just want to get/walk some values from something and not have to set up an entire SNMP manager.

## How does it work?

    {ok, C} = snmerp:open("hostname", [{community, "public"}]),
    snmerp:get(C, {"sysName", 0}) % -> {ok, <<"full.hostname">>}
    snmerp:walk(C, "sysName") % -> {ok, [{0, <<"full.hostname">>}]}

You can also load in your own MIBs, by first compiling them to a .bin file with erlc. Then add the path to the .bin files to the MIB database before calling `snmerp:open`, like so:

    {ok, Mibs} = snmerp_mib:add_dir("/some/path/mibs", snmerp_mib:default()),
    {ok, C} = snmerp:open("hostname", [{mibs, Mibs}, ...])
