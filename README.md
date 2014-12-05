Super-simple SNMP client for Erlang.

For when you just want to get/walk some values from something and not have to set up an entire SNMP manager.

## How does it work?

    {ok, C} = snmerp:open("hostname", [{community, "public"}]),
    snmerp:get(C, {"sysName", 0})
        -> {ok, <<"full.hostname">>}
    snmerp:walk(C, "sysName")
        -> {ok, [{0, <<"full.hostname">>}]}

You can also load in your own MIBs, by first compiling them to a .bin file with erlc. Then add the path to the .bin files to the MIB database before calling `snmerp:open`, like so:

    {ok, Mibs} = snmerp_mib:add_dir("/some/path/mibs", snmerp_mib:default()),
    {ok, C} = snmerp:open("hostname", [{mibs, Mibs}, ...])

And it has dedicated table fetching support:

    snmerp:table(C, "ifTable", [])
        -> {ok, ["ifIndex", "ifDescr", "ifType", ...], [
                {1,1,"eth0",ethernet,...},
                {2,2,"eth1",ethernet,...}, ...]}
    snmerp:table(C, "ifTable", ["ifType", "ifDescr"], [])
        -> {ok, [{1, ethernet, "eth0"}, {2, ethernet, "eth1"}, ...]}

## API documentation

[See here](http://arekinath.github.io/snmerp/).

## License

2-clause BSD

