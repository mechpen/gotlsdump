# gotlsdump

Dump TLS payload for go applications.

This tool uses `bpf` and `uprobe` to attach to two go functions:

- `crypto/tls.(*Conn).Read`
- `crypto/tls.(*Conn).Write`

Then dumps data passed to `Write`, and data returned from `Read`.

The `uretprobe` does not work with go applications.  Using `uretprobe`
could crash the application.  This is because go moves stacks around.
To safely catch return values of the tls `Read` function, we first
disassemble the function, then attach `uprobe` to all `ret`
instructions.

## Requirements

- bcc
- python elftools
- python distorm3

## Example

### build and run test go app

```
$ cd test && go build . && ./test https://example.com
```

### run the dump in another terminal

```
$ sudo ./gotlsdump.py --prog test/test --format pcap --output dump
^C
81 packets captured
```

### view the traffic with wireshark

```
$ wireshark-gtk -X lua_script:wireshark/dummy.lua dump
```
![wireshark](wireshark/wireshark.jpg)
