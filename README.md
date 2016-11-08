Internet bandwidth data usage monitor by domain.

### Setup

- The program works with rust nightly. Make sure you have `rust` installed.
Use [rustup](https://www.rustup.rs).

- Clone and build the program from source.

``` bash
$git clone git@github.com:kracekumar/imon.git
$cd imon
$cargo build
```

- Start the daemon. The daemon captures `WiFi` packet, so you need to have access to the device.
`$sudo ./target/debug/imon start`

- Open an another terminal and go the project root directory. Now query the daemon.

``` bash
./target/debug/imon site google.com zulipchat.com duckduckgo.com
---
Command: site
Arguments: google.com, zulipchat.com, duckduckgo.com,
---

0| google.com| 1.07 "MB"| "2016-11-02"
1| google.com| 7.18 "MB"| "2016-11-03"
2| google.com| 1.03 "MB"| "2016-11-04"
3| google.com| 1.08 "MB"| "2016-11-05"
4| google.com| 9.23 "MB"| "2016-11-06"
5| google.com| 6.22 "MB"| "2016-11-07"
6| zulipchat.com| 2.36 "MB"| "2016-11-03"
7| zulipchat.com| 1.83 "MB"| "2016-11-05"
8| zulipchat.com| 3.48 "MB"| "2016-11-06"
9| duckduckgo.com| 468.15 "KB"| "2016-11-02"
10| duckduckgo.com| 1.29 "MB"| "2016-11-03"
11| duckduckgo.com| 365.41 "KB"| "2016-11-04"
12| duckduckgo.com| 1.10 "MB"| "2016-11-05"
13| duckduckgo.com| 462.53 "KB"| "2016-11-06"
14| duckduckgo.com| 2.55 "MB"| "2016-11-07"

```

### Help

```bash
user@user-ThinkPad-T400 ~/c/imon> ./target/debug/imon -h
imon

Usage:
  imon <command> [<args> ...] [--from=<from>] [--to=<to>]
       [-h|--help]

Options:
  -h --help     Show this screen.
  --version     Show version. # Not yet implemented
  --start       Start date in the format YYYY-MM-DD
  --end         End date in the format YYYY-MM-DD

The mostly used commands are
    start    Start the daemon
    report   Report
    site     Display Site specific data

Examples - Querying
--------
- ./target/debug/imon site google.com zulipchat.com duckduckgo.com
- ./target/debug/imon site google.com
- ./target/debug/imon site google.com --from 2016-11-01
- ./target/debug/imon site google.com --from 2016-11-01 --to 2016-11-03
- ./target/debug/imon report
- ./target/debug/imon report --from 2016-11-05
- ./target/debug/imon report --from 2016-11-05 --to 2016-11-05

```

### TODO

- [ ] Add unit tests
- [ ] Add integration tests
- [ ] Publish to crate
- [X] Add command line usage documentation
- [X] Filter local network traffic
- [ ] Add a way to monitor Ethernet port
- [ ] Handle cache IP miss. Send DNS lookup.
- [ ] Support audio/video sites.
- [ ] Integrate with travis-ci
- [ ] Write cached IPs to disk before shutting down
- [ ] During startup, read IPs from file
- [ ] IP cache invalidation
- [ ] Replace `println` with log.
- [ ] Support IPv6 packets!
- [ ] Handle socket connection failure when daemon is down
- [ ] Handle input argument validation
- [X] Move decoding logic to separate file
- [ ] Use multiple threads to handle the packet decoding

### Autostart
