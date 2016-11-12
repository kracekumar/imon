imon [![Build Status](https://travis-ci.org/kracekumar/imon.svg)](https://travis-ci.org/kracekumar/imon) [![codecov](https://codecov.io/gh/kracekumar/imon/branch/master/graph/badge.svg)](https://codecov.io/gh/kracekumar/imon)

Internet bandwidth data usage monitor by domain. [Short presentation](http://slides.com/kracekumarramaraju/who-is-eating-my-bandwidth#/)

### Setup

- The program works with rust nightly. Make sure you have `rust` installed.
Use [rustup](https://www.rustup.rs).

- Install `libpcap-dev` and `libsqlite` for your OS.

- Clone and build the program from source.

``` bash
git clone git@github.com:kracekumar/imon.git
cd imon
cargo build
```

- Start the daemon. The daemon captures `WiFi` packet, so you need to have access to the device.
`#env RUST_LOG=debug ./target/release/imon start`

- Open an another terminal and go the project root directory. Now query the daemon.

```bash
env RUST_LOG=debug ./target/release/imon site google.com
---
Command: site
Arguments: google.com,
---

0| google.com| 1.07 "MB"| "2016-11-02"
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

- [x] Add unit tests
- [x] Add integration tests
- [ ] Publish to crate
- [X] Add command line usage documentation
- [X] Filter local network traffic
- [ ] Add a way to monitor Ethernet port
- [ ] Handle cache IP miss. Send DNS lookup.
- [ ] Support audio/video sites.
- [x] Integrate with travis-ci
- [ ] Write cached IPs to disk before shutting down
- [ ] During startup, read IPs from file
- [ ] IP cache invalidation
- [X] Replace `println` with log.
- [ ] Support IPv6 packets!
- [X] Handle socket connection failure when daemon is down
- [ ] Handle input argument validation
- [X] Move decoding logic to separate file
- [ ] Use multiple threads to handle the packet decoding


### Caveats

- The hashmap stores domain name against IP address. So sites sharing same IP address traffic data will be skewed. `youtube` and `google.com` share similar IPs.
- The majority of sites load static data from CDN, the request goes to IP address of the CDN. As a result the original domain traffic represented is lesser than actual. Though traffic data against the CDN is stored.
- If the daemon is started after opening the browser, DNS request isn't sent until and unless DNS result is expired or DNS result is missing in cache.
