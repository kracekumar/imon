#[allow(dead_code)]
#[allow(exceeding_bitshifts)]

use std::sync::{Arc};
use std::thread;
use std::sync::mpsc;
use std::collections::HashMap;

use pcap;
use docopt::Docopt;

use decoder::{decode};
use Args;
use db;
use ipc;

const USAGE: &'static str = "
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
";


fn sniff(sender: &mpsc::Sender<Vec<u8>>){
    /* This is the foundation of the application.

    The function listens to all packets flowing in and out.
    Once the packet is captured, the packet is passed on to the
    decoder thread via channel.
     */
    for device in pcap::Device::list().unwrap() {
        if device.name == "wlan0" {
            let mut cap = device.open().unwrap();
            // Capture the packet forever!
            loop{
                while let Ok(packet) = cap.next() {
                    let len = (&packet.data).len();
                    let mut data = Vec::new();
                    data.resize(len, 0);
                    data.clone_from_slice(&packet);
                    let res = sender.send(data);
                    match res {
                        Ok(_) => {},
                        Err(e) => {
                            /* Without this error handling sometimes code crashes.
                            Whatever happens sniffer thread can't crash.
                            */
                            debug!("{:?}", e);
                        },
                    }
                }
            }
        }
    }
}


fn hub(){
    info!("Starting hub");
    ipc::listen();
}


fn start(){
    /* This is the entry point for daemon.

    Daemon spawns three threads to handle sniffing, decoding, hub.
     */
    info!("Starting daemon");
    let (sender, receiver) = mpsc::channel();

    let domain_cache: HashMap<String, String> = HashMap::new();
    let mut domain_cache_arc = Arc::new(domain_cache);

    let sniffer_handle: thread::JoinHandle<()>;
    let depositer_handle: thread::JoinHandle<()>;

    let hub_handle: thread::JoinHandle<()>;
    // Start sniffer

    sniffer_handle = thread::spawn(move || {
        sniff(&sender);
    });

    let conn = db::create_conn(None);

    // Start depositer
    depositer_handle = thread::spawn(move || {
        decode(&receiver, Arc::get_mut(&mut domain_cache_arc).unwrap(), &conn);
    });
    // Start Hub
    hub_handle = thread::spawn(|| hub());
    // Join all threads
    sniffer_handle.join().unwrap();
    depositer_handle.join().unwrap();
    hub_handle.join().unwrap();
}


pub fn parse_arguments(){
    /* Parse given command line arguments
     */
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());
    info!("{}", args);
    match args.arg_command.as_ref() {
        "start" => {
            start()
        },
        "report" | "site" => {
            ipc::query(&args)
        },
        _ => {
            println!("{}", "Not found command")
        }
    }
}
