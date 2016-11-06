use mioco;

use std::net::{SocketAddr, TcpStream, Shutdown};
use std::str::FromStr;
use std::io::{self, Read, Write};
use mioco::tcp::TcpListener;
use msgpack::{Encoder, Decoder};
use rustc_serialize::{Encodable, Decodable};
use db;
use formatter;
use {Args, HubResult, TrafficTuple};


const DEFAULT_LISTEN_ADDR : &'static str = "127.0.0.1:5555";


fn listend_addr() -> SocketAddr {
    FromStr::from_str(DEFAULT_LISTEN_ADDR).unwrap()
}

fn handle_report(args: Args) -> Vec<TrafficTuple>{
    let mut buf: Vec<TrafficTuple> = Vec::new();
    let conn = db::create_conn();
    match args.flag_from{
        Some(val) => {
            let to = match args.flag_to {
                Some(to) => {
                    to
                },
                None => {
                    format!("{}", db::get_current_date().format("%Y-%m-%d"))
                }
            };
            println!("{:?}: {:?}", val, to);
            let res = db::Traffic::report_by_date_range(
                val, to, &conn);
            println!("got {} results for date range", res.len());
            for traffic in res.iter(){
                let mut val = traffic.clone().to_tuple();
                buf.push(val);
            }
        },
        None => {
            let res = db::Traffic::report_today(&conn);
            println!("got {} results", res.len());
            for (index, traffic) in res.iter().enumerate(){
                let mut val = traffic.clone().to_tuple();
                buf.push(val);
            }
        }
    }
    buf
}


fn handle_site(args: Args) -> Vec<TrafficTuple>{
    let mut buf: Vec<TrafficTuple> = Vec::new();
    let conn = db::create_conn();
    match args.flag_from{
        Some(val) => {
            let to = match args.flag_to {
                Some(to) => {
                    to
                },
                None => {
                    format!("{}", db::get_current_date().format("%Y-%m-%d"))
                }
            };
            for domain_name in args.arg_args.iter(){
                let res = db::Traffic::filter_site_by_date_range(
                    domain_name.to_string(), val.clone(), to.clone(), &conn);
                println!("got {} results for {}", res.len(), domain_name);
                for traffic in res.iter(){
                    let mut val = traffic.clone().to_tuple();
                    buf.push(val);
                }
            }
        },
        None => {
            for domain_name in args.arg_args.iter(){
                let res = db::Traffic::filter_site(domain_name.to_string(), &conn);
                println!("got {} results for {}", res.len(), domain_name);
                for traffic in res.iter(){
                    let mut val = traffic.clone().to_tuple();
                    buf.push(val);
                }
            }
        }
    }
    buf
}


fn handle_request(args: Args) -> Vec<u8>{
    //Handle command
    let mut buf: Vec<TrafficTuple> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    match args.arg_command.as_ref() {
        "report" => {
            buf = handle_report(args);
        },
        "site" => {
            buf = handle_site(args);
        },
        _ => {
            println!("nothing");
        }
    }
    let hub_result = HubResult{result: buf};
    let _ = hub_result.encode(&mut Encoder::new(&mut data));
    data
}


// Server
pub fn listen(){
    println!("{}", "started");
    mioco::start(|| -> io::Result<()>{
        let addr = listend_addr();

        let listener = try!(TcpListener::bind(&addr));

        println!("Starting hub on {:?}", try!(listener.local_addr()));

        loop {
            let mut conn = try!(listener.accept());

            mioco::spawn(
                move || -> io::Result<()>{
                    let mut buf = [0u8; 200];
                    loop {
                        let size = try!(conn.read(&mut buf));
                        if size == 0 {
                            /* Empty */
                            println!("{}", "Connection closed");
                            break;
                        }
                        let mut decoder = Decoder::new(&buf[..]);
                        let args: Args = Decodable::decode(&mut decoder).ok().unwrap();
                        println!("Received query: {:?}", args);
                        let mut resp = handle_request(args);
                        let _ = try!(conn.write_all(&mut resp[..]));
                        let _ = try!(conn.shutdown(Shutdown::Write));
                    }
                    Ok(())
                }
            );
        }
    }).unwrap();
    println!("{}", "exit");
}


fn send_to_hub(args: &Args) -> Vec<u8>{
    // TODO: Come up with accurate number
    let mut buf = [0u8; 120];
    args.encode(&mut Encoder::new(&mut &mut buf[..]));

    // Send the data over the wire
    let mut stream = TcpStream::connect(DEFAULT_LISTEN_ADDR).unwrap();
    let _ = stream.write(&buf);
    let mut recv: Vec<u8> = Vec::new();
    stream.read_to_end(&mut recv);
    recv
}


// client
pub fn query(args: &Args){
    /* Query to daemon
     */
    let res = send_to_hub(args);
    // Decode the hub output
    let mut decoder = Decoder::new(&res[..]);
    let res: HubResult = Decodable::decode(&mut decoder).unwrap();
    formatter::display_report(&res, &args.arg_command);
}
