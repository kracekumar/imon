use std::process;
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
    /* Handle report for daily or over date range
    */
    let mut buf: Vec<TrafficTuple> = Vec::new();
    let conn = db::create_conn(None);
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
            let res = db::Traffic::report_by_date_range(
                val, to, &conn);
            info!("got {} results for date range", res.len());
            for traffic in res.iter(){
                let val = traffic.clone().to_tuple();
                buf.push(val);
            }
        },
        None => {
            let res = db::Traffic::report_today(&conn);
            info!("got {} results", res.len());
            for traffic in res.iter(){
                let val = traffic.clone().to_tuple();
                buf.push(val);
            }
        }
    }
    buf
}


fn handle_site(args: Args) -> Vec<TrafficTuple>{
    /* Handle site specific query.

    Sample requests:
    ----
    site google.com --from 2016-11-01 --to 2016-11-05
    site google.com duckduckgo.com
    site google.com --from 2016-11-01
    */
    let mut buf: Vec<TrafficTuple> = Vec::new();
    let conn = db::create_conn(None);
    match args.flag_from{
        Some(val) => {
            let to = match args.flag_to {
                Some(to) => {
                    to
                },
                None => {
                    // if `to` argument is missing, get current date
                    format!("{}", db::get_current_date().format("%Y-%m-%d"))
                }
            };
            for domain_name in args.arg_args.iter(){
                let res = db::Traffic::filter_site_by_date_range(
                    domain_name.to_string(), val.clone(), to.clone(), &conn);
                info!("got {} results for {}", res.len(), domain_name);
                for traffic in res.iter(){
                    let val = traffic.clone().to_tuple();
                    buf.push(val);
                }
            }
        },
        None => {
            // If `from` argument is missing show all records for the site[s].
            for domain_name in args.arg_args.iter(){
                let res = db::Traffic::filter_site(domain_name.to_string(), &conn);
                info!("got {} results for {}", res.len(), domain_name);
                for traffic in res.iter(){
                    let val = traffic.clone().to_tuple();
                    buf.push(val);
                }
            }
        }
    }
    buf
}


fn handle_request(args: Args) -> Vec<u8>{
    //Handle incoming query
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
            info!("nothing");
        }
    }
    let hub_result = HubResult{result: buf};
    let _ = hub_result.encode(&mut Encoder::new(&mut data));
    data
}


// Server
pub fn listen(){
    /* Listen to all incoming socket connections.

    When a new connection is received spawn a `coroutine`
    and handle data collection and write the result to socket.

    As soon the data is written over the socket, close the connection.
    */
    let _ = mioco::start(|| -> io::Result<()>{
        let addr = listend_addr();

        let listener = try!(TcpListener::bind(&addr));

        info!("Starting hub on {:?}", try!(listener.local_addr()));

        loop {
            let mut conn = try!(listener.accept());

            mioco::spawn(
                move || -> io::Result<()>{
                    // 120 is minimum required
                    let mut buf = [0u8; 150];
                    loop {
                        let size = try!(conn.read(&mut buf));
                        if size == 0 {
                            /* Empty */
                            info!("{}", "Connection closed");
                            break;
                        }
                        let mut decoder = Decoder::new(&buf[..]);
                        let args: Args = Decodable::decode(&mut decoder).ok().unwrap();
                        info!("Received query: {:?}", args);
                        let mut resp = handle_request(args);
                        let _ = try!(conn.write_all(&mut resp[..]));
                        let _ = try!(conn.shutdown(Shutdown::Write));
                    }
                    Ok(())
                }
            );
        }
    }).unwrap();
    info!("{}", "exit");
}


fn send_to_hub(args: &Args) -> Vec<u8>{
    // TODO: Come up with accurate number
    let mut buf = [0u8; 120];
    let _ = args.encode(&mut Encoder::new(&mut &mut buf[..]));

    // Send the data over the wire
    let stream = TcpStream::connect(DEFAULT_LISTEN_ADDR);
    match stream {
        Ok(mut conn) => {
            let _ = conn.write(&buf);
            let mut recv: Vec<u8> = Vec::new();
            let _ = conn.read_to_end(&mut recv);
            recv
        }
        Err(e) => {
            debug!("{:?}", e);
            debug!("check daemon is running");
            process::exit(1);
        }
    }
    
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
