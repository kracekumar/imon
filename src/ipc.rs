use mioco;

use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::io::{self, Read, Write};
use mioco::tcp::TcpListener;
use msgpack::{Encoder, Decoder};
use rustc_serialize::{Encodable, Decodable};
    
use db;
use Args;


const DEFAULT_LISTEN_ADDR : &'static str = "127.0.0.1:5555";

fn listend_addr() -> SocketAddr {
    FromStr::from_str(DEFAULT_LISTEN_ADDR).unwrap()
}


fn handle_request(args: &Args){
    //Handle command
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
                        let resp = handle_request(&args);
                        //let _ = try!(conn.write_all(&mut buf[..size]));
                    }
                    Ok(())
                }
            );
        }
    }).unwrap();
    println!("{}", "exit");
}


fn send_to_hub(args: &Args){
    // TODO: Come up with accurate number
    let mut buf = [0u8; 120];
    args.encode(&mut Encoder::new(&mut &mut buf[..]));

    // Send the data over the wire
    let mut stream = TcpStream::connect(DEFAULT_LISTEN_ADDR).unwrap();
    let _ = stream.write(&buf);
}


// client
pub fn query(args: &Args){
    /* Query to daemon
     */
    println!("Querying hub");
    send_to_hub(args)
}
