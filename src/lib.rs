#![feature(plugin)]
#![plugin(docopt_macros)]

extern crate rusqlite;
extern crate time;
extern crate chrono;
extern crate mioco;
extern crate bytes;
extern crate rmp_serialize as msgpack;
extern crate rustc_serialize;
extern crate docopt;
extern crate pcap;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate resolve;

use std::fmt;

pub mod cli;
pub mod decoder;
pub mod packet;
pub mod db;
pub mod ipc;
pub mod formatter;


pub type TrafficTuple = (String, i64, String);


#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct Args {
    flag_from: Option<String>,
    flag_to: Option<String>,
    arg_args: Vec<String>,
    arg_command: String,
}


impl fmt::Display for Args{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        let mut message: String = "---\n".to_string();
        message.push_str(&format!("Command: {}\n", self.arg_command));

        if self.arg_args.len() > 0 {
            message.push_str(&format!("Arguments: "));
            for arg in self.arg_args.iter() {
                message.push_str(&format!("{}, ", arg));
            }
            message.push('\n');
        }

        match self.flag_from{
            Some(ref val) => {
                message.push_str(&format!("Start date: {}\n", val));
            },
            None => {
            }
        }

        match self.flag_to{
            Some(ref val) => {
                message.push_str(&format!("To date: {}\n", val));
            },
            None => {
            }
        }
        message.push_str(&"---\n".to_string());
        write!(f, "{}", message)
    }
}


#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct HubResult{
    result: Vec<TrafficTuple>
}
