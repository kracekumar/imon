extern crate rusqlite;
extern crate time;
extern crate chrono;
extern crate mioco;
extern crate bytes;
extern crate rmp_serialize as msgpack;
extern crate rustc_serialize;
extern crate docopt;

use rustc_serialize::{Encodable, Decodable};
use msgpack::encode::Encoder;

pub mod cli;
mod db;
mod ipc;
mod formatter;

#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct Args {
    flag_today: bool,
    flag_week: bool,
    arg_start_date: Option<String>,
    arg_end_date: Option<String>,
    cmd_start: bool,
    cmd_report: bool,
}

// #[derive(Debug, RustcDecodable, RustcEncodable)]
// pub struct ShadowArgs {
//     flag_today: bool,
//     flag_week: bool,
//     arg_start_date: Option<String>,
//     arg_end_date: Option<String>,
//     cmd_start: bool,
//     cmd_report: bool,
// }


// impl ShadowArgs{
//     pub fn from_args(args: &Args) -> ShadowArgs{
//         ShadowArgs{flag_today: args.flag_today, flag_week: args.flag_week,
//                    arg_start_date: args.arg_start_date,
//                    arg_end_date: args.arg_end_date, cmd_start: args.cmd_start,
//                    cmd_report: args.cmd_report
//         }
//     }
// }
