#[macro_use] extern crate log;
extern crate env_logger;
extern crate imon;

fn main(){
    env_logger::init().unwrap();
    imon::cli::parse_arguments();
}

