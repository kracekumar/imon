#[allow(dead_code)]

extern crate pcap;
extern crate argparse;

use std::sync::{Arc, Mutex};
use std::thread;
use std::sync::mpsc;


fn start_hub(){
    println!("starting the pcap")
}


fn sniff(sender: &mpsc::Sender<&[u8]>){
    println!("Sniff");
    for device in pcap::Device::list().unwrap() {
        println!("device");
        if device.name == "wlan0" {
            println!("Found device! {:?}", device);
            let mut cap = device.open().unwrap();
            loop{
                while let Ok(packet) = cap.next() {
                    println!("got packet! {:?}", packet);
                    // let data = packet.data.clone();
                    // sender.send(data).unwrap();
                }
            }
        }
    }
}


fn depositer(receiver: &mpsc::Receiver<&[u8]>){
    loop{
        println!("Received: {:?}", receiver.recv().unwrap());
    }
}

fn hub(){
    println!("Hub");
}


fn fetcher(){
    println!("Fetcher");
}


fn start(){
    println!("Start");
    // ZMQ socket
    // Pcap library capture
    let data = Arc::new(Mutex::new(0));

    let (sender, receiver) = mpsc::channel();

    let sniffer_handle: thread::JoinHandle<()>;
    let depositer_handle: thread::JoinHandle<()>;
    let hub_handle: thread::JoinHandle<()>;
    let fetcher_handle: thread::JoinHandle<()>;
    // Start sniffer
    sniffer_handle = thread::spawn(move || {
        sniff(&sender);
    });
    // Start depositer
    depositer_handle = thread::spawn(move || {
        depositer(&receiver);
    });
    // Start Hub
    hub_handle = thread::spawn(|| hub());
    // Start fetcher
    fetcher_handle = thread::spawn(|| fetcher());
    // Join all threads
    sniffer_handle.join().unwrap();
    depositer_handle.join().unwrap();
    hub_handle.join().unwrap();
    fetcher_handle.join().unwrap();
}


fn top(){
    println!("top");
}


fn invalid(){
    println!("Invalid args")
}


pub fn parse_arguments(){
    // Attach all commands
    let mut verbose = false;
    let mut command = "".to_string();
    {
        let mut parser = argparse::ArgumentParser::new();
        parser.set_description("imon is a command line utility to monitor internet data consumption");
        parser.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], argparse::StoreTrue,
                        "Be verbose");
        parser.refer(&mut command).required()
            .add_argument("command", argparse::Store,
                          r#"Command to run (either "start" or "top")"#);
        parser.parse_args_or_exit();
    }
    // Get all commands from user
    match command.as_ref() {
        "start" => start(),
        "top" => top(),
        _ => invalid(),
    }
}
