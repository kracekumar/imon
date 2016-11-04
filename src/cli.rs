#[allow(dead_code)]
#[allow(exceeding_bitshifts)]

extern crate pcap;

use std;
use std::sync::{Arc, Mutex};
use std::thread;
use std::sync::mpsc;
use rusqlite::Connection;
use std::collections::HashMap;

use docopt::Docopt;
use Args;
use db;
use ipc;

const USAGE: &'static str = "
imon

Usage:
  imon start
  imon report [--today | --week]
  imon report from <start_date> to <end_date>
  imon (-h | --help)
  imon --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --today       Take today's date as argument
  --week        Take this week date range as argument
";



#[derive(Debug, Clone)]
#[derive(PartialEq)]
enum PacketType{
    IPv4,
    ARP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Unknown
}


#[derive(Debug, Clone)]
#[derive(PartialEq)]
enum DNSRequestType{
    A,
    NS,
    CNAME,
    SOA,
    WKS,
    PTR,
    MX,
    SRV,
    AAAA,
    ANY,
    Unknown
}


#[derive(Debug, Clone)]
struct PhysicalLayer<'a>{
    dst: std::string::String,
    src: std::string::String,
    packet_type: PacketType,
    raw: &'a [u8]
}


#[derive(Debug, Clone)]
struct IPv4Packet<'a>{
    version: std::string::String,
    ihl: u8,
    tos: std::string::String, /* type of service */
    total_length: i32,
    id: std::string::String,
    flags: std::string::String,
    fragment_offset: std::string::String,
    ttl: std::string::String,
    protocol: PacketType,
    header_checksum: std::string::String,
    source_ip: std::string::String,
    destination_ip: std::string::String,
    options: std::string::String,
    payload: &'a [u8],
    raw: &'a [u8]
}


#[derive(Debug, Clone)]
struct TCPPacket<'a>{
    source_port: u16,
    destination_port: u16,
    seq_num: u64,
    ack_num: u64,
    data_offset: u8,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
    window_size: u16,
    checksum: u16,
    options: std::string::String,
    payload: Option<&'a[u8]>,
    raw: &'a [u8]
}


#[derive(Debug, Clone)]
struct UDPPacket<'a>{
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    payload: Option<&'a[u8]>,
    raw: &'a [u8]
}


#[derive(Debug, Clone)]
struct DNSPacket<'a>{
    id: u16,
    query: bool, // Query or Response
    opcode: u8,
    authoriative_answer: bool, // Authoriative Answer
    trun_cation: bool, // TrunCation
    recursion_desired: bool, // Recursion Desired
    recursion_available: bool, // Recursion available
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    qsection: &'a QSection,
    answer: &'a DNSAnswer,
    raw: &'a [u8]
}


#[derive(Debug, Clone)]
struct QSection{
    qname: String,
    qtype: DNSRequestType,
    qclass: u16
}


#[derive(Debug, Clone)]
struct DNSAnswer{
    name: String,
    ans_type: DNSRequestType,
    class: u16,
    ttl: u32,
    rlength: u16,
    rdata: Vec<String>
}


impl DNSAnswer{
    fn update_name(&mut self, name: String){
        self.name = name;
    }
}


#[derive(Debug, Clone)]
struct Traffic{
    domain_name: String,
    bytes: u32
}


fn get_packet_type(type_data: std::string::String) -> PacketType{
    // https://www.wikiwand.com/en/EtherType
    match type_data.as_ref() {
        "0800" => PacketType::IPv4,
        "86dd" => PacketType::IPv6,
        "6" => PacketType::TCP,
        "0806" => PacketType::ARP,
        "11" => PacketType::UDP,
        "1" => PacketType::ICMP,
        _ => PacketType::Unknown
    }

}


fn get_dns_packet_type(record_data: u16) -> DNSRequestType{
    match record_data {
        1 => DNSRequestType::A,
        2 => DNSRequestType::NS,
        5 => DNSRequestType::CNAME,
        6 => DNSRequestType::SOA,
        11 => DNSRequestType::WKS,
        12 => DNSRequestType::PTR,
        15 => DNSRequestType::MX,
        33 => DNSRequestType::SRV,
        28 => DNSRequestType::AAAA,
        255 => DNSRequestType::ANY,
        _ => DNSRequestType::Unknown
    }
}


fn start_hub(){
    println!("starting the pcap")
}


fn bytes_to_int(values: &[u8]) -> u64{
    fn shifter(values: &[u8], multiplier: u64) -> u64{
        let mut mul = multiplier;
        let mut sum: u64 = 0;
        let no_of_pos_to_shift: u64 = 8;
        for i in values.iter() {
            sum = sum + ((*i as u64) << mul) as u64;
            if mul != 0 {
                mul = mul - no_of_pos_to_shift;
            }
        }
        sum
    }

    match values.len(){
        2 => {
            shifter(values, 8 as u64)
        },
        3 => {
            shifter(values, 16 as u64)
        },
        4 => {
            shifter(values, 24 as u64)
        }
        _ => {0 as u64}
    }
}


fn decode_physical_layer(packet: &[u8]) -> PhysicalLayer{
    let dst = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                      packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    let src = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                      packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    let packet_type = format!("{:02x}{:02x}", packet[12], packet[13]);
    PhysicalLayer{dst: dst, src: src, packet_type: get_packet_type(packet_type), raw: packet}
}


fn decode_ipv4_packet(packet: &[u8]) -> IPv4Packet{
    // First 4 bit
    let version = format!("{:x}", packet[0] & 240);
    // Next four bit
    let ihl = packet[0] & 15;
    let tos = format!("{:x}", packet[1]);
    let total_length = format!("{:x}{:x}", packet[2], packet[3]);
    let total_length = i32::from_str_radix(&total_length, 16).unwrap();
    let id = format!("{:x}{:x}", packet[4], packet[5]);
    let flags = format!("{:x}", packet[6] >> 5);
    let fragment_offset = format!("{:x}{:x}", packet[6] >> 3, packet[7]);
    let ttl = format!("{:x}", packet[8]);
    let protocol = get_packet_type(format!("{:x}", packet[9]));
    let header_checksum = format!("{:x}{:x}", packet[10], packet[11]);
    let source_ip = format!("{:?}.{:?}.{:?}.{:?}",
                            packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = format!("{:?}.{:?}.{:?}.{:?}",
                                 packet[16], packet[17], packet[18], packet[19]);

    let mut options = String::new();
    let mut payload_start = 0;
    if ihl > 5 {
        for p in packet[20..].iter() {
            options.push_str(&format!("{:x}", p));
        }
        payload_start = ihl * 4;
    }
    else {
        // At this point there is no options, so everything else is payload
        payload_start = ihl * 4;
    }

    let payload: &[u8] = &packet[payload_start as usize ..];
    
    IPv4Packet{version: version, ihl: ihl, tos: tos, total_length: total_length, id: id,
               flags: flags, fragment_offset: fragment_offset, ttl: ttl, protocol: protocol,
               header_checksum: header_checksum, source_ip: source_ip,
               destination_ip: destination_ip, options: options,
               payload: &payload, raw: packet}
}


fn decode_tcp_packet(packet: &[u8]) -> TCPPacket{
    let source_port  = bytes_to_int(&packet[0..2]) as u16;

    let destination_port = bytes_to_int(&packet[2..4]) as u16;

    let seq_num = bytes_to_int(&packet[4..8]);
    let ack_num = bytes_to_int(&packet[8..12]);

    let data_offset = 4 * (packet[12] >> 4);

    let window_size = ((packet[14] as u16) << 8) + packet[15] as u16;

    let checksum = bytes_to_int(&packet[14..16]) as u16;

    let mut options = String::new();
    let mut payload = None;

    if data_offset >= 20 {
        if data_offset < packet.len() as u8{
            payload = Some(&packet[data_offset as usize ..]);
            for p in packet[16..data_offset as usize].iter(){
                options.push_str(&format!("{:x}", p));
            }
        }
        else {
            payload = None;
        }
        
    }

    let flags = format!("{:08b}", packet[13]).into_bytes();

    fn set_or_unset(bit: u8) -> bool{
        // 49 is 1 in ASCII
        match bit {
            49 => true,
            _ => false,
        }
    }
    let urg = set_or_unset(flags[2]);
    let ack = set_or_unset(flags[3]);
    let psh = set_or_unset(flags[4]);
    let rst = set_or_unset(flags[5]);
    let syn = set_or_unset(flags[6]);
    let fin = set_or_unset(flags[7]);
    TCPPacket{source_port: source_port, destination_port: destination_port, seq_num: seq_num,
              ack_num: ack_num, data_offset: data_offset, window_size: window_size,
              checksum: checksum, options: options, payload: payload, urg: urg, ack: ack, psh: psh,
              syn: syn, fin: fin, raw: &packet, rst: rst}
}


fn decode_udp_packet(packet: &[u8]) -> UDPPacket{
    let source_port  = bytes_to_int(&packet[0..2]) as u16;
    let destination_port = bytes_to_int(&packet[2..4]) as u16;
    let length = bytes_to_int(&packet[4..6]) as u16;
    let checksum = bytes_to_int(&packet[6..8]) as u16;
    let payload = Some(&packet[8..]);

    UDPPacket{source_port: source_port, destination_port: destination_port,
              length: length, checksum: checksum, payload: payload,
              raw: &packet}
}

fn extract_dns_name(packet: &[u8]) -> (String, u16){
    let mut start: u16 = 1;
    let mut stop: u16 = (packet[0] + 1) as u16;
    let mut domain_name = String::new();
    while true {
        let v: Vec<u8> = packet[start as usize ..stop as usize].iter().map({|x| *x}).collect();
        domain_name.push_str(&String::from_utf8(v).unwrap());
        if packet[stop as usize] == 0 {
            break;
        } else {
            domain_name.push('.');
        }
        start = stop + 1 as u16;
        stop = start + (packet[stop as usize] as u16);
    }
    (domain_name, stop + 1)
}


fn extract_dns_question(packet: &[u8]) -> (QSection, &[u8]){
    /* Total answers is represented by anscount variable. 
    If the value is 6. There are six IP address associated with 
    domain name.

    QName is a variable length string encoded in Standard DNS name
    notation like “[3] w w w [13] x y z i n d u s t r i e s [3] c o m [0]”.

    QType unsigned 16 bit representing record type.

    QClass unsigned 16 bit representing class of resource records.
     */
    let (domain_name, last_read_position) = extract_dns_name(&packet);
    let qtype = bytes_to_int(&packet[last_read_position as usize .. (last_read_position + 2) as usize]) as u16;
    let qclass = bytes_to_int(&packet[(last_read_position + 2) as usize .. (last_read_position + 4) as usize]) as u16;

    (QSection{qname: domain_name,
              qtype: get_dns_packet_type(qtype),
              qclass: qclass},
     &packet[(last_read_position + 4) as usize ..])
}


fn extract_dns_answer(packet: &[u8]) -> Option<DNSAnswer>{
    if packet.len() <= 0 as usize {
        None
    } else {
        match packet[0]{
            192 => {
                /*192 = 11000000 */
                /* First byte tells if the response is pointer based reference.
                Second byte tells the position from which request domain name starts from.
                This is already parsed in question section. Pick the name from there.
                 */
                let mut start = 2;
                let ans_type = get_dns_packet_type(
                    bytes_to_int(&packet[start as usize .. (start + 2) as usize]) as u16);
                start += 2;
                let class = bytes_to_int(&packet[start as usize .. (start + 2) as usize]) as u16;
                start = start + 2;
                let ttl = bytes_to_int(&packet[start as usize .. (start + 4) as usize]) as u32;
                start = start + 4;
                let rlength = bytes_to_int(&packet[start as usize .. (start + 2) as usize]) as u16;
                start = start + 2;
                let mut rdata = Vec::new(); /* Assumption maximum of 6 IPs */
                if ans_type == DNSRequestType::A || ans_type == DNSRequestType::CNAME {
                    for i in 0..(rlength/4) {
                        let ip_octets: &[u8] = &packet[(start) as usize .. (start + 4) as usize];
                        let address = format!("{:?}.{:?}.{:?}.{:?}",
                                              ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]);
                        rdata.push(address);
                        start = start + 4;
                    }
                }
                // TODO: Support AAAA, SOA and other records
                Some(DNSAnswer{name: "".to_string(), ans_type: ans_type, class: class,
                               ttl: ttl, rlength: rlength, rdata: rdata})
            },
            _ => {
                // This is DNS notation. TODO: Implement
                None
            }
        }
    }
}


fn get_domain_name(name: String) -> String{
    let cloned_name = name.clone();
    let words: Vec<&str> = name.split('.').collect();
    let len = words.len();
    let mut domain_name = String::new();
    if len > 2 {
        domain_name.push_str(words[len - 2 as usize]);
        domain_name.push_str(".");
        domain_name.push_str(words[len - 1 as usize]);
        domain_name
    } else {
        cloned_name
    }
}


fn decode_dns_packet(packet: &[u8], domain_cache: &mut HashMap<String, String>){
    let id = bytes_to_int(&packet[0..2]) as u16;
    // This is the first bit
    let query = (packet[2] & 10000000) == 1;
    // 1 to 4th bit
    let opcode = packet[2] & 01111000;
    let authoriative_answer = (packet[2] & 00000100) == 1;
    let trun_cation = (packet[2] & 00000010) == 1;
    let recursion_desired = (packet[2] & 00000001) == 1;
    let recursion_available = (packet[3] & 10000000) == 1;
    // Next three bits are not neccessary
    let rcode = packet[3] & 00001111;
    let qdcount = bytes_to_int(&packet[4..6]) as u16;
    let ancount = bytes_to_int(&packet[6..8]) as u16;
    let nscount = bytes_to_int(&packet[8..10]) as u16;
    let arcount = bytes_to_int(&packet[10..12]) as u16;
    //question_name = bytes_to_int
    let (qsection, answer_data) = extract_dns_question(&packet[12..]);
    let mut answer = extract_dns_answer(&answer_data).unwrap();

    if answer.name == "" {
        answer.update_name(qsection.qname.clone());
    }

    let mut answer_clone = answer.clone();
    let qsection_clone = qsection.clone();

    let dns_packet = DNSPacket{id: id, query: query, opcode: opcode, authoriative_answer:authoriative_answer,
                               trun_cation: trun_cation, recursion_desired: recursion_desired,
                               recursion_available: recursion_available, rcode: rcode,
                               qdcount: qdcount, ancount: ancount, nscount: nscount,
                               arcount: arcount, qsection: &qsection, answer: &answer,
                               raw: &packet};

    let cloned_dns_packet = dns_packet.clone();
    println!("{:?}", dns_packet);

    if answer_clone.rdata.len() > 0 {
        let domain_name = get_domain_name(answer_clone.name.clone());
        for (index, ip) in answer_clone.rdata.iter().enumerate() {
            domain_cache.insert(ip.to_string(), domain_name.clone());
        }
    }
}


fn store_packet(ip: String, len: usize, domain_cache: &mut HashMap<String, String>, conn: &Connection){
    let val = domain_cache.get(&ip);
    match val{
        Some(domain_name) => {
            println!("Data for {:?} of {:?} bytes", domain_name, len);
            db::Traffic::create_or_update(domain_name.to_string(), len as i64, conn);
        },
        None => {
            println!("IP is missing in cache{:?}", ip);
        }
    }
}


fn decode_packet(packet: Vec<u8>, domain_cache: &mut HashMap<String, String>, conn: &Connection){
    let len = packet.len();
    let physical_layer_packet = decode_physical_layer(&packet);
    if physical_layer_packet.packet_type == PacketType::IPv4 {
        let ipv4_packet = decode_ipv4_packet(&packet[14 ..]);

        if ipv4_packet.protocol == PacketType::TCP {
            let payload: &[u8] = ipv4_packet.payload;
            let tcp_packet = decode_tcp_packet(&payload);
            if (tcp_packet.source_port == 80) | (tcp_packet.source_port == 443){
                store_packet(ipv4_packet.source_ip.to_string(), len, domain_cache, conn);
            } else if (tcp_packet.destination_port == 80) | (tcp_packet.destination_port == 443){
                store_packet(ipv4_packet.destination_ip.to_string(), len, domain_cache, conn);
            }
            else {
                store_packet(ipv4_packet.destination_ip.to_string(), len, domain_cache, conn);
                println!("Non HTTP tcp packet {:?}, {:?}", ipv4_packet, tcp_packet);
            }
        }
        else if ipv4_packet.protocol == PacketType::UDP {
            let payload: &[u8] = ipv4_packet.payload;
            let udp_packet = decode_udp_packet(&payload);
            match udp_packet.source_port {
                53 => decode_dns_packet(udp_packet.payload.unwrap(), domain_cache),
                _ => {
                    store_packet(ipv4_packet.source_ip.to_string(), len, domain_cache, conn);
                }
            }
        }
    }
}


fn sniff(sender: &mpsc::Sender<Vec<u8>>){
    for device in pcap::Device::list().unwrap() {
        if device.name == "wlan0" {
            println!("Found device! {:?}", device);
            let mut cap = device.open().unwrap();
            loop{
                while let Ok(packet) = cap.next() {
                    let len = (&packet.data).len();
                    let mut data = Vec::new();
                    data.resize(len, 0);
                    data.clone_from_slice(&packet);
                    sender.send(data).unwrap();
                }
            }
        }
    }
}


fn decode(receiver: &mpsc::Receiver<Vec<u8>>, domain_cache: &mut HashMap<String, String>, conn: &Connection){
    loop{
        let packet = receiver.recv().unwrap();
        decode_packet(packet, domain_cache, conn);
    }
}


fn depositer(receiver: &mpsc::Receiver<Traffic>){
    loop{
        let packet = receiver.recv().unwrap();
        /*
        3. Save to DB.
         */
    }
}


fn hub(){
    println!("Hub");
    ipc::listen();
}


fn fetcher(){
    println!("Fetcher");
}


fn start(){
    println!("Start");
    // ZMQ socket
    // Pcap library capture
    let (sender, receiver) = mpsc::channel();
    let mut domain_cache: HashMap<String, String> = HashMap::new();
    let mut domain_cache_arc = Arc::new(domain_cache);

    let sniffer_handle: thread::JoinHandle<()>;
    let depositer_handle: thread::JoinHandle<()>;
    let hub_handle: thread::JoinHandle<()>;
    let fetcher_handle: thread::JoinHandle<()>;
    // Start sniffer
    sniffer_handle = thread::spawn(move || {
        sniff(&sender);
    });
    let conn = db::create_conn();
    // Start depositer
    depositer_handle = thread::spawn(move || {
        decode(&receiver, Arc::get_mut(&mut domain_cache_arc).unwrap(), &conn);
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
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());
    println!("{:?}", args);
    if args.cmd_start {
        start();
    } else if args.cmd_report {
        if args.flag_today{
            ipc::query(&args);
        } else {
            println!("{}", "nothing now");
        }
    }
}
