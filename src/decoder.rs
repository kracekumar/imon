use std::sync::mpsc;
use std::str::FromStr;
use std::collections::HashMap;

use packet::{PhysicalLayer, IPv4Packet, TCPPacket, UDPPacket, QSection, DNSAnswer, DNSPacket, DNSRequestType, PacketType, get_packet_type, get_dns_packet_type};
use db;
use std::net::{IpAddr, Ipv4Addr};
use rusqlite::Connection;


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


pub fn decode_dns_packet(packet: &[u8]) ->DNSPacket{
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

    let dns_packet = DNSPacket{id: id, query: query, opcode: opcode, authoriative_answer:authoriative_answer,
                               trun_cation: trun_cation, recursion_desired: recursion_desired,
                               recursion_available: recursion_available, rcode: rcode,
                               qdcount: qdcount, ancount: ancount, nscount: nscount,
                               arcount: arcount, qsection: qsection, answer: answer};

    println!("{:?}", dns_packet);

    dns_packet
}

fn to_ip_from_str(ip: &str) -> Ipv4Addr{
    Ipv4Addr::from_str(ip).unwrap()
}


fn store_packet(ip: String, len: usize, domain_cache: &mut HashMap<String, String>, conn: &Connection){
    let val = domain_cache.get(&ip);
    match val{
        Some(domain_name) => {
            println!("Data for {:?} of {:?} bytes", domain_name, len);
            db::Traffic::create_or_update(domain_name.to_string(), len as i64, conn);
        },
        None => {
            let ipv4 = to_ip_from_str(&ip);
            if !ipv4.is_private(){
                /* Lot of service directly connect to IP address and reverse lookup fails.
                As of now there is no way to trace the origin of the packet domain.
                */
                db::Traffic::create_or_update("unresolved.com".to_string(), len as i64, conn);
            }
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
            }
        }
        else if ipv4_packet.protocol == PacketType::UDP {
            let payload: &[u8] = ipv4_packet.payload;
            let udp_packet = decode_udp_packet(&payload);
            match udp_packet.source_port {
                53 => {
                    let dns_packet = decode_dns_packet(udp_packet.payload.unwrap());
                    if dns_packet.answer.rdata.len() > 0 {
                        let domain_name = get_domain_name(dns_packet.answer.name.clone());
                        for (index, ip) in dns_packet.answer.rdata.iter().enumerate() {
                            domain_cache.insert(ip.to_string(), domain_name.clone());
                        }
                    }
                },
                _ => {
                    
                    store_packet(ipv4_packet.source_ip.to_string(), len, domain_cache, conn);
                }
            }
        }
    }
}


pub fn decode(receiver: &mpsc::Receiver<Vec<u8>>, domain_cache: &mut HashMap<String, String>, conn: &Connection){
    loop{
        let packet = receiver.recv().unwrap();
        decode_packet(packet, domain_cache, conn);
    }
}


#[test]
fn test_decode_dns_packet(){
    let data: &[u8] = &[218, 188, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 10, 107, 114, 97, 99, 101, 107, 117, 109, 97, 114, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 56, 64, 0, 4, 66, 6, 44, 4][..];
    let dns_packet = decode_dns_packet(&data);

    println!("{:?}", dns_packet);
    assert_eq!(dns_packet.answer.ans_type,
               DNSRequestType::A);
    assert_eq!(dns_packet.answer.name, "kracekumar.com");
}
