#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub enum PacketType{
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
pub enum DNSRequestType{
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
pub struct PhysicalLayer<'a>{
    pub dst: String,
    pub src: String,
    pub packet_type: PacketType,
    pub raw: &'a [u8]
}


#[derive(Debug, Clone)]
pub struct IPv4Packet<'a>{
    pub version: String,
    pub ihl: u8,
    pub tos: String, /* type of service */
    pub total_length: i32,
    pub id: String,
    pub flags: String,
    pub fragment_offset: String,
    pub ttl: String,
    pub protocol: PacketType,
    pub header_checksum: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub options: String,
    pub payload: &'a [u8],
    pub raw: &'a [u8]
}


#[derive(Debug, Clone)]
pub struct TCPPacket<'a>{
    pub source_port: u16,
    pub destination_port: u16,
    pub seq_num: u64,
    pub ack_num: u64,
    pub data_offset: u8,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window_size: u16,
    pub checksum: u16,
    pub options: String,
    pub payload: Option<&'a[u8]>,
    pub raw: &'a [u8]
}


#[derive(Debug, Clone)]
pub struct UDPPacket<'a>{
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Option<&'a[u8]>,
    pub raw: &'a [u8]
}


#[derive(Debug, Clone)]
pub struct DNSPacket{
    pub id: u16,
    pub query: bool, // Query or Response
    pub opcode: u8,
    pub authoriative_answer: bool, // Authoriative Answer
    pub trun_cation: bool, // TrunCation
    pub recursion_desired: bool, // Recursion Desired
    pub recursion_available: bool, // Recursion available
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub qsection: QSection,
    pub answer: DNSAnswer
}


#[derive(Debug, Clone)]
pub struct QSection{
    pub qname: String,
    pub qtype: DNSRequestType,
    pub qclass: u16
}


#[derive(Debug, Clone)]
pub struct DNSAnswer{
    pub name: String,
    pub ans_type: DNSRequestType,
    pub class: u16,
    pub ttl: u32,
    pub rlength: u16,
    pub rdata: Vec<String>
}


impl DNSAnswer{
    pub fn update_name(&mut self, name: String){
        self.name = name;
    }
}


#[derive(Debug, Clone)]
pub struct Traffic{
    pub domain_name: String,
    pub bytes: u32
}


pub fn get_packet_type(type_data: String) -> PacketType{
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


pub fn get_dns_packet_type(record_data: u16) -> DNSRequestType{
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
