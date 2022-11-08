use std::net::Ipv4Addr;
use libc::timeval;
use etherparse::TcpHeaderSlice;

#[derive(Hash, PartialEq, Eq, Debug)]
pub struct FiveTuple {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8
}

impl std::fmt::Display for FiveTuple {                                                                                  
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {                                                    
        write!(f, "{}:{} --> {}:{} (p={}))", self.src_ip, self.src_port, self.dst_ip, self.src_port, self.proto)
    }                                                                                                                   
}


pub struct OtherData {
    pub len: u16,
    pub arr_time: timeval
}

#[derive(Debug)]
pub struct TCPInfo {
    seq_num: u32,
    ack_num: u32,
    ns: bool,
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl TCPInfo {
    pub fn from_tcp_hdr(hdr: &TcpHeaderSlice) -> Self {
        TCPInfo {
            ns: hdr.ns(),
            cwr: hdr.cwr(),
            ece: hdr.ece(),
            urg: hdr.urg(),
            ack: hdr.ack(),
            psh: hdr.psh(),
            rst: hdr.rst(),
            syn: hdr.syn(),
            fin: hdr.fin(),
            seq_num: hdr.sequence_number(),
            ack_num: hdr.acknowledgment_number()
        }
    }
}