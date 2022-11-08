use std::collections::HashSet;

use std::net::Ipv4Addr;
use libc::timeval;

use pcap::{Capture, Packet, Offline};
use etherparse::*;

mod data_formats;
use crate::data_formats::{FiveTuple, OtherData, TCPInfo};
pub struct PktData {
    pub ft: FiveTuple,
    pub other: OtherData,
    pub tcp: Option<TCPInfo>
}

enum PacketResult {
    DATA(PktData),
    NOT_IP,
    NOT_ETHER,
    IPV6,
    END,
    TIMEOUT
}

pub struct ResultRow {
    pub num_pkts: u64,
    pub num_valid: u64,
    pub num_ipv6: u64,
    pub new_ips: u32,
    pub pkts_from_new_ips: u32,
    pub bytes: u32,
    pub bytes_from_new_ips: u32,
    pub ips_observed: u32,
    pub pkts_old_ips: u32
}

fn get_next_pkt(cap: &mut Capture<Offline>, end_time: timeval) -> PacketResult {
    let pkt = match cap.next().ok() {
        Some(p) => p,
        None => { return PacketResult::END; }
    };
    let arr_time = pkt.header.ts;

    if arr_time.tv_sec > end_time.tv_sec {
        println!("Ending");
        return PacketResult::TIMEOUT;
    }

    //println!("Read packet");
    let eth = match SlicedPacket::from_ethernet(&pkt) { 
        Ok(d) => d, 
        //None => { return PacketResult::NOT_ETHER; }
        Err(e) => match SlicedPacket::from_ip(&pkt).ok() {
            Some(d) => d,
            None => { println!("{:?}", e); return PacketResult::NOT_ETHER; }
        }
        
        
    };
    //println!("{:#?}", eth);
    let ip = match eth.ip {
        Some(d) => d,
        None => { return PacketResult::NOT_IP; }
    };

    let (src_ip, dst_ip, proto, len) = match ip {
        InternetSlice::Ipv4(v4, _) => (v4.source_addr(), v4.destination_addr(), v4.protocol(), v4.payload_len()),
        InternetSlice::Ipv6(v6, _) => { return PacketResult::IPV6; }
    };

    let (src_port, dst_port, tcp) = match eth.transport {
        None => { (0, 0, None) },
        Some(TransportSlice::Tcp(tcp)) =>
            (tcp.source_port(), tcp.destination_port(), Some(TCPInfo::from_tcp_hdr(&tcp))),
        Some(TransportSlice::Udp(udp)) =>
            (udp.source_port(), udp.destination_port(), None),
        Some(_) => { (0, 0, None) }
    };

    let ft = FiveTuple {src_ip, dst_ip, src_port, dst_port, proto};
    let other = OtherData{len, arr_time};
    let data = PktData{ft, other, tcp};

    PacketResult::DATA(data)
}

fn get_next_pkt_force_ipv4(cap: &mut Capture<Offline>, end_time: timeval) -> PacketResult {
    let pkt = match cap.next().ok() {
        Some(p) => p,
        None => { println!("END OF DATA"); return PacketResult::END; }
    };
    let arr_time = pkt.header.ts;

    if arr_time.tv_sec > end_time.tv_sec {
        return PacketResult::TIMEOUT;
    }

    //println!("Read packet");
    let sliced = match SlicedPacket::from_ip(&pkt) { 
        Ok(d) => d, 
        Err(e) => { return PacketResult::NOT_IP; }
    };

    //println!("{:#?}", sliced);

    let ip = match sliced.ip {
        Some(d) => d,
        None => { return PacketResult::NOT_IP; }
    };

    let (src_ip, dst_ip, proto, len) = match ip {
        InternetSlice::Ipv4(v4, _) => (v4.source_addr(), v4.destination_addr(), v4.protocol(), v4.payload_len()),
        InternetSlice::Ipv6(v6, _) => { return PacketResult::IPV6; }
    };

    let (src_port, dst_port, tcp) = match sliced.transport {
        None => { (0, 0, None) },
        Some(TransportSlice::Tcp(tcp)) =>
            (tcp.source_port(), tcp.destination_port(), Some(TCPInfo::from_tcp_hdr(&tcp))),
        Some(TransportSlice::Udp(udp)) =>
            (udp.source_port(), udp.destination_port(), None),
        Some(_) => { (0, 0, None) }
    };

    let ft = FiveTuple {src_ip, dst_ip, src_port, dst_port, proto};
    let other = OtherData{len, arr_time};
    let data = PktData{ft, other, tcp};

    PacketResult::DATA(data)
}


fn open_pcap(path: String) -> Result<Capture<Offline>, pcap::Error> {
    let cap = Capture::from_file(path)?;
    Ok(cap)
}

fn read_to_time(start_time: timeval, start_time_offset_sec: u32, cap: &mut Capture<Offline>) {
    loop {
        let pkt = cap.next().expect("Ran out of packets before hitting target time offset");
        let pkt_time = pkt.header.ts;
        if pkt_time.tv_sec > start_time.tv_sec + start_time_offset_sec as i64 {
            break;
        }
    }
    println!("Read to target time");
}

fn get_time_of_first_packet(cap: &mut Capture<Offline>) -> timeval {
    cap.next().expect("NO FIRST PACKET").header.ts
}

fn main() {
    println!("Hello, world!");
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        println!("Usage: pcap_to_csv <input_pcap> <offset_sec> <duration_sec> <output_csv>");
        println!("<input_pcap>: Path to the input pcap file");
        println!("<offset_sec>: How long into the trace should we start reading (seconds). NOTE: THIS WILL IGNORE UP TO THE FIRST PACKET AFTER THE SPECIFIED TIME, AND THEN CONSIDER FURTHER PACKETS");
        println!("<duration_sec>: How many seconds to read for. (This will disregard every packet after the expiration time)");
        println!("<epoch_dur_sec>: How many seconds per epoch");
        println!("<output_csv>: Path to output CSV to write source IPs to");
        println!("<force_ipv4_encap>: Should we force the system to assume raw IPv4 packets (true|false)");
        println!("NEED TO SET SET force_ipv4_encap TO true FOR CAIDA TRACES (and anything else where capinfos says \"RAW IP\" as the encapsulation type");
        std::process::exit(1);
    }

    let pcap_path: String = args[1].parse().expect("Failed to parse pcap_path");
    let offset_sec: u32 = args[2].parse().expect("Failed to parse offset_sec");
    let duration_sec: u32 = args[3].parse().expect("Failed to parse duration_sec");
    let epoch_dur_sec: u32 = args[4].parse().expect("Failed to parse epoch_dur_sec");
    let output_path: String = args[5].parse().expect("Failed to parse output path");
    let force_ipv4: bool = args[6].parse().expect("Failed to parse force_ipv4_encap as bool");

    let mut pcap = open_pcap(pcap_path).expect("Failed to open pcap");

    let start_time = get_time_of_first_packet(&mut pcap);
    read_to_time(start_time, offset_sec, &mut pcap);

    let end_time = timeval{ tv_sec: start_time.tv_sec + offset_sec as i64 + duration_sec as i64, tv_usec: 0};

    let mut hash_set = HashSet::<Ipv4Addr>::new();
    
    let mut cur_epoch_end = timeval{ tv_sec: start_time.tv_sec + offset_sec as i64 + epoch_dur_sec as i64, tv_usec: 0};
    let mut last_pkt = false;

    let mut result_vec: Vec<ResultRow> = Vec::new();

    loop {
        //WARNING: UNDER THIS APPROACH THE LAST PACKET OF EACH EPOCH IS LOST
        let mut ipv6_cnt = 0;
        let mut not_ip_cnt = 0;
        let mut not_ether_cnt = 0;
        let mut valid = 0;

        let mut bytes = 0;
        let mut epoch_set = HashSet::<Ipv4Addr>::new();
        let mut local_set = HashSet::<Ipv4Addr>::new();
        let mut packets_by_new_ips = 0;
        let mut bytes_by_new_ips = 0;
        let mut pkts_by_old_ips = 0;

        loop {
            let pkt = match force_ipv4 {
                true => get_next_pkt_force_ipv4(&mut pcap, cur_epoch_end),
                false => get_next_pkt(&mut pcap, cur_epoch_end)
            };

            match pkt {
                PacketResult::END => { last_pkt = true; break; },
                PacketResult::NOT_IP => { not_ip_cnt += 1; },
                PacketResult::IPV6 => { ipv6_cnt += 1; },
                PacketResult::NOT_ETHER => { not_ether_cnt += 1; },
                PacketResult::DATA(pkt_vals) => {
                    valid += 1;
                    bytes += pkt_vals.other.len as u32;
                    if !hash_set.contains(&pkt_vals.ft.src_ip) {
                        epoch_set.insert(pkt_vals.ft.src_ip);
                    }
                    else{
                        pkts_by_old_ips += 1;
                    }
                    if epoch_set.contains(&pkt_vals.ft.src_ip){
                        packets_by_new_ips += 1;
                        bytes_by_new_ips += pkt_vals.other.len as u32;
                    }
                    local_set.insert(pkt_vals.ft.src_ip);
                },
                PacketResult::TIMEOUT => { break; }
            }
        }

        let new_ips = epoch_set.len();
        let epoch_ips = local_set.len();

        let result_row = ResultRow {
            num_pkts: valid + ipv6_cnt + not_ip_cnt + not_ether_cnt,
            num_ipv6: ipv6_cnt,
            num_valid: valid,
            bytes: bytes,
            bytes_from_new_ips: bytes_by_new_ips,
            new_ips: new_ips as u32,
            ips_observed: epoch_ips as u32,
            pkts_from_new_ips: packets_by_new_ips,
            pkts_old_ips: pkts_by_old_ips
        };

        result_vec.push(result_row);

        hash_set.extend(epoch_set);

        if cur_epoch_end.tv_sec - (start_time.tv_sec + offset_sec as i64) > duration_sec as i64 {
            break;
        } 

        cur_epoch_end = timeval{ tv_sec: cur_epoch_end.tv_sec + epoch_dur_sec as i64, tv_usec: 0};

        if last_pkt {
            break;
        }        
    }

    println!("SIZE OF HASH SET: {}", hash_set.len());

    // let result_vec: Vec<String> = hash_set.iter().map(|ip| ip.to_string()).collect();
    // let data = result_vec.join("\n");
    // std::fs::write(output_path, data);

    let mut result_strings = Vec::<String>::new();
    result_strings.push(String::from("time,num_pkts,num_bytes,num_valid,num_ipv6,new_ips,new_ip_pkts,old_ip_pkts,new_ip_bytes,total_epoch_ips"));
    let mut cur_time = 0;
    for r in result_vec.iter(){
        let str = format!("{},{},{},{},{},{},{},{},{},{}", cur_time, r.num_pkts, r.bytes, r.num_valid, r.num_ipv6, r.new_ips, r.pkts_from_new_ips, r.pkts_old_ips, r.bytes_from_new_ips, r.ips_observed);
        cur_time += epoch_dur_sec;
        result_strings.push(str);
    }

    let data = result_strings.join("\n");
    std::fs::write(output_path, data).expect("Failed to write result data");
}
