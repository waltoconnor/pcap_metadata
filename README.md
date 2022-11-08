# PCAP metadata collector
This is a small utility that takes a PCAP file, divides it in to windows, and writes aggregate statistics about each window to a CSV file, written as a supporting tool for a larger project.

If parsing data in raw IP packets rather than normal MAC packets (as is the case with CAIDA traces), set the `<force_ipv4_encap>` setting to `true`.

This utility might be useful to someone directly, but also serves as a fairly extensible template for extracting PCAP data with Rust.

A `shell.nix` is provided, this program requires `libc` to be installed.

Currently the collected statistics are:
- Number of packets
- Number of bytes
- Number of valid packets
- Number of IPV6 packets
- Number of packets sent by IPs that appeared for the first time in the current epoch
- Number of packets sent by IPs that have appeared in previous epochs
- Number of bytes sent by new IPs
- Total number unique source IPs observed as of the end of the current epoch

