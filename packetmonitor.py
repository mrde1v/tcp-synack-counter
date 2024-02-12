import argparse
import time
import socket
from collections import defaultdict

from scapy.all import sniff, IP, TCP

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def capture_stats(interface, local_ip):
    ip_stats_per_second = defaultdict(lambda: {"syn_count": 0, "ack_count": 0})
    ip_stats_overall = defaultdict(lambda: {"syn_count": 0, "ack_count": 0})
    ip_counts = defaultdict(int)

    def packet_callback(packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            if ip_src == local_ip:
                return
            tcp = packet[TCP]
            
            ip_stats_per_second[ip_src]["syn_count"] += 1 if tcp.flags & 2 else 0  # SYN flag
            ip_stats_per_second[ip_src]["ack_count"] += 1 if tcp.flags & 16 else 0  # ACK flag
            
            ip_stats_overall[ip_src]["syn_count"] += 1 if tcp.flags & 2 else 0
            ip_stats_overall[ip_src]["ack_count"] += 1 if tcp.flags & 16 else 0
            
            ip_counts[ip_src] += 1
            
            print("IP:", ip_src, "SYN:", ip_stats_per_second[ip_src]["syn_count"], "ACK:", ip_stats_per_second[ip_src]["ack_count"], "CONN:", ip_counts[ip_src])

    sniff(iface=interface, prn=packet_callback, timeout=1)

    return ip_stats_per_second, ip_stats_overall, ip_counts

def save_ips_above_threshold(ip_counts, threshold, output_file):
    with open(output_file, "w") as f:
        for ip, count in ip_counts.items():
            if count > threshold:
                f.write(f"{ip} PKS: {count}\n")

def save_per_second_stats(ip_stats_per_second, output_file):
    with open(output_file, "a") as f:
        for ip, stats in ip_stats_per_second.items():
            f.write(f"{ip}: SYN={stats['syn_count']}, ACK={stats['ack_count']}\n")

def save_overall_stats(ip_stats_overall, output_file):
    with open(output_file, "w") as f:
        for ip, stats in ip_stats_overall.items():
            f.write(f"{ip}: SYN={stats['syn_count']}, ACK={stats['ack_count']}\n")

def update_overall_stats(ip_stats_per_second, ip_stats_overall):
    for ip, stats in ip_stats_per_second.items():
        ip_stats_overall[ip]["syn_count"] += stats["syn_count"]
        ip_stats_overall[ip]["ack_count"] += stats["ack_count"]

def main():
    parser = argparse.ArgumentParser(description="Capture TCP-SYN and TCP-ACK packets and display network stats")
    parser.add_argument("interface", help="Network interface to capture packets from")
    parser.add_argument("--threshold", type=int, default=10, help="Threshold for saving IP addresses to ips.txt")
    args = parser.parse_args()

    local_ip = get_local_ip()
    print("Server IP:", local_ip)
    print("Capturing stats for interface:", args.interface)
    
    ips_output_file = "ips.txt"
    persecond_output_file = "persecond.txt"
    overall_output_file = "overall.txt"
    
    ip_stats_overall = defaultdict(lambda: {"syn_count": 0, "ack_count": 0})
    
    while True:
        ip_stats_per_second, _, ip_counts = capture_stats(args.interface, local_ip)
        save_ips_above_threshold(ip_counts, args.threshold, ips_output_file)
        save_per_second_stats(ip_stats_per_second, persecond_output_file)
        update_overall_stats(ip_stats_per_second, ip_stats_overall)
        save_overall_stats(ip_stats_overall, overall_output_file)
        
        time.sleep(1)

if __name__ == "__main__":
    main()
