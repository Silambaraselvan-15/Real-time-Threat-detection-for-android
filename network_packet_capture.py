"""
Network Packet Capture for Anomaly Detection
Captures IP and DNS data using Scapy for threat detection
"""

from scapy.all import sniff, IP, DNS, DNSQR, DNSRR, UDP, get_if_list
import pandas as pd
from datetime import datetime
import json
import os
from collections import defaultdict, Counter

class NetworkPacketCapture:
    def __init__(self, output_dir="captured_data"):
        """Initialize packet capture with storage"""
        self.output_dir = output_dir
        self.packets_data = []
        self.dns_data = []
        self.ip_data = []
        self.suspicious_ips = Counter()
        self.suspicious_domains = Counter()
        self.dns_queries = defaultdict(int)
        self.ip_flows = defaultdict(lambda: {"count": 0, "timestamps": []})
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def extract_ip_info(self, packet):
        """Extract IP layer information"""
        if IP in packet:
            ip_layer = packet[IP]
            ip_info = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "ttl": ip_layer.ttl,
                "protocol": ip_layer.proto,
                "packet_length": len(packet),
                "flags": ip_layer.flags,
                "fragmented": ip_layer.frag != 0
            }
            return ip_info
        return None
    
    def extract_dns_info(self, packet):
        """Extract DNS layer information"""
        if DNS in packet:
            dns_layer = packet[DNS]
            dns_info = {
                "timestamp": datetime.now().isoformat(),
                "dns_id": dns_layer.id,
                "is_response": dns_layer.qr,
                "opcode": dns_layer.opcode,
                "return_code": dns_layer.rcode,
                "questions": [],
                "answers": []
            }
            
            # Extract DNS queries
            if dns_layer.qdcount > 0:
                for i in range(dns_layer.qdcount):
                    question = dns_layer.qd[i]
                    query_name = question.qname.decode('utf-8', errors='ignore').rstrip('.')
                    query_type = question.qtype
                    dns_info["questions"].append({
                        "domain": query_name,
                        "query_type": query_type
                    })
                    self.dns_queries[query_name] += 1
            
            # Extract DNS responses
            if dns_layer.ancount > 0:
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    answer_name = answer.rrname.decode('utf-8', errors='ignore').rstrip('.')
                    answer_data = answer.rdata if hasattr(answer, 'rdata') else "N/A"
                    dns_info["answers"].append({
                        "domain": answer_name,
                        "answer": str(answer_data),
                        "ttl": answer.ttl
                    })
            
            return dns_info
        return None
    
    def packet_callback(self, packet):
        """Callback function for packet processing"""
        try:
            # Extract IP information
            ip_info = self.extract_ip_info(packet)
            if ip_info:
                self.ip_data.append(ip_info)
                flow_key = f"{ip_info['src_ip']} -> {ip_info['dst_ip']}"
                self.ip_flows[flow_key]["count"] += 1
                self.ip_flows[flow_key]["timestamps"].append(ip_info["timestamp"])
            
            # Extract DNS information
            dns_info = self.extract_dns_info(packet)
            if dns_info:
                self.dns_data.append(dns_info)
                
                # Track DNS queries for anomaly detection
                for question in dns_info["questions"]:
                    domain = question["domain"]
                    if self.dns_queries[domain] > 10:  # Flag domains with many queries
                        self.suspicious_domains[domain] += 1
            
            # Store combined packet info
            if ip_info:
                packet_info = ip_info.copy()
                packet_info["has_dns"] = dns_info is not None
                if dns_info:
                    packet_info["dns_queries"] = len(dns_info["questions"])
                self.packets_data.append(packet_info)
            
            # Print progress
            print(f"[+] Captured {len(self.packets_data)} packets", end="\r")
            
        except Exception as e:
            print(f"[-] Error processing packet: {e}")
    
    def save_data_to_csv(self):
        """Save captured data to CSV files"""
        try:
            # Save IP data
            if self.ip_data:
                ip_df = pd.DataFrame(self.ip_data)
                ip_csv_path = os.path.join(self.output_dir, "ip_data.csv")
                ip_df.to_csv(ip_csv_path, index=False)
                print(f"\n[+] Saved IP data to {ip_csv_path}")
            
            # Save DNS data
            if self.dns_data:
                dns_df = pd.DataFrame([
                    {
                        "timestamp": d["timestamp"],
                        "is_response": d["is_response"],
                        "questions": json.dumps(d["questions"]),
                        "answers": json.dumps(d["answers"])
                    }
                    for d in self.dns_data
                ])
                dns_csv_path = os.path.join(self.output_dir, "dns_data.csv")
                dns_df.to_csv(dns_csv_path, index=False)
                print(f"[+] Saved DNS data to {dns_csv_path}")
            
            # Save combined packet data
            if self.packets_data:
                packet_df = pd.DataFrame(self.packets_data)
                packet_csv_path = os.path.join(self.output_dir, "packets_data.csv")
                packet_df.to_csv(packet_csv_path, index=False)
                print(f"[+] Saved packet data to {packet_csv_path}")
        
        except Exception as e:
            print(f"[-] Error saving data: {e}")
    
    def save_data_to_json(self):
        """Save captured data to JSON files"""
        try:
            # Save all data
            all_data = {
                "metadata": {
                    "capture_time": datetime.now().isoformat(),
                    "total_packets": len(self.packets_data),
                    "total_dns_packets": len(self.dns_data),
                    "total_ip_flows": len(self.ip_flows)
                },
                "ip_data": self.ip_data,
                "dns_data": self.dns_data,
                "dns_queries": dict(self.dns_queries),
                "suspicious_domains": dict(self.suspicious_domains),
                "ip_flows": dict(self.ip_flows)
            }
            
            json_path = os.path.join(self.output_dir, "network_data.json")
            with open(json_path, 'w') as f:
                json.dump(all_data, f, indent=2)
            print(f"[+] Saved JSON data to {json_path}")
        
        except Exception as e:
            print(f"[-] Error saving JSON: {e}")
    
    def print_statistics(self):
        """Print capture statistics"""
        print("\n" + "="*60)
        print("CAPTURE STATISTICS")
        print("="*60)
        print(f"Total Packets Captured: {len(self.packets_data)}")
        print(f"DNS Packets: {len(self.dns_data)}")
        print(f"IP Flows: {len(self.ip_flows)}")
        print(f"Unique DNS Queries: {len(self.dns_queries)}")
        print(f"Suspicious Domains (>10 queries): {len(self.suspicious_domains)}")
        
        if self.dns_queries:
            print("\nTop 10 DNS Queries:")
            for domain, count in self.dns_queries.most_common(10):
                print(f"  {domain}: {count}")
        
        if self.ip_flows:
            print("\nTop 10 IP Flows:")
            sorted_flows = sorted(
                self.ip_flows.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )[:10]
            for flow, data in sorted_flows:
                print(f"  {flow}: {data['count']} packets")
    
    def start_capture(self, packet_count=0, timeout=60, interface=None, filters=""):
        """
        Start packet capture
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds
            interface: Network interface to sniff on (None = all interfaces)
            filters: BPF filter (e.g., "tcp port 53" for DNS)
        """
        try:
            if interface is None:
                # Try to get the default interface
                interfaces = get_if_list()
                if interfaces:
                    interface = interfaces[0]
                    print(f"[+] Using default interface: {interface}")
                else:
                    print("[-] No network interfaces found")
                    return
            
            print(f"[+] Starting packet capture on {interface}")
            print(f"[+] Packet count: {packet_count if packet_count > 0 else 'unlimited'}")
            print(f"[+] Timeout: {timeout} seconds")
            if filters:
                print(f"[+] Filters: {filters}")
            print("[+] Press Ctrl+C to stop\n")
            
            # Start sniffing
            sniff(
                prn=self.packet_callback,
                iface=interface,
                filter=filters,
                count=packet_count if packet_count > 0 else 0,
                timeout=timeout,
                store=False
            )
        
        except PermissionError:
            print("[-] Error: This script requires administrator/root privileges!")
            print("[*] Please run as administrator (Windows) or with sudo (Linux/Mac)")
        except Exception as e:
            print(f"[-] Error starting capture: {e}")
    
    def save_all_data(self):
        """Save captured data in all formats"""
        self.save_data_to_csv()
        self.save_data_to_json()
        self.print_statistics()


def main():
    """Main execution"""
    import sys
    
    # Configuration
    packet_count = 0  # 0 = capture until timeout
    timeout = 60  # seconds
    interface = None  # None = auto-detect
    filters = ""  # Empty = all traffic, "dns" = DNS only, "tcp port 53" = DNS TCP
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        try:
            packet_count = int(sys.argv[1])
        except ValueError:
            pass
    
    if len(sys.argv) > 2:
        try:
            timeout = int(sys.argv[2])
        except ValueError:
            pass
    
    if len(sys.argv) > 3:
        interface = sys.argv[3]
    
    if len(sys.argv) > 4:
        filters = sys.argv[4]
    
    # Create capture instance
    capturer = NetworkPacketCapture(output_dir="captured_data")
    
    # Start capturing
    capturer.start_capture(packet_count=packet_count, timeout=timeout, interface=interface, filters=filters)
    
    # Save results
    capturer.save_all_data()


if __name__ == "__main__":
    main()
