import argparse
from typing import Callable, Optional, Dict, Any
from scapy.all import sniff, IP, TCP, UDP, ICMP, show_interfaces

def packet_callback_wrapper(callback: Callable[[Dict[str, Any]], None]):
    """
    Returns a callback function that Scapy's sniff() can use.
    It extracts the metadata and passes it to the provided callback,
    ensuring no packet payload is captured.
    """
    def process_packet(packet):
        # We only process IP packets for basic metadata extraction
        if IP in packet:
            ip_layer = packet[IP]
            
            # Determine protocol and ports
            protocol = "Other"
            src_port = None
            dst_port = None
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
                
            # Extract only metadata, excluding payload
            metadata = {
                "timestamp": float(packet.time),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": len(packet)
            }
            
            # Pass the extracted metadata to the user-provided callback
            callback(metadata)
            
    return process_packet


def default_print_callback(metadata: Dict[str, Any]):
    """
    A simple callback that prints the packet metadata to the console.
    """
    # Format ports safely (they might be None for ICMP/Other)
    src = f"{metadata['src_ip']}:{metadata['src_port']}" if metadata['src_port'] else metadata['src_ip']
    dst = f"{metadata['dst_ip']}:{metadata['dst_port']}" if metadata['dst_port'] else metadata['dst_ip']
    
    print(f"[{metadata['timestamp']:.4f}] {metadata['protocol']:>4} | {src} -> {dst} | Length: {metadata['length']} bytes")


def start_sniffer(interface: Optional[str] = None, callback: Callable[[Dict[str, Any]], None] = default_print_callback, count: int = 0):
    """
    Starts the Scapy sniffer on the given interface.
    """
    print(f"Starting sniffer on interface: {interface if interface else 'default (all interfaces)'}")
    print("Press Ctrl+C to stop.")
    
    try:
        # store=False prevents scapy from keeping all captured packets in memory, avoiding memory leaks
        sniff(iface=interface, prn=packet_callback_wrapper(callback), store=False, count=count)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except PermissionError:
        print("\nError: Permission denied. Packet sniffing requires administrative/root privileges.")
        print("Please run this script with elevated privileges (e.g., 'Run as Administrator' or 'sudo').")
    except Exception as e:
        print(f"\nAn error occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetPulse Packet Sniffer")
    parser.add_argument(
        "-i", "--interface", 
        help="Network interface to sniff on. If not provided, sniffs on default.", 
        default=None
    )
    parser.add_argument(
        "-c", "--count", 
        type=int,
        help="Number of packets to capture before exiting (default: 0 = infinite).", 
        default=0
    )
    parser.add_argument(
        "--show-interfaces", 
        action="store_true", 
        help="Show available network interfaces and exit."
    )
    
    args = parser.parse_args()
    
    if args.show_interfaces:
        print("Available Network Interfaces:")
        show_interfaces()
        print("\nRun the script again with '-i <interface_name>' or '-i <interface_index>' to start sniffing.")
    else:
        start_sniffer(interface=args.interface, count=args.count)
