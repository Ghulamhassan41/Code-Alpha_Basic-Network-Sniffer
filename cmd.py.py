"""
CodeAlpha Internship - Task 1: Basic Network Sniffer
------------------------------------------------------
This program captures live network packets and displays useful
information about them: source/destination IP, protocol, ports,
and a preview of the payload (the actual data being sent).

LEGAL/ETHICAL NOTE:
Only run this on a network you own or have explicit permission to
monitor (e.g. your home network or a lab/test environment). Capturing
traffic on networks you don't own or lack permission for is illegal
in most countries.

Requirements:
    pip install scapy
    Run with administrator/root privileges:
        Windows -> run terminal "as Administrator"
        Linux/Mac -> use 'sudo python3 sniffer.py'
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Keep a simple counter so we can see how many packets we've captured
packet_count = 0


def process_packet(packet):
    """
    This function runs automatically every time a new packet is captured.
    'packet' is the captured network packet object from scapy.
    """
    global packet_count
    packet_count += 1

    print(f"\n{'='*60}")
    print(f"Packet #{packet_count}  |  Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")

    # --- Check if the packet has an IP layer ---
    # Almost all internet traffic uses IP (Internet Protocol) to route
    # data between devices. If this layer isn't present, we skip it.
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src         # Where the packet came from
        dst_ip = ip_layer.dst         # Where the packet is going
        print(f"Source IP:      {src_ip}")
        print(f"Destination IP: {dst_ip}")

        # --- Figure out which protocol is being used on top of IP ---
        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport = packet[TCP].sport   # Source port
            dport = packet[TCP].dport   # Destination port
            print(f"Protocol:       {proto_name}")
            print(f"Source Port:    {sport}")
            print(f"Destination Port: {dport}")

        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"Protocol:       {proto_name}")
            print(f"Source Port:    {sport}")
            print(f"Destination Port: {dport}")

        elif packet.haslayer(ICMP):
            # ICMP is used for things like 'ping'
            print("Protocol:       ICMP (e.g. ping)")

        else:
            print(f"Protocol:       Other (IP protocol number: {ip_layer.proto})")

        # --- Show a small preview of the actual data (payload) ---
        # We only show the first 50 bytes so the output doesn't flood
        # your terminal, and we ignore characters that can't be printed.
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                preview = payload[:50].decode(errors="replace")
            except Exception:
                preview = str(payload[:50])
            print(f"Payload Preview: {preview}")
    else:
        # Non-IP packets (e.g. ARP) - just note that we saw one
        print("Non-IP packet captured (e.g. ARP) - skipping details")


def main():
    print("Starting network sniffer...")
    print("Press Ctrl+C to stop.\n")

    # sniff() is the scapy function that does all the heavy lifting:
    #   - prn=process_packet  -> call our function for every packet
    #   - store=False         -> don't keep packets in memory (saves RAM)
    #   - count=0              -> 0 means capture forever until stopped
    #
    # Optional: you can filter traffic using BPF syntax, e.g.:
    #   sniff(filter="tcp", prn=process_packet, store=False)
    # to only capture TCP packets.
    try:
        sniff(prn=process_packet, store=False, count=0)
    except KeyboardInterrupt:
        print(f"\n\nStopped. Total packets captured: {packet_count}")
    except PermissionError:
        print("\nERROR: Permission denied.")
        print("Try running this script with administrator/root privileges.")


if __name__ == "__main__":
    main()
