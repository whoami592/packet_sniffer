import socket
import struct
import binascii
import sys
import platform

def main():
    # Create a raw socket
    try:
        if platform.system() == "Windows":
            # On Windows, use IPPROTO_IP for raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            # Bind to the primary network interface
            sock.bind(('0.0.0.0', 0))
            # Include IP headers
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # On Linux, use PF_PACKET for raw socket
            sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except socket.error as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

    print("Packet Sniffer Started... Press Ctrl+C to stop.")

    try:
        while True:
            # Capture packet
            packet, addr = sock.recvfrom(65535)
            # Parse packet
            ethernet_header = packet[:14]
            eth_fields = struct.unpack("!6s6sH", ethernet_header)
            src_mac = binascii.hexlify(eth_fields[0]).decode()
            dst_mac = binascii.hexlify(eth_fields[1]).decode()
            eth_type = eth_fields[2]

            # Format MAC addresses
            src_mac = ':'.join(src_mac[i:i+2] for i in range(0, 12, 2))
            dst_mac = ':'.join(dst_mac[i:i+2] for i in range(0, 12, 2))

            # Check if IP packet
            if eth_type == 0x0800:
                ip_header = packet[14:34]
                ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
                version_ihl = ip_fields[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                protocol = ip_fields[6]
                src_ip = socket.inet_ntoa(ip_fields[8])
                dst_ip = socket.inet_ntoa(ip_fields[9])

                # Parse protocol-specific headers
                if protocol == 6:  # TCP
                    tcp_header = packet[34:54]
                    tcp_fields = struct.unpack("!HHLLBBHHH", tcp_header)
                    src_port = tcp_fields[0]
                    dst_port = tcp_fields[1]
                    print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                elif protocol == 17:  # UDP
                    udp_header = packet[34:42]
                    udp_fields = struct.unpack("!HHHH", udp_header)
                    src_port = udp_fields[0]
                    dst_port = udp_fields[1]
                    print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                elif protocol == 1:  # ICMP
                    icmp_header = packet[34:38]
                    icmp_fields = struct.unpack("!BBH", icmp_header)
                    icmp_type = icmp_fields[0]
                    icmp_code = icmp_fields[1]
                    print(f"ICMP Packet: {src_ip} -> {dst_ip} Type: {icmp_type} Code: {icmp_code}")
                else:
                    print(f"IP Packet: {src_ip} -> {dst_ip} Protocol: {protocol}")
            else:
                print(f"Ethernet Packet: {src_mac} -> {dst_mac} Type: {hex(eth_type)}")

    except KeyboardInterrupt:
        print("\nPacket Sniffer Stopped.")
        if platform.system() == "Windows":
            # Disable promiscuous mode on Windows
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sock.close()

if __name__ == "__main__":
    main()