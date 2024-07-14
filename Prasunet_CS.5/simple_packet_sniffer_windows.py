import socket
import struct
import logging
import datetime
import argparse

# Setup logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Unpack Ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC address
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Unpack IPv4 packet
def unpack_ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = socket.inet_ntoa(src)
    dest_ip = socket.inet_ntoa(target)
    return src_ip, dest_ip, proto, data[header_length:]

# Get protocol name
def get_protocol(proto_num):
    if proto_num == 1:
        return 'ICMP'
    elif proto_num == 6:
        return 'TCP'
    elif proto_num == 17:
        return 'UDP'
    else:
        return f'Other ({proto_num})'

# Function to clear log file
def clear_log_file():
    open('packet_sniffer.log', 'w').close()
    logging.info("Log file cleared.")

# Main function to capture packets
def main(src_ip_filter, dest_ip_filter):
    logging.info("Starting packet sniffer...")
    
    # Create a raw socket and bind it to the public interface
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        logging.info("Socket created and bound to interface.")
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        print(f"Permission error: {e}")
        return
    except Exception as e:
        logging.error(f"Error creating socket: {e}")
        print(f"Error creating socket: {e}")
        return

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    packet_count = 0  # Initialize packet count

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)

            if eth_proto == 8:  # IPv4
                src_ip, dest_ip, proto, data = unpack_ipv4_packet(data)
                protocol = get_protocol(proto)

                if (not src_ip_filter or src_ip == src_ip_filter) and (not dest_ip_filter or dest_ip == dest_ip_filter):
                    payload_data = data[:20]  # Extract the first 20 bytes of payload data for logging

                    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    log_entry = (f"Timestamp: {timestamp}\n"
                                 f"Source MAC: {src_mac}\n"
                                 f"Destination MAC: {dest_mac}\n"
                                 f"Source IP: {src_ip}\n"
                                 f"Destination IP: {dest_ip}\n"
                                 f"Protocol: {protocol}\n"
                                 f"Payload Data: {payload_data}\n"
                                 "-" * 50)
                    print(log_entry)
                    logging.info(log_entry)
                    packet_count += 1

                    # Clear log file after capturing 100 packets
                    if packet_count >= 100:
                        clear_log_file()
                        packet_count = 0
            else:
                logging.debug(f"Non-IPv4 packet captured: Ethernet Protocol {eth_proto}")
    except KeyboardInterrupt:
        logging.info("Packet sniffer stopped by user.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
        print(f"Error during packet capture: {e}")
    finally:
        # Disable promiscuous mode
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        logging.info("Promiscuous mode disabled, exiting.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument('-s', '--src_ip', type=str, help="Source IP to filter")
    parser.add_argument('-d', '--dest_ip', type=str, help="Destination IP to filter")
    args = parser.parse_args()
    
    main(args.src_ip, args.dest_ip)
