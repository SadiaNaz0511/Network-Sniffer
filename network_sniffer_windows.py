import logging
from scapy.all import sniff, TCP, UDP, ICMP
from scapy.error import Scapy_Exception

# Configure logging to log to both the console and a file
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Create a file handler
file_handler = logging.FileHandler('network_sniffer.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Add the file handler to the logger
logger.addHandler(file_handler)

def packet_callback(packet):
    try:
        if packet.haslayer(TCP):
            logger.info(f"TCP Packet: {packet.summary()}")
        elif packet.haslayer(UDP):
            logger.info(f"UDP Packet: {packet.summary()}")
        elif packet.haslayer(ICMP):
            logger.info(f"ICMP Packet: {packet.summary()}")
        else:
            logger.info(f"Other Packet: {packet.summary()}")
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def start_sniffing(interface):
    try:
        logger.info(f"Starting the network sniffer on interface: {interface}...")
        sniff(prn=packet_callback, store=0, iface=interface)
    except PermissionError:
        logger.error("Permission denied. Try running the script with elevated privileges (e.g., using sudo).")
    except Scapy_Exception as e:
        logger.error(f"Scapy error: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff on (e.g., eth0, WiFi, Tun0, All): ").strip()
    if interface.lower() == 'all':
        interface = None  # Sniff on all interfaces
    start_sniffing(interface)
