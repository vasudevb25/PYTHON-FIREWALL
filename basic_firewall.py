# Modules
import os # to interact with the os
import sys # handles system specific operations,e.g executing a script
import time # track time interval : to determine the transfer rates for packets
from collections import defaultdict # used to store and manage packet counts for each ip_addes
from scapy.all import sniff,IP,TCP # allows us to analyse network packets
import ctypes
import platform

# Specify the maximum packet load rate per second for an IP address
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD} packets/sec")

# File paths for whitelist and blacklist
WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"

# Read IPs from a file
def read_ip_file(filename):
    if not os.path.exists(filename): # if file does not exist
        return set()
    
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips) # set, cause it doesn't have duplicates

# Write an IP address to a file
def write_ip_to_file(filename, ip):
    with open(filename, "a") as file:
        file.write(f"{ip}\n")

# NIMDA fn :used to check nimda worm signature
def is_nimda_worm(packet):
    # check if the packet has a TCP LAYER & the destination port=80[http]
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        # Convert payload to a string and check for different variants of Nimda-like signatures
        payload_str = str(payload).lower()
        if "get /scripts/root.exe" in payload_str or "get /msadc/root.exe" in payload_str or "get /c/winnt/system32/cmd.exe" in payload_str:
            return True
    return False


# Log events to a file
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

# Block IP based on OS
def block_ip(ip):
    if platform.system() == "Windows":
        # Windows command to block IP using netsh
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    else:
        # Linux command to block IP using iptables
        os.system(f"iptables -A INPUT -s {ip} -j DROP")

# Check if the script is run as an administrator on Windows
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Packet Callback
def packet_callback(packet):
    src_ip = packet[IP].src

    # Check if IP is in the whitelist
    if src_ip in whitelist_ips:
        return

    # Check if IP is in the blacklist
    if src_ip in blacklist_ips:
        block_ip(src_ip)
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return
    
    # Check for Nimda worm signature
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        block_ip(src_ip)
        log_event(f"Blocking Nimda source IP: {src_ip}")
        if src_ip not in blacklist_ips:
            write_ip_to_file(BLACKLIST_FILE, src_ip)  # Add the IP to the blacklist file
            blacklist_ips.add(src_ip)  # Add to the set to avoid re-blocking
        return

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    # Check if a DoS attack is happening every t seconds
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            '''print(f"IP: {ip}, Packet Rate: {packet_rate:.2f} packets/sec")'''
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                block_ip(ip)
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)
                if ip not in blacklist_ips:
                    write_ip_to_file(BLACKLIST_FILE, ip)  # Add to the blacklist file

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    # Check for root/admin privileges
    if platform.system() == "Windows":
        if not is_admin():
            print("You need to run this script as an administrator.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("This script requires root privileges.")
            sys.exit(1)

    # Import whitelist and blacklist IPs
    whitelist_ips = read_ip_file(WHITELIST_FILE)
    blacklist_ips = read_ip_file(BLACKLIST_FILE)

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    # Start sniffing packets and analyzing them
    try:
        sniff(filter="ip", prn=packet_callback)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")


'''
In this final project, I have added new commits along with DoS Blocker and
 added 3 more important firewall functions:
1. White- + Blacklist
2. Signature Detection
3. Logging
'''