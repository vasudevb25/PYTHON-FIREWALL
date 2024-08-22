# Modules
import os #to interact with the os
import sys #handles system specific operations,e.g executing a script
import time #track time interval : to determine the transfer rates for packets
from collections import defaultdict #used to store and manage packet counts for each ip_addes
from scapy.all import sniff,IP #allows us to analyse network packets
import ctypes
import platform

# Specify the maximum packet load rate per second for an IP address
threshold = 1  # Change to 1 for testing purposes
print(f"THRESHOLD: {threshold} packets/sec")

# If root access is enabled in Windows
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# BLOCKING IP IN [WINDOWS/LINUX]
def block_ip(ip):
    """Blocks an IP address using the appropriate method for the platform."""
    if platform.system() == "Windows":
        # Windows Firewall block command (example, use PowerShell or netsh for precise rules)
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    else:
        # Linux: block the IP with iptables
        os.system(f"iptables -A INPUT -s {ip} -j DROP")

# Packet Callback
def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    # Check if a DoS attack is happening every 0.5 seconds
    if time_interval >= 0.5:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            '''print(f"IP: {ip}, Packet Rate: {packet_rate:.2f} packets/sec")'''
            if packet_rate > threshold and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, Packet Rate: {packet_rate:.2f}")
                block_ip(ip)
                blocked_ips.add(ip)

        # Keep the counts for slightly longer to catch fast spikes
        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    # Check for root/admin privileges
    if platform.system() == "Windows":
        if not is_admin():
            print("You need to run this script as an administrator.")
            exit(1)
    else:
        if os.geteuid() != 0:
            print("You need to run this script as root.")
            exit(1)
    
    # Initialize packet tracking data
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




'''In this project, I build a Python script designed to monitor network traffic and detect potential
 Denial of Service attacks by analyzing the rate at which IP packets are sent. 

If the rate exceeds a predefined threshold which we can set, then the script will block the 
IP address, mitigating the impact of the attack. 

In this script I'll also introduce you to the Scapy library, a powerful network manipulation tool,
 to sniff and analyze network packets.'''

'''
why root access is required beacuse:
    #1.To access raw network traffic
    #2.To modify systems firewall to block an ip
'''

