# pip install scapy
# pip install mac-vendor-lookup

from scapy.all import ARP, Ether, srp
from datetime import datetime
import time
import socket
import csv
from mac_vendor_lookup import MacLookup

# Time
start = time.perf_counter()
curDT = datetime.now()
day = curDT.strftime("%d")
month = curDT.strftime("%m")
year = curDT.strftime("%Y")
date_time = curDT.strftime("%m/%d/%Y, %H:%M:%S")

# Vars
count = 0
mac_lookup = MacLookup()
#mac_lookup.update_vendors()

# OUI
def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown"

# Hostname
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "No Name"
    return hostname

# Scan
def scan(network):
    """Scan a network for MAC"""
    print(f"Scanning {network}...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    global count
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    if devices:
        print(f"\n{'IP':<16} {'Hostname':<32} {'MAC':<18} {'Vendor':<32}")
        print("-" * 90)
        for device in devices:
            ip_addr = device['ip']
            mac_addr = device['mac']
            hostname = get_hostname(device['ip'])
            vendor = get_vendor(device['mac'])
            print(f"{ip_addr:<16} {hostname:<32} {mac_addr:<18} {vendor:<32}")
            count += 1
    else:
        print("No devices found")

# CSV
    with open('csvfile.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor'])
        for item in devices:
            writer.writerow([ip_addr, hostname, mac_addr, vendor])

# Final
if __name__ == "__main__":
    network = input(f"Enter network to scan (ex: 192.168.1.0/24): ").strip()
    scan(network)
    end = time.perf_counter()
    print('\r\nNumber of IP:' + str(count) + f'\r\nFinished in {round(end-start,2)} second(s)\r\n')
