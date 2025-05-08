# pip install scapy
# pip install mac-vendor-lookup

from scapy.all import ARP, Ether, srp
from datetime import datetime
import time
import socket
import csv
from concurrent.futures import ProcessPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup

# Time
start = time.perf_counter()
curDT = datetime.now()
date_time = curDT.strftime("%m/%d/%Y, %H:%M:%S")

# Vars
count = 0
mac_lookup = MacLookup()
mac_lookup.update_vendors()

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

def resolve_device(device):
    ip_addr = device['ip']
    mac_addr = device['mac']
    hostname = get_hostname(ip_addr)
    vendor = get_vendor(mac_addr)
    return {
        'ip': ip_addr,
        'hostname': hostname,
        'mac': mac_addr,
        'vendor': vendor
    }

# Scan
def scan(network):
    global count
    print(f"Scanning {network}...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]

    if not devices:
        print("No devices found")
        return

    print(f"\n{'IP':<16} {'Hostname':<32} {'MAC':<18} {'Vendor':<32}")
    print("-" * 90)

# Multiprocessing
    rows = []
    with ProcessPoolExecutor() as executor:
        future_to_device = {executor.submit(resolve_device, d): d for d in devices}
        for future in as_completed(future_to_device):
            item = future.result()
            print(f"{item['ip']:<16} {item['hostname']:<32} {item['mac']:<18} {item['vendor']:<32}")
            rows.append(item)
            count += 1

# CSV
    with open('csvfile.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor'])
        for item in rows:
            writer.writerow([item['ip'], item['hostname'], item['mac'], item['vendor']])

# Final
if __name__ == "__main__":
    network = input(f"Enter network to scan (ex: 192.168.1.0/24): ").strip()
    scan(network)
    end = time.perf_counter()
    print('\r\nNumber of IP:{}\r\nFinished in {} second(s)\r\n'.format(count, round(end-start,2)))
