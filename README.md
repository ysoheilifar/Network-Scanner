# Network Scanner with MAC Vendor Lookup
This Python script scans a given local network, detects active devices, and displays important details for each device, including:

- IP Address
- Hostname
- MAC Address
- Device Vendor (Manufacturer)

The script uses the scapy library for low-level network scanning, and mac-vendor-lookup for finding the hardware manufacturer based on MAC address. Device information is also saved to a CSV file for later reference.

Two versions are included:
- Scan_Vendor.py : Single-process version
- Scan_Vendor_MultiProc.py : Multiprocessing (parallel) version
Both scripts save results to a CSV file and print device details in a table.

> Multiprocessing
> - A faster version using Python’s multiprocessing (ProcessPoolExecutor) to resolve hostnames and vendors in parallel for all detected devices, greatly improving speed on larger networks.
> - Hostname and vendor lookup are performed in parallel (multiprocessing).

### How It Works
1. Scan the Network
The script sends ARP requests to the specified network range to discover connected devices. For each device that responds, it collects the IP and MAC addresses.

2. Hostname Resolution
It tries to resolve each IP address to its hostname using a reverse DNS lookup. If not possible, it marks the device as unnamed.

3. Vendor Lookup
Using the MAC address, it identifies the manufacturer (vendor) of each device.

4. Output
Results are printed in a table and saved into a CSV file called csvfile.csv.

### Usage
1. Install Requirements:
```python
pip install scapy mac-vendor-lookup
```
2. Run the Script:
- Single-process version
```python
python Scan_Vendor.py
```
- Multiprocessing (parallel) version
```python
python Scan_Vendor_MultiProc.py
```
3. Enter network range:

E.g., 192.168.1.0/24
Results will be printed and saved.

### General Notes
- You may need administrator/root access to send ARP requests.
- Both scripts are for educational, IT, and troubleshooting purposes.
- For best results, use them in local networks with manageable device counts.

> [!CAUTION]
> - ARP will not find devices outside your own subnet
> - ARP requests are local only (layer 2: broadcast, not routable).
> - Even if you give Scapy a range outside your subnet, you will receive “no devices found.”

### Summary Table

| Method | Same subnet? | Remote subnet? | MAC/Vendor? | Requirements|
---------|--------------|----------------|-------------|-------------|
Direct ARP scan (Scapy)	| ✅	 | ❌ | ✅ | Your device on target subnet|
Agent/script on remote subnet | ✅	| ✅ | ✅ | Script running remotely|
Router ARP/SNMP table | ✅ | ✅ | ✅ | Router access|
DHCP server lease list | ✅ | ✅ | ✅ | DHCP server management|
Nmap/ICMP port scan | ✅ | ✅ | ❌ |
