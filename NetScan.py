from scapy.all import ARP, Ether, srp
import time
import socket
import subprocess
import os
import tkinter as tk
from tkinter import ttk
import threading

# Global list to store detected devices and cache for vendors
devices = []
mac_vendor_cache = {}
# Attempts to get hostname using nameserver (reverse DNS)
def get_hostname(ip):
    """Attempt to resolve the hostname for the IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown Host"

# Attempts to retrieve vendor from MAC address using macvendors API
def get_vendor(mac):
    """Get the vendor name from the MAC address using macvendors.co API via curl."""
    if mac in mac_vendor_cache:
        return mac_vendor_cache[mac]
    
    stripedMacAddress = mac.replace(":", "").upper()
    macApiUrl = f"https://api.macvendors.com/{stripedMacAddress}"
    
    try:
        result = subprocess.run(["curl", "-s", macApiUrl], capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            vendor = result.stdout.strip()
            mac_vendor_cache[mac] = vendor
            return vendor
        else:
            return "Not Found"
    except subprocess.CalledProcessError:
        return "Error"

# scan network for new devices
def scan_network(network):
    """Scan the network and update the devices list."""
    global devices
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    result = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    for sent, received in result:
        mac_address = received.hwsrc
        ip_address = received.psrc

        if any(dev["MAC"] == mac_address for dev in devices):
            continue

        print(f"New Device Found: {ip_address} ({mac_address})")

        device = {
            "IP": ip_address,
            "MAC": mac_address,
            "Hostname": get_hostname(ip_address),
            "Vendor": get_vendor(mac_address)
        }
        devices.append(device)
        time.sleep(1)
        update_gui(device)
        generate_html()

    time.sleep(5)

# generates an html page with device scan results  
def generate_html():
    """Generate an HTML file with the scan results."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; }
        table { width: 80%; margin: auto; border-collapse: collapse; background: white; }
        th, td { padding: 10px; border: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <h2>Network Scan Results</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Hostname</th>
            <th>Vendor</th>
        </tr>
    """

    for device in devices:
        html_content += f"""
        <tr>
            <td>{device['IP']}</td>
            <td>{device['MAC']}</td>
            <td>{device['Hostname']}</td>
            <td>{device['Vendor']}</td>
        </tr>
        """

    html_content += """
    </table>
</body>
</html>
    """

    with open("scan_results.html", "w") as f:
        f.write(html_content)

# Updates GUI with new network devices
def update_gui(device):
    """Update the Tkinter application window with new device details."""
    tree.insert("", "end", values=(device["IP"], device["MAC"], device["Hostname"], device["Vendor"]))

# keeps scanning for new network devices
def scan_loop(network):
    """Continuously scan the network in a loop with rate-limiting."""
    while True:
        scan_network(network)
        time.sleep(1)

# Runs network scanning GUI 
def run_gui():
    """Initialize and run the Tkinter GUI."""
    global tree
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("800x400")

    tree = ttk.Treeview(root, columns=("IP", "MAC", "Hostname", "Vendor"), show="headings")
    tree.heading("IP", text="IP Address")
    tree.heading("MAC", text="MAC Address")
    tree.heading("Hostname", text="Hostname")
    tree.heading("Vendor", text="Vendor")
    tree.pack(fill="both", expand=True)

    scan_thread = threading.Thread(target=scan_loop, args=("192.168.4.0/24",), daemon=True)
    scan_thread.start()

    root.mainloop()

# main execution
def main():
    run_gui()

main()
