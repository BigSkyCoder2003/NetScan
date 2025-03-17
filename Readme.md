# NetScan

NetScan is a network scanning tool built with Python and Scapy. It scans a specified network range, identifies devices, and displays key information such as IP address, MAC address, hostname, and vendor. the vendor is retrieved using the the [Macvendors API](https://macvendors.com/api).

## Features

- **ARP-based Network Discovery**: Scans for devices within a specified IP range.
- **Vendor Identification**: Fetches vendor details using the macvendors API.
- **Real-time Updates**: Continuously scans and updates the GUI with newly discovered devices.
- **HTML Report Generation**: Outputs the scan results in an HTML table.
- **Tkinter GUI**: Provides a simple, interactive interface to view network scan results.

## Requirements

- Python 3.x
- Scapy (`pip install scapy`)
- Tkinter (pre-installed with Python in most distributions)
- Curl (for macvendors API requests)

## Installation

1. Clone or download the repository.
2. Install the required Python package:
   ```bash
   pip install scapy
