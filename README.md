## 🔎 NetworkScanner
NetworkScanner is a Python-based GUI tool for scanning devices on a local network. It detects IP addresses, MAC addresses, hostnames, and open ports of connected devices. The results can be saved to a CSV file for analysis.

## 🚀 Features
- 📡 Scan devices on a specified IP range or subnet using ARP.

- 🔐 Identify open TCP ports (22–443) using Nmap.

- 🧠 Detect device hostnames via reverse DNS lookup.

- 🖥️ Clean and interactive Tkinter GUI interface.

- 💾 Export scan results to a CSV file.

- 🧪 UDP scan function included (optional).

## 🖼️ GUI Preview

(Replace this with your own screenshot)

## 🛠️ Installation
## Prerequisites:
- Python 3.x

- pip

## Required Libraries:
Install required dependencies using pip:

[bash]
- pip install scapy python-nmap

Also ensure:

- nmap is installed on your system (e.g., sudo apt install nmap for Linux).

## 🧪 How to Use
1. Run the script:

[bash]

python projectscanner.py

2. Enter the Target IP/Subnet, e.g. 192.168.1.0/24.

3. Click Start Scan.

4. View results in the table:

- IP Address

- MAC Address

- Hostname

- Open Ports

5. Click Save Results to export as .csv.

## 📜 License
This project is for educational purposes. Feel free to modify or extend it!
