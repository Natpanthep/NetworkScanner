from scapy.all import ARP, Ether, srp
import nmap#สแกนหาpost
import socket #หาชื่อhost
import tkinter as tk #สร้างgui
from tkinter import filedialog, messagebox, ttk
import csv#บันทึกผลลัพท์เป็นไฟล์csv
import time#ใช้ในการคำนวนเวลา


def scan_network(subnet):#ทำหน้าที่สแกน ช่วงip ที่ต้องการสแกน
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp # รวมแพ็กเก็ต ARP กับ Ethernet
    result = srp(packet, timeout=2, verbose=0)[0] # ส่งแพ็กเก็ตและรับคำตอบ
    clients = []

    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]  # ดึง Hostname  ของ IP 
        except socket.herror:
            hostname = "Unknown"  
        clients.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": hostname
        })

    return clients


def scan_with_nmap(ip):#สแกนพอร์ตที่เปิด
    nm = nmap.PortScanner()
    open_ports = []
    try:
        nm.scan(ip, arguments='-T4 --min-parallelism 100 -p 22-443')
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols(): #loopโปรโตคอล
                lport = nm[ip][proto].keys()     #loop port
                for port in lport:
                    state = nm[ip][proto][port]['state'] # ดูสถานะพอร์ต
                    service = nm[ip][proto][port]['name'] # ชื่อพอร์ตนั้น
                    if state == 'open':
                        open_ports.append(f"{port}({service})")
    except Exception as e:
        messagebox.showerror("Nmap Error", f"Error scanning with Nmap: {e}")
    return open_ports


def save_results_to_file(clients): # ให้ผู้ใช้เลือกตำแหน่งไฟล์
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if not file_path:
        return
    with open(file_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Hostname", "MAC Address", "Open Ports"])
        for client in clients:
            ip = client["ip"]
            mac = client["mac"]
            hostname = client.get("hostname", "Unknown")
            open_ports = ", ".join(client.get("open_ports", []))
            writer.writerow([ip, hostname, mac, open_ports])
    messagebox.showinfo("Success", f"Results saved to {file_path}")

def udp_scan(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sU -T4')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")


def start_scan(): # รับ subnet ที่input
    subnet = ip_entry.get()
    if not subnet:
        messagebox.showerror("Input Error", "Please enter a target IP or subnet.")
        return

    results_table.delete(*results_table.get_children()) # clear ตาราง
    progress_label.config(text="Scanning network...") # อัปเดต GUI
    root.update_idletasks()

    start_time = time.time() # บันทึกเวลาเริ่ม
    clients = scan_network(subnet) # สแกนเครือข่าย
    total_clients = len(clients)
    elapsed_times = []

    for i, client in enumerate(clients, 1):
        client_start_time = time.time()

        client["open_ports"] = scan_with_nmap(client["ip"]) # สแกนพอร์ต
        open_ports = ", ".join(client["open_ports"])

        
        results_table.insert("", "end", values=(client["ip"], client["mac"], client["hostname"], open_ports))

      
        elapsed_time = time.time() - client_start_time
        elapsed_times.append(elapsed_time)
        avg_time = sum(elapsed_times) / len(elapsed_times)
        remaining_time = avg_time * (total_clients - i)
        eta_minutes, eta_seconds = divmod(remaining_time, 60)

        # Update progress label
        progress_label.config(text=f"Scanning: {i}/{total_clients} | ETA: {int(eta_minutes)}m {int(eta_seconds)}s")
        root.update_idletasks()

    total_time = time.time() - start_time
    total_minutes, total_seconds = divmod(total_time, 60)
    progress_label.config(text=f"Scan complete in {int(total_minutes)}m {int(total_seconds)}s")
    messagebox.showinfo("Scan Complete", f"Found {len(clients)} devices on the network.")


# GUI 
root = tk.Tk()
root.title("Network Scanner")

# Input 
input_frame = ttk.Frame(root, padding=10) # กรอบ
input_frame.grid(row=0, column=0, sticky="ew") #แถว 0 คอลัมน์ 0

ttk.Label(input_frame, text="Target IP/Subnet:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
ip_entry = ttk.Entry(input_frame, width=30)  # ช่องใส่ subnet 
ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
scan_button = ttk.Button(input_frame, text="Start Scan", command=start_scan) # ปุ่ม
scan_button.grid(row=0, column=2, padx=5, pady=5)

# Results 
results_frame = ttk.Frame(root, padding=10) # กรอบ
results_frame.grid(row=1, column=0, sticky="nsew") #แถว 1 คอลัมน์ 0

columns = ("IP Address", "MAC Address", "Hostname", "Open Ports") # กำหนดคอลัมน์
results_table = ttk.Treeview(results_frame, columns=columns, show="headings", height=10)
for col in columns:
    results_table.heading(col, text=col) #หัวคอลัมน์
    results_table.column(col, width=150, anchor="center") # กำหนดความกว้าง
results_table.pack(fill="both", expand=True) # ขยายพื้นที่

# Progress 
progress_label = ttk.Label(root, text="") #เริ่มเป็นช่องว่าง
progress_label.grid(row=2, column=0, pady=5)

# Save
save_button = ttk.Button(root, text="Save Results", command=lambda: save_results_to_file([results_table.item(child)["values"] for child in results_table.get_children()]))
save_button.grid(row=3, column=0, pady=10)

# Adjust window resizing
root.columnconfigure(0, weight=1)
root.rowconfigure(1, weight=1)

root.mainloop() #คำสั้งเริ่ม GUI