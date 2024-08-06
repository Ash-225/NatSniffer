import tkinter as tk
from tkinter import *
from tkinter import ttk, Menu
import socket
import struct
import textwrap
import threading

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")
        self.root.geometry("1024x900")
        self.packet_count = 0

        self.apply_dark_theme()
        self.create_menu()
        self.create_display_filter()
        self.create_packet_display()
        self.create_data_grid()

        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def apply_dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        small_font = ('TkDefaultFont', 9)

        style.configure("TFrame", background="#2e2e2e")
        style.configure("TLabel", background="#2e2e2e", foreground="#ffffff", font=small_font)
        style.configure("TEntry", background="#3e3e3e", foreground="#ffffff", font=small_font)
        style.configure("TButton", background="#3e3e3e", foreground="#ffffff", font=small_font)
        style.configure("TMenu", background="#2e2e2e", foreground="#ffffff", activebackground="#3e3e3e", activeforeground="#ffffff")
        style.configure("Treeview", 
                        background="#3e3e3e", 
                        foreground="#ffffff", 
                        fieldbackground="#3e3e3e", 
                        font=small_font)
        style.configure("Treeview.Heading", 
                        background="#2e2e2e", 
                        foreground="#ffffff", 
                        font=small_font)
        style.configure("Treeview", rowheight=20)

        self.root.configure(background="#2e2e2e")
        self.root.option_add("*Menu.Font", small_font)

    def create_menu(self):
        menubar = Menu(self.root, background="#2e2e2e", foreground="#ffffff", activebackground="#3e3e3e", activeforeground="#ffffff")
        
        file_menu = Menu(menubar, tearoff=0, background="#2e2e2e", foreground="#ffffff", activebackground="#3e3e3e", activeforeground="#ffffff")
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        self.root.config(menu=menubar)

    def open_file(self):
        pass

    def create_packet_display(self):
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")

        packet_frame = ttk.Frame(self.root)
        packet_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.packet_tree.yview)

        for col in columns:
            self.packet_tree.heading(col, text=col, anchor=tk.W)
        
        self.packet_tree.column("No.", width=70, stretch=tk.NO)
        self.packet_tree.column("Time", width=70, stretch=tk.NO)
        self.packet_tree.column("Source", width=150, stretch=tk.NO)
        self.packet_tree.column("Destination", width=150, stretch=tk.NO)
        self.packet_tree.column("Protocol", width=80, stretch=tk.NO)
        self.packet_tree.column("Length", width=70, stretch=tk.NO)
        self.packet_tree.column("Info", width=300, stretch=tk.YES)

    def create_display_filter(self):
        filter_frame = ttk.Frame(self.root)
        filter_frame.pack(side=tk.TOP, fill=tk.X)

        filter_label = ttk.Label(filter_frame, text="Apply a display filter:")
        filter_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.filter_entry = ttk.Entry(filter_frame)
        self.filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5, pady=5)

    def create_data_grid(self):
        data_frame = ttk.Frame(self.root)
        data_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        data_columns = ("Field", "Value")
        
        data_scrollbar = ttk.Scrollbar(data_frame, orient=tk.VERTICAL)
        data_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.data_tree = ttk.Treeview(data_frame, columns=data_columns, show="headings", yscrollcommand=data_scrollbar.set)
        self.data_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        data_scrollbar.config(command=self.data_tree.yview)

        for col in data_columns:
            self.data_tree.heading(col, text=col, anchor=tk.W)
        
        self.data_tree.column("Field", width=150, stretch=tk.NO)
        self.data_tree.column("Value", width=500, stretch=tk.YES)

    def capture_packets(self):
        con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        while True:
            raw_data, addr = con.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
            
            self.packet_count += 1
            protocol = "Unknown"
            length = len(raw_data)
            info = data[:9999].hex()

            if eth_proto == 8:
                version, header_length, ttl, proto, src, target, data = self.ipv4_packet(data)
                if proto == 1:
                    protocol = "ICMP"
                elif proto == 6:
                    protocol = "TCP"
                    src_port, dest_port, sequence , acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syc, flag_fin, data = self.tcp_sag(data)
                    info = f'Sequence: {sequence}, acknowledgemrnt: {acknowledgement}, URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syc}, FIN: {flag_fin}'
                elif proto == 17:
                    protocol = "UDP"
                    src_port, dest_port, size , data = self.udp_seg(data)
                    info = f'Source Port: {src_port} , Destination Port: {dest_port}, Length: {size}, Data: {data}'
                elif proto == 53:
                    protocol = "DNS"
                    info = self.dns_packet(data)
                elif proto == 80:
                    protocol = "HTTP"
                    info = self.http_packet(data)
            elif eth_proto == 1544:
                protocol = "ARP"
                info = self.arp_packet(data)
                    
            self.root.after(0, self.add_packet_to_display, self.packet_count, "", src_mac, dest_mac, protocol, length, info, raw_data)

    def add_packet_to_display(self, no, time, source, destination, protocol, length, info, raw_data):
        item_id = self.packet_tree.insert("", "end", values=(no, time, source, destination, protocol, length, info))
        self.packet_tree.tag_bind(item_id, "<<TreeviewSelect>>", lambda event, data=raw_data: self.display_packet_data(data))

    def display_packet_data(self, data):
        self.data_tree.delete(*self.data_tree.get_children())

        hex_data = data.hex()
        wrapped_hex_data = textwrap.wrap(hex_data, 32)
        for i, line in enumerate(wrapped_hex_data):
            self.data_tree.insert("", "end", values=(f"Offset {i * 16:04x}", line))

        # Display Ethernet frame details
        dest_mac, src_mac, eth_proto, ip_data = self.ethernet_frame(data)
        self.data_tree.insert("", "end", values=("Ethernet", ""))
        self.data_tree.insert("", "end", values=("  Destination MAC", dest_mac))
        self.data_tree.insert("", "end", values=("  Source MAC", src_mac))
        self.data_tree.insert("", "end", values=("  Protocol", hex(eth_proto)))

        # Display IP details if it's an IP packet
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, transport_data = self.ipv4_packet(ip_data)
            self.data_tree.insert("", "end", values=("IPv4", ""))
            self.data_tree.insert("", "end", values=("  Version", version))
            self.data_tree.insert("", "end", values=("  Header Length", header_length))
            self.data_tree.insert("", "end", values=("  TTL", ttl))
            self.data_tree.insert("", "end", values=("  Protocol", proto))
            self.data_tree.insert("", "end", values=("  Source IP", src))
            self.data_tree.insert("", "end", values=("  Destination IP", target))

            if proto == 17:
                src_port , dest_port, size, data = self.udp_seg(transport_data)
                self.data_tree.insert("", "end", values=("UDP", ""))
                self.data_tree.insert("", "end", values=("  Source Port", src_port))
                self.data_tree.insert("", "end", values=("  Destination Port", dest_port))
                self.data_tree.insert("", "end", values=("  Length", size))

        # Display ARP details if it's an ARP packet
        elif eth_proto == 1544:
            arp_info = self.arp_packet(ip_data)
            self.data_tree.insert("", "end", values=("ARP", arp_info))

    def udp_seg(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
    
    def tcp_sag(self, data):
        (src_port, dest_port, sequence , acknowledgement, offset_resserved_flags) = struct.unpack('! H H L L H' ,data[:14])
        offeset = (offset_resserved_flags >> 12) * 4
        flag_urg = (offset_resserved_flags & 32) >> 5
        flag_ack = (offset_resserved_flags & 16) >> 4
        flag_psh = (offset_resserved_flags & 8) >> 3
        flag_rst = (offset_resserved_flags & 4) >> 2
        flag_syc = (offset_resserved_flags & 2) >> 1
        flag_fin = (offset_resserved_flags & 2)

        return src_port, dest_port, sequence , acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syc, flag_fin, data[offeset:]


    def icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def arp_packet(self, data):
        htype, ptype, hlen, plen, operation, sha, spa, tha, tpa = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
        return {
            'hardware_type': htype,
            'protocol_type': ptype,
            'hardware_size': hlen,
            'protocol_size': plen,
            'operation': operation,
            'sender_hardware_address': self.get_mac_addr(sha),
            'sender_protocol_address': self.ipv4(spa),
            'target_hardware_address': self.get_mac_addr(tha),
            'target_protocol_address': self.ipv4(tpa)
        }

    def dns_packet(self, data):
        pass  # Implement DNS packet parsing here

    def http_packet(self, data):
        try:
            http_data = data.decode('utf-8')
            request_line, headers_alone = http_data.split('\r\n', 1)
            headers = headers_alone.split('\r\n')
            method, url, version = request_line.split()
            return f'HTTP Packet: {method} {url} {version}, Headers: {headers}'
        except Exception as e:
            return f"HTTP Packet: Error parsing HTTP data - {str(e)}"

root = tk.Tk()
app = PacketAnalyzerApp(root)
root.mainloop()
