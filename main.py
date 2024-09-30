import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("T- Network Packet Analyzer")
        self.root.geometry("900x700")
        self.root.configure(bg="#0f0f0f")  # Dark background

        # Terminal-like title label
        self.title_label = tk.Label(self.root, text="T-PACKET ANALYZER", font=("Terminal", 20, "bold"), fg="#00FF00", bg="#0f0f0f")
        self.title_label.pack(pady=10)

        # Hacker style buttons with neon effect
        self.start_button = tk.Button(self.root, text="Start Capturing", font=("Terminal", 12, "bold"), command=self.start_sniffing, bg="#006400", fg="#00FF00", activebackground="#004d00")
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Capturing", font=("Terminal", 12, "bold"), command=self.stop_sniffing, bg="#8B0000", fg="#FF6347", state="disabled", activebackground="#660000")
        self.stop_button.pack(pady=10)

        self.save_button = tk.Button(self.root, text="Save Packets", font=("Terminal", 12, "bold"), command=self.save_packets, bg="#00008B", fg="#1E90FF", state="disabled", activebackground="#000066")
        self.save_button.pack(pady=10)

        self.new_section_button = tk.Button(self.root, text="Start New Section", font=("Terminal", 12, "bold"), command=self.start_new_section, bg="#FFD700", fg="#000", activebackground="#ccac00")
        self.new_section_button.pack(pady=10)

        # Packet display with terminal font and neon colors
        self.packet_display = scrolledtext.ScrolledText(self.root, width=110, height=30, bg="#0a0a0a", fg="#00FF00", wrap="word", font=("Terminal", 10), insertbackground="white")
        self.packet_display.pack(pady=10)

        # Status label with neon colors
        self.status_label = tk.Label(self.root, text="Status: Waiting to Start", font=("Terminal", 12), fg="#00FF00", bg="#0f0f0f")
        self.status_label.pack(pady=10)

        self.capturing = False
        self.packets = []

    def start_sniffing(self):
        self.capturing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.save_button.config(state="disabled")
        self.status_label.config(text="Status: Capturing...", fg="#FFD700")
        self.packet_display.insert(tk.END, "Packet capture started...\n")
        self.packet_display.see(tk.END)

        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.capturing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.save_button.config(state="normal")
        self.status_label.config(text="Status: Capture Stopped", fg="#FF6347")
        self.packet_display.insert(tk.END, "Packet capture stopped.\n")
        self.packet_display.see(tk.END)

    def save_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as f:
                for packet in self.packets:
                    f.write(f"{packet}\n")
            messagebox.showinfo("Saved", "Packets have been saved successfully.")

    def start_new_section(self):
        self.packets = []
        self.packet_display.delete(1.0, tk.END)
        self.packet_display.insert(tk.END, "Starting new section...\n")
        self.packet_display.see(tk.END)

    def sniff_packets(self):
        sniff(prn=self.analyze_packet, stop_filter=self.stop_filter)

    def stop_filter(self, packet):
        return not self.capturing

    def analyze_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                protocol = "Other"
                src_port = None
                dst_port = None

            packet_info = f"Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}"
            if src_port and dst_port:
                packet_info += f" | Source Port: {src_port} | Destination Port: {dst_port}"

            self.packet_display.insert(tk.END, f"{packet_info}\n", "info")
            self.packet_display.see(tk.END)

            self.packets.append(packet_info)

def main():
    root = tk.Tk()
    app = PacketAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
