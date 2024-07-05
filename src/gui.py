import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
from src.email_manager import load_emails, save_emails
from src.arp_detector import start_sniffing, stop_sniffing, ip_mac_map
import re

class ARPDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ARP Spoofing Detector")
        self.geometry("1000x400")

        self.create_widgets()

    def create_widgets(self):
        # Navigation bar
        self.navbar = tk.Frame(self, bg="lightgray")
        self.navbar.pack(side="top", fill="x")

        self.arp_table_button = tk.Button(self.navbar, text="ARP Table", command=self.show_arp_table)
        self.arp_table_button.pack(side="left", fill="x", expand=True)

        self.log_table_button = tk.Button(self.navbar, text="Logs", command=self.show_log_table)
        self.log_table_button.pack(side="left", fill="x", expand=True)

        self.email_list_button = tk.Button(self.navbar, text="Email List", command=self.show_email_list)
        self.email_list_button.pack(side="left", fill="x", expand=True)

        # Main content frames
        self.arp_frame = ttk.Frame(self)
        self.log_frame = ttk.Frame(self)
        self.email_frame = ttk.Frame(self)

        self.create_arp_table(self.arp_frame)
        self.create_log_table(self.log_frame)
        self.create_email_list(self.email_frame)

        self.show_arp_table()

        # Bind window closing event to a method
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.refresh()

    def show_arp_table(self):
        self.arp_frame.pack(fill="both", expand=True)
        self.log_frame.pack_forget()
        self.email_frame.pack_forget()

    def show_log_table(self):
        self.arp_frame.pack_forget()
        self.log_frame.pack(fill="both", expand=True)
        self.email_frame.pack_forget()

    def show_email_list(self):
        self.arp_frame.pack_forget()
        self.log_frame.pack_forget()
        self.email_frame.pack(fill="both", expand=True)

    def create_arp_table(self, parent):
        self.arp_table_label = tk.Label(parent, text="ARP Table", font=("Helvetica", 16))
        self.arp_table_label.pack(pady=10)

        columns = ('IP Address', 'MAC Address')
        self.arp_table = ttk.Treeview(parent, columns=columns, show='headings', height=10)
        self.arp_table.heading('IP Address', text='IP Address')
        self.arp_table.heading('MAC Address', text='MAC Address')
        self.arp_table.column('IP Address', anchor=tk.CENTER, width=200)
        self.arp_table.column('MAC Address', anchor=tk.CENTER, width=200)
        self.arp_table.pack(pady=10)

    def create_log_table(self, parent):
        self.log_table_label = tk.Label(parent, text="Logs", font=("Helvetica", 16))
        self.log_table_label.pack(pady=10)

        log_columns = ('Time', 'Log Level', 'Action')
        self.log_table = ttk.Treeview(parent, columns=log_columns, show='headings', height=10)
        self.log_table.heading('Time', text='Time')
        self.log_table.heading('Log Level', text='Log Level')
        self.log_table.heading('Action', text='Action')
        self.log_table.column('Time', anchor=tk.CENTER, width=200)
        self.log_table.column('Log Level', anchor=tk.CENTER, width=100)
        self.log_table.column('Action', anchor=tk.CENTER, width=600)
        self.log_table.pack(pady=10)

    def create_email_list(self, parent):
        self.email_list_label = tk.Label(parent, text="Email List", font=("Helvetica", 16))
        self.email_list_label.pack(pady=10)
        self.email_list = tk.Listbox(parent, width=40, height=10, justify="center")
        self.email_list.pack(pady=10)

        self.add_email_button = tk.Button(parent, text="Add Email", command=self.add_email)
        self.add_email_button.pack(pady=5)
        self.remove_email_button = tk.Button(parent, text="Remove Email", command=self.remove_email)
        self.remove_email_button.pack(pady=5)

    def on_closing(self):
        stop_sniffing()
        self.destroy()

    def refresh(self):
        self.refresh_arp_table()
        self.refresh_log_table()
        self.refresh_email_list()
        self.after(10000, self.refresh)

    def refresh_arp_table(self):
        for row in self.arp_table.get_children():
            self.arp_table.delete(row)
        for ip, mac in ip_mac_map.items():
            self.arp_table.insert('', tk.END, values=(ip, mac.upper()))

    def refresh_log_table(self):
        for row in self.log_table.get_children():
            self.log_table.delete(row)
        with open('logs/arp_spoofing_detector.log', 'r') as log_file:
            logs = log_file.readlines()
            for line in logs[::-1]:
                try:
                    time, level_action = line.split(' - ', 1)
                    level, action = level_action.split(' - ', 1)
                    self.log_table.insert('', tk.END, values=(time, level, action.strip()))
                except ValueError:
                    continue

    def refresh_email_list(self):
        emails = load_emails()
        self.email_list.delete(0, tk.END)
        for email in emails:
            self.email_list.insert(tk.END, email)

    def add_email(self):
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        email = simpledialog.askstring("Input", "Enter email:")
        if email:
            if re.match(email_pattern, email):
                emails = load_emails()
                if email not in emails:
                    emails.append(email)
                    save_emails(emails)
                    self.refresh_email_list()
                else:
                    messagebox.showinfo("Info", "Email already exists.")
            else:
                messagebox.showwarning("Info", "Invalid email address.")

    def remove_email(self):
        selected_email = self.email_list.get(tk.ACTIVE)
        if selected_email:
            emails = load_emails()
            if selected_email in emails:
                emails.remove(selected_email)
                save_emails(emails)
                self.refresh_email_list()
            else:
                messagebox.showinfo("Info", "Email not found.")

app = None
sniff_thread = None

def main():
    global app
    app = ARPDetectorApp()

    global sniff_thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    app.mainloop()

if __name__ == "__main__":
    main()
