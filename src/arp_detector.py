import logging
import nmap
import netifaces
from scapy.all import sniff, ARP
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_manager import load_emails
import threading

logging.basicConfig(filename='logs/arp_spoofing_detector.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ip_mac_map = {}

default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
ip_address = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]['addr']
subnet_mask = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]['netmask']
ip_address_parts = ip_address.split('.')
subnet_mask_parts = subnet_mask.split('.')
network_address = '.'.join(str(int(ip_address_parts[i]) & int(subnet_mask_parts[i])) for i in range(4))
cidr_notation = sum(bin(int(x)).count('1') for x in subnet_mask_parts)

stop_sniff_event = threading.Event()

def update_ip_mac_map():
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=f'{network_address}/{cidr_notation}', arguments='-sS -O')
        
        for host in nm.all_hosts():
            if 'mac' in nm[host]['addresses']:
                ip_mac_map[host] = nm[host]['addresses']['mac'].lower()

    except nmap.PortScannerError as e:
        logging.error(f"Nmap scan error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in updating ip_mac_map with Nmap: {str(e)}")

update_ip_mac_map()

def scan_arp():
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=f'{network_address}/{cidr_notation}', arguments='-sS -O')
        
    except nmap.PortScannerError as e:
        logging.error(f"Nmap scan error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in updating ip_mac_map with Nmap: {str(e)}")

def set_interval(func, sec):
    def wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, wrapper)
    t.start()
    return t

interval = set_interval(scan_arp, 30)

def send_email_alert(sender, receivers, subject, body):
    sender_email = 'your_email'  # Change to your Gmail email address
    sender_password = 'your_key_passwd'  # Change to your Gmail password
    print(1)
    message = MIMEMultipart()
    message['From'] = sender
    message['To'] = ', '.join(receivers)
    message['Subject'] = subject
    print(2)
    message.attach(MIMEText(body, 'plain'))
    print(3)

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    text = message.as_string()
    print(4)
    server.sendmail(sender, receivers, text)
    print(5)
    server.quit()
    logging.info('Email alert sent.')

def send_email_alert_in_thread(sender, receivers, subject, body):
    email_thread = threading.Thread(target=send_email_alert, args=(sender, receivers, subject, body))
    email_thread.start()

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        if sender_ip in ip_mac_map:
            if ip_mac_map[sender_ip] != sender_mac:
                alert_message = f"{sender_ip} : {ip_mac_map[sender_ip].upper()} may spoofed {sender_mac.upper()}"
                logging.warning(alert_message)
                recipients = load_emails()
                send_email_alert_in_thread('your_email@gmail.com', recipients, "ARP Spoofing Detected", alert_message)
                ip_mac_map[sender_ip] = sender_mac
        else:
            ip_mac_map[sender_ip] = sender_mac
            print(f"New ARP entry: {sender_ip} - {sender_mac}")  # Print for debugging

def start_sniffing():
    sniff(prn=detect_arp_spoof, filter="arp", store=0, stop_filter=lambda x: stop_sniff_event.is_set())

def stop_sniffing():
    # Cancel the interval timer and set the stop event
    stop_sniff_event.set()
    interval.cancel()
    exit()
