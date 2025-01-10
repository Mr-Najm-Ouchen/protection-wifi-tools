from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap 
import os
import sys
import ctypes
import smtplib
from email.mime.text import MIMEText

# Function to send an email alert
def send_alert(message):
    try:
        from_addr = "your_email@example.com"
        to_addr = "admin_email@example.com"
        msg = MIMEText(message)
        msg['Subject'] = "Network Intrusion Alert"
        msg['From'] = from_addr
        msg['To'] = to_addr

        # Set up the server and send the email
        server = smtplib.SMTP('smtp.example.com', 587)
        server.starttls()
        server.login("your_email@example.com", "your_password")
        server.sendmail(from_addr, to_addr, msg.as_string())
        server.quit()
        print(f"[INFO] Alert sent to {to_addr}")
    except Exception as e:
        print(f"[ERROR] Failed to send alert: {e}")

# Function to detect suspicious activity on the network
def packet_callback(packet):
    try:
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 4:  # Probe Request frame
                print(f"[ALERT] Probe request detected from {packet.addr2}")
                send_alert(f"Suspicious probe request detected from {packet.addr2}")

            if packet.type == 2:  # Data frame
                print(f"[INFO] Data frame detected: {packet.addr1} -> {packet.addr2}")
                
                # Detect possible attack (e.g., deauthentication attack)
                if packet.addr1 == "00:00:00:00:00:00":  # Example address for attack
                    print("[ALERT] Possible deauthentication attack detected.")
                    send_alert("Possible deauthentication attack detected.")
                    stop_attack(packet.addr2)
                    counter_attack(packet.addr2)
    except Exception as e:
        print(f"[ERROR] {e}")

# Function to stop an attack by deauthenticating the attacker
def stop_attack(attacker_mac):
    print(f"[INFO] Stopping attack from {attacker_mac}")
    deauth_packet = RadioTap() / Dot11(addr1=attacker_mac, addr2=attacker_mac, addr3=attacker_mac) / Dot11Deauth()
    sendp(deauth_packet, iface="wlan0", count=10)

# Function to send counter-attacks (fake deauthentication packets to the attacker)
def counter_attack(attacker_mac):
    print(f"[INFO] Sending counter-attack to {attacker_mac}")
    fake_packet = RadioTap() / Dot11(addr1=attacker_mac, addr2="FF:FF:FF:FF:FF:FF", addr3=attacker_mac) / Dot11Deauth()
    sendp(fake_packet, iface="wlan0", count=100)

# Check if the script is running as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Main function
def main():
    if not is_admin():
        print("[ERROR] Please run this script as administrator.")
        sys.exit(1)

    interface = input("Enter the network interface to monitor (e.g., Wi-Fi): ")

    print("[INFO] Starting packet capture. Press Ctrl+C to stop.")

    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping packet capture.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()


#created by NAJM DINE OUCHENE 