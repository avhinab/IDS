from scapy.all import *
import sys
import subprocess
import time
from collections import defaultdict, deque

arp_table = {}
# Log of packets for ddos detection
packet_log = defaultdict(deque)
# Blacklisted IPs
blacklist = set()
# Set of IPs potentially initating DDoS attack
potential_ddos = {}

# Example values for traffic threshold in certain window
THRESHOLD = 100
WINDOW = 5
# Cooldown for how often warnings are sent out
WARNING_COOLDOWN = 5

def check_arp(pkt):
  """
    Checks if MAC address of device sending packet already exists in
    ARP table, corresponding to a different IP. If so raises error for
    likely APR spoofing.
  """
  if pkt.haslayer(ARP):
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
    old_mac = arp_table.get(ip)
    if old_mac and old_mac != mac:
      print(f'[!] Potential ARP spoofing: {ip} shared by {mac} and {old_mac}')
    arp_table[ip] = mac

def check_ddos(pkt):
  """
    Checks if an IP is sending excessive number of packets in {WINDOW}
    and alerts.
  """
  if pkt.haslayer(IP):
    ip = pkt[IP].src
    now = time.time()
    timestamps = packet_log[ip]

    timestamps.append(now)

    # Remove old packets from timestamps
    while timestamps and now - timestamps[0] > WINDOW:
      timestamps.popleft()

    # If packets sent exceeds threshold alert
    if len(timestamps) > THRESHOLD and ip not in potential_ddos:
      print(f'[!] Potential DoS: {ip} has exceeded {THRESHOLD} packets in {WINDOW} seconds')
      potential_ddos[ip] = now
    elif ip in potential_ddos and now - potential_ddos[ip] > WARNING_COOLDOWN:
      del potential_ddos[ip]

def check_blacklist(pkt):
  # Alert if IP is sent from blacklisted IP
  if pkt.haslayer(IP):
    ip = pkt[IP].src
    if ip in blacklist:
      print(f'[!] Blacklisted IP detected: {ip}')

def process(pkt):
  check_arp(pkt)
  check_ddos(pkt)
  check_blacklist(pkt)

def clear_arp():
  # Clear ARP table so all IPs need to re-establish MAC pairing
  try:
    subprocess.run('sudo ip -s -s neigh flush all'.split(), check=True, stdout=subprocess.DEVNULL)
  except subprocess.CalledProcessError as e:
    print(f'Error clearing ARP table: {e}')

  print('ARP table cleared')

def build_blacklist():
  # Build blacklisted IPs from blacklist.txt file
  try:
    with open("blacklist.txt", "r") as f:
      for ip in f:
        blacklist.add(ip.rstrip())
  except FileNotFoundError:
    print(f"[!] Warning: blacklist.txt not found. No IPs will be blocked.")

def main():
  if len(sys.argv) < 2:
    print('Usage: sniffer.py <iface>')
    sys.exit(1)

  iface = sys.argv[1]

  clear_arp()
  build_blacklist()

  # Start sniffer on network {iface}, processing each packet
  print(f'IDS starting- analysing packets on interface: {iface}')
  sniff(iface=iface, prn=process, store=False)

if __name__=="__main__":
  main()