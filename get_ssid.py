import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from pprint import pprint
import time

def scan_wifi_networks(interface='wlan0', scan_time=5, channels=[1,6,11]):
  networks = []
  start_time = time.time()
  packet_count = 0

  def packet_handler(pkt):
      nonlocal packet_count
      packet_count += 1
    
      if pkt.haslayer(Dot11Beacon):
          try:
              ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
              bssid = pkt[Dot11].addr2
    
              # Get channel from DS Parameter Set (element ID 3)
              channel = None
              elt = pkt[Dot11Elt]
              while elt and isinstance(elt, Dot11Elt):
                if elt.ID == 3 and len(elt.info) > 0:  # DS Parameter Set
                    channel = ord(elt.info)
                    break
                elt = elt.payload if hasattr(elt, 'payload') else None

                # Get signal strength from RadioTap header
                signal_strength = None
                if pkt.haslayer(RadioTap):
                    # Try different RadioTap signal strength fields
                    if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                        signal_strength = pkt[RadioTap].dBm_AntSignal
                    elif hasattr(pkt[RadioTap], 'Antenna_signal'):
                        signal_strength = pkt[RadioTap].Antenna_signal
                    elif hasattr(pkt, 'dBm_AntSignal'):
                        signal_strength = pkt.dBm_AntSignal

              if ssid != '' and ssid.isprintable() and len(ssid.strip()) > 0:
                  networks.append((ssid, bssid, channel, signal_strength))
    
          except Exception as e:
              print(f"Error decoding beacon: {e}")

  for channel in channels:
      print(f"Scanning channel {channel}...")

      # Change to specific channel
      subprocess.run(['sudo', 'iwconfig', interface, 'channel', str(channel)],
                    capture_output=True)

      # Your existing packet handler code here...
      sniff(iface=interface, prn=packet_handler, timeout=scan_time/len(channels))

  # Print discovered networks
  unique_networks_set = list(set(networks))
  unique_networks = []
  for i in unique_networks_set:
    unique_networks.append({'ssid':i[0], 'bssid':i[1], 'channel':i[2], 'strength':i[3]})

  return {'non_unique': networks, 'unique': unique_networks}

'''
# %%timeit -r 1 -n 1
scan_wifi_networks(scan_time=3)['unique']

[('ssid', 'xx:xx:c2:xx:54:xx', 6, -36),
 ('ssid2', 'xx:xx:67:xx:70:57', 3, -26),
 ('ssid3', 'xx:xx:e0:xx:7d:3c', 6, -50)]
'''