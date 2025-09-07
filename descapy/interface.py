from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from descapy.common import get_curr_time, setup_logger
import subprocess

logger = setup_logger(__name__)  # This will show 'file2' in logs

class InterfaceDE:
    '''Interface class

    Inputs:
    - interface: the id of the interface
    - scan_time: how long to run each wifi scan for
    - channels: which channels to scan for
        - [1,6,11] - most common 2.4ghz channels
    '''
    def __init__(
        self
        , interface: str = 'wlan0'
        , scan_time: int = 10
        , channels: list = [1,6,11]
    ):
        self.interface = interface
        self.scan_time = scan_time
        self.channels = channels
        self.networks = dict()
        self.networks_list = list()
    
    def scan(self
        , scan_time: int = 10
        , channels: list = [1,6,11]):
        '''
        Running the scan will clear all prior scans in the class
        '''
        self.scan_time = scan_time
        self.channels = channels
        packet_count = 0
        self.networks = dict()

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
                        self.networks_list.append((ssid, bssid, channel, signal_strength, get_curr_time()))
                        if bssid in self.networks:
                            self.networks[bssid]['channel'].add(channel)
                            self.networks[bssid]['strength'].add(signal_strength)
                            self.networks[bssid]['scan_end'] = get_curr_time()
                        else:
                            channel_set = set()
                            channel_set.add(channel)
                            signal_strength_set = set()
                            signal_strength_set.add(signal_strength)
                            self.networks[bssid] = {
                                'ssid': ssid
                                , 'channel': channel_set
                                , 'strength': signal_strength_set
                                , 'scan_start': get_curr_time()
                                , 'scan_end': get_curr_time()
                            }
                
                except Exception as e:
                    logger.error(f"Error decoding beacon: {e}")

        for channel in channels:
            logger.info(f"Scanning channel {channel}...")

            # Change to specific channel
            subprocess.run(['sudo', 'iwconfig', self.interface, 'channel', str(channel)],
                            capture_output=True)

            # Your existing packet handler code here...
            sniff(iface=self.interface, prn=packet_handler, timeout=scan_time/len(channels))

        return self.networks