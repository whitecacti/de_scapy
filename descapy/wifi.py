from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from descapy.common import get_curr_time, setup_logger
from descapy.interface import InterfaceDE
import subprocess

logger = setup_logger(__name__)  # This will show 'file2' in logs

class WiFiDE:
    def __init__(
        self
        , interface: str = 'wlan0'
        , ap_bssid: str = 'ff:ff:ff:ff:ff:ff'
        , channel: int = 1
    ):
        self.interface = InterfaceDE(interface=interface, channels=[channel])
        self.ap_bssid = ap_bssid
        self.channel = channel

        # this class will contain the packets for everything, but then filter it down
        self.all_packets_scan = []
        self.devices = []

    def scan_for_devices(self, scan_time: int = 5):
        '''
        Return all the devices connected to an AP
        '''
        self.all_packets_scan = []
        self.all_packets_scan = self.interface.scan_for_pkts(scan_time=scan_time, channels = [self.channel])

        unique_bssid = {}
        for i in self.all_packets_scan:
            addr3 = i[Dot11].addr3
            if addr3:
                if addr3 not in unique_bssid:
                    unique_bssid[addr3] = {'count': 0, 'reciever': {}, 'transmitter': {}}

                unique_bssid[addr3]['count'] += 1

                if i[Dot11].addr1:
                    addr1 = i[Dot11].addr1
                    if addr1 != 'ff:ff:ff:ff:ff:ff' and addr1 != self.ap_bssid:
                        unique_bssid[addr3]['reciever'][addr1] = \
                            unique_bssid[addr3]['reciever'].get(addr1, 0) + 1

                if i[Dot11].addr2:
                    addr2 = i[Dot11].addr2
                    if addr2 != 'ff:ff:ff:ff:ff:ff' and addr2 != self.ap_bssid:
                        unique_bssid[addr3]['transmitter'][addr2] = \
                            unique_bssid[addr3]['transmitter'].get(addr2, 0) + 1
       
        self.all_devices = unique_bssid
        try:
            self.devices = unique_bssid[self.ap_bssid]
            return self.devices
        except:
            raise Exception('bssid not found')
