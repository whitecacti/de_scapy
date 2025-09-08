# DEScapy

A data engineering project to capture, log & triangulate AP signals.


## Scapy packet description
RadioTap / Dot11FCS / Dot11Beacon / SSID='xyz' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltCountry / Dot11Elt / Dot11Elt / Dot11EltERP / Dot11EltRates / Dot11EltRSN / Dot11Elt / Dot11Elt / Dot11EltHTCapabilities / Dot11Elt / Dot11EltOBSS / Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11Elt / Dot11EltVendorSpecific

RadioTap is the physical layer of a packet
    # Contain metadata about radio transmission (signal strength, channel, rate, etc.)
    # Not part of the actual 802.11 frame, but added by the wireless adapter
    # Essential for understanding the physical layer characteristics
    signal = pkt[RadioTap].dBm_AntSignal  # Signal strength
    channel = pkt[RadioTap].Channel       # Channel frequency
    antenna = pkt[RadioTap].Antenna       # Antenna number
