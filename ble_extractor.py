from scapy.all import rdpcap, Packet
import pandas as pd
import numpy as np
import os

def extract_packets_from_pcap(pcap_path, label=None):
    """
    Extract packet features from a BLE pcap file using scapy.
    Returns a list of dicts with keys: timestamp, info, length, delta, type (if label given).
    """
    packets = rdpcap(pcap_path)
    records = []
    prev_time = None

    for pkt in packets:
        try:
            # Use scapy's summary as a text description (similar to Wireshark Info)
            info = pkt.summary()
            length = len(pkt)
            ts = float(pkt.time)
            delta = 0.0 if prev_time is None else ts - prev_time
            prev_time = ts
            rec = {
                'timestamp': ts,
                'info': str(info),
                'length': length,
                'delta': delta
            }
            if label is not None:
                rec['type'] = label
            records.append(rec)
        except Exception as e:
            # skip corrupted packets
            continue
    return records