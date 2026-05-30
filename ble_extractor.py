from scapy.all import rdpcap
import pyshark
import pandas as pd
import numpy as np

def extract_packets_from_pcap(pcap_path, label=None, tshark_path=r'C:\Program Files\Wireshark\tshark.exe'):
    """
    Extract packet features from a BLE pcap or BTSnoop file.
    Uses scapy first; falls back to pyshark if the format is unsupported.
    Prints progress every 1000 packets.
    """
    records = []
    prev_time = None

    # Try scapy first
    try:
        packets = rdpcap(pcap_path)
        total = len(packets)
        print(f"Total packets in file (scapy): {total}")
        for i, pkt in enumerate(packets):
            try:
                info = pkt.summary()
                length = len(pkt)
                ts = float(pkt.time)
                delta = 0.0 if prev_time is None else ts - prev_time
                prev_time = ts
                rec = {'timestamp': ts, 'info': str(info), 'length': length, 'delta': delta}
                if label is not None:
                    rec['type'] = label
                records.append(rec)
                if (i+1) % 1000 == 0 or (i+1) == total:
                    print(f"  Processed {i+1}/{total} packets...")
            except:
                continue
        return records
    except Exception as e:
        print(f"Scapy failed ({e}). Trying pyshark...")

    # Fallback to pyshark (works for BTSnoop logs and any format Wireshark understands)
    try:
        cap = pyshark.FileCapture(pcap_path, keep_packets=False, tshark_path=tshark_path)
        # pyshark doesn't give total upfront, so we just iterate
        total = 0
        for i, pkt in enumerate(cap):
            try:
                info = getattr(pkt, '_ws_col_Info', None) or getattr(pkt, 'info', None) or str(pkt)
                length = int(pkt.length)
                ts = float(getattr(pkt, 'sniff_timestamp', None) or getattr(pkt, 'sniff_time', 0))
                delta = 0.0 if prev_time is None else ts - prev_time
                prev_time = ts
                rec = {'timestamp': ts, 'info': str(info), 'length': length, 'delta': delta}
                if label is not None:
                    rec['type'] = label
                records.append(rec)
                total += 1
                if total % 1000 == 0:
                    print(f"  Processed {total} packets...")
            except:
                continue
        cap.close()
        print(f"Extracted {total} packets (pyshark)")
        return records
    except Exception as e2:
        print(f"pyshark also failed: {e2}")
        return []