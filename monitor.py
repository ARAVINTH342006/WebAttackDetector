from scapy.all import sniff, IP, TCP, conf
import time
import numpy as np
from collections import defaultdict
import threading

from model_logic import classify_warning

conf.use_pcap = True
conf.use_npcap = True

LOOPBACK_IFACE = r"\Device\NPF_Loopback"


last_packet_time = time.time()

flow_stats = defaultdict(lambda: {
    'start': time.time(),
    'pkts': 0,
    'bytes': 0,
    'sizes': [],
    'syn': 0,
    'fin': 0,
    'rst': 0,
    'src_pkts': 0,
    'dst_pkts': 0
})


def packet_handler(pkt):
    global last_packet_time
    last_packet_time = time.time()

    if IP not in pkt or TCP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport

    
    if not (
        (sport == 5000 or dport == 5000) and
        (src_ip == "127.0.0.1" or dst_ip == "127.0.0.1")
    ):
        return

    key = (src_ip, sport)
    stats = flow_stats[key]

    stats['pkts'] += 1
    pkt_size = len(pkt)
    stats['bytes'] += pkt_size
    stats['sizes'].append(pkt_size)

    flags = pkt[TCP].flags
    stats['syn'] += int(flags & 0x02 != 0)
    stats['fin'] += int(flags & 0x01 != 0)
    stats['rst'] += int(flags & 0x04 != 0)

    if src_ip == "127.0.0.1":
        stats['src_pkts'] += 1
    else:
        stats['dst_pkts'] += 1



def monitor_flows():
    global flow_stats

    while True:
        time.sleep(1)
        now = time.time()

        
        if now - last_packet_time >= 1.0:
            features = {
                'flow_duration': 1.0,
                'Rate': 0.0,
                'Srate': 0.0,
                'Drate': 0.0,
                'Protocol Type': 6,
                'Header_Length': 20,
                'syn_flag_number': 0,
                'fin_flag_number': 0,
                'rst_flag_number': 0,
                'Tot size': 0,
                'Std': 0.0,
                'Variance': 0.0
            }

            
            if now - last_packet_time >= 1.0:
                print("[IDLE] No traffic | P=0.00 | **NORMAL**")
                continue


        
        for key in list(flow_stats.keys()):
            stats = flow_stats[key]
            duration = now - stats['start']

            if duration >= 1.0:
                rate = stats['pkts'] / duration
                srate = stats['src_pkts'] / duration
                drate = stats['dst_pkts'] / duration

                sizes = np.array(stats['sizes'])
                std = sizes.std() if len(sizes) > 1 else 0.0
                var = sizes.var() if len(sizes) > 1 else 0.0

                features = {
                    'flow_duration': duration,
                    'Rate': rate,
                    'Srate': srate,
                    'Drate': drate,
                    'Protocol Type': 6,
                    'Header_Length': 20,
                    'syn_flag_number': stats['syn'],
                    'fin_flag_number': stats['fin'],
                    'rst_flag_number': stats['rst'],
                    'Tot size': stats['bytes'],
                    'Std': std,
                    'Variance': var
                }

                label, prob = classify_warning(features)

                print(
                    f"{key} | Rate={rate:.1f}/s | "
                    f"SYN={stats['syn']} | "
                    f"P={prob:.2f} | **{label}**"
                )

                del flow_stats[key]




print("====================================")
print(" LIVE IDS – XGBoost (localhost:5000)")
print("====================================")
print("curl → Normal | Locust → DoS")
print("Interface:", LOOPBACK_IFACE)
print("------------------------------------")


threading.Thread(target=monitor_flows, daemon=True).start()

sniff(
    iface=LOOPBACK_IFACE,
    filter="tcp port 5000",
    prn=packet_handler,
    store=0
)
