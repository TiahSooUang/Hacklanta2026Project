from __future__ import annotations

from collections import defaultdict
from typing import Callable

from tamaskan_ai.models import Flow


def parse(pcap_path: str, progress_cb: Callable[[int], None] | None = None) -> list[Flow]:
    """Parse a PCAP file and return a list of bidirectional Flow objects.

    Args:
        pcap_path: Path to the .pcap / .pcapng file.
        progress_cb: Optional callback invoked every 1000 packets with the
                     running packet count.

    Returns:
        List of Flow dataclass instances with computed statistics.

    Raises:
        ValueError: If no IP packets are found in the file.
    """
    from scapy.all import sniff, IP, TCP, UDP  # local import keeps startup fast

    # flow_key -> {"timestamps": [], "sizes": []}
    flow_data: dict[str, dict] = defaultdict(lambda: {"timestamps": [], "sizes": []})
    n_packets = 0
    ip_packets = 0

    def _process(pkt):
        nonlocal n_packets, ip_packets

        n_packets += 1
        if progress_cb is not None and n_packets % 1000 == 0:
            progress_cb(n_packets)

        if not pkt.haslayer(IP):
            return

        ip_packets += 1
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = str(ip.proto)

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            src_port = 0
            dst_port = 0

        # Bidirectional key: sort the two endpoint strings so A→B and B→A map to the same flow
        endpoints = sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])
        flow_key = "|".join(endpoints + [proto])

        pkt_size = len(pkt)
        pkt_time = float(pkt.time)

        flow_data[flow_key]["timestamps"].append(pkt_time)
        flow_data[flow_key]["sizes"].append(pkt_size)

    sniff(offline=pcap_path, store=0, prn=_process)

    if ip_packets == 0:
        raise ValueError("No IP flows found in this file.")

    flows: list[Flow] = []
    for flow_key, data in flow_data.items():
        timestamps = data["timestamps"]
        sizes = data["sizes"]

        packet_count = len(timestamps)
        total_bytes = sum(sizes)
        avg_packet_size = total_bytes / packet_count

        if packet_count == 1:
            duration_s = 0.001  # guard against division by zero
        else:
            duration_s = max(timestamps) - min(timestamps)
            if duration_s < 0.001:
                duration_s = 0.001

        bytes_per_sec = total_bytes / duration_s
        pkts_per_sec = packet_count / duration_s

        flows.append(
            Flow(
                flow_id=flow_key,
                packets=packet_count,
                bytes_total=total_bytes,
                duration_s=duration_s,
                bytes_per_sec=bytes_per_sec,
                pkts_per_sec=pkts_per_sec,
                avg_packet_size=avg_packet_size,
            )
        )

    return flows
