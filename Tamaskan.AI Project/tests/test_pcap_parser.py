"""Unit tests for tamaskan_ai.core.pcap_parser.parse

Tests use unittest.mock to patch scapy.all.sniff so no real PCAP files are
needed on disk.

Validates: Requirements 2.2, 2.4, 2.5
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tamaskan_ai.core.pcap_parser import parse


# ---------------------------------------------------------------------------
# Helpers – build fake Scapy-like packet objects
# ---------------------------------------------------------------------------

def _make_ip_tcp_packet(src_ip: str, src_port: int,
                         dst_ip: str, dst_port: int,
                         timestamp: float, size: int) -> MagicMock:
    """Return a mock that behaves like a Scapy IP/TCP packet."""
    pkt = MagicMock()
    pkt.time = timestamp
    pkt.__len__ = MagicMock(return_value=size)

    # haslayer behaviour
    def _haslayer(layer):
        from scapy.all import IP, TCP, UDP
        if layer is IP:
            return True
        if layer is TCP:
            return True
        if layer is UDP:
            return False
        return False

    pkt.haslayer.side_effect = _haslayer

    # __getitem__ behaviour
    ip_layer = MagicMock()
    ip_layer.src = src_ip
    ip_layer.dst = dst_ip
    ip_layer.proto = 6  # TCP

    tcp_layer = MagicMock()
    tcp_layer.sport = src_port
    tcp_layer.dport = dst_port

    def _getitem(layer):
        from scapy.all import IP, TCP
        if layer is IP:
            return ip_layer
        if layer is TCP:
            return tcp_layer
        raise KeyError(layer)

    pkt.__getitem__ = MagicMock(side_effect=_getitem)
    return pkt


def _make_non_ip_packet(timestamp: float = 1.0, size: int = 60) -> MagicMock:
    """Return a mock that has no IP layer."""
    pkt = MagicMock()
    pkt.time = timestamp
    pkt.__len__ = MagicMock(return_value=size)
    pkt.haslayer.return_value = False
    return pkt


def _sniff_side_effect(packets):
    """Return a side_effect function for patching scapy.all.sniff."""
    def _sniff(offline, store, prn):
        for pkt in packets:
            prn(pkt)
    return _sniff


# ---------------------------------------------------------------------------
# Test 1 – bidirectional flow grouping (Req 2.2)
# ---------------------------------------------------------------------------

class TestBidirectionalFlowGrouping:
    """A→B and B→A packets must be merged into a single Flow."""

    def test_forward_and_reverse_merge_into_one_flow(self):
        """Two packets in opposite directions share the same flow key."""
        pkt_ab = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                     timestamp=1.0, size=100)
        pkt_ba = _make_ip_tcp_packet("10.0.0.2", 80, "10.0.0.1", 1234,
                                     timestamp=1.5, size=200)

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([pkt_ab, pkt_ba])):
            flows = parse("fake.pcap")

        assert len(flows) == 1, "Forward and reverse packets must form exactly one flow"
        flow = flows[0]
        assert flow.packets == 2
        assert flow.bytes_total == 300

    def test_two_distinct_flows_stay_separate(self):
        """Packets belonging to different conversations produce separate flows."""
        pkt1 = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                   timestamp=1.0, size=100)
        pkt2 = _make_ip_tcp_packet("192.168.1.1", 5000, "8.8.8.8", 443,
                                   timestamp=2.0, size=150)

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([pkt1, pkt2])):
            flows = parse("fake.pcap")

        assert len(flows) == 2, "Two distinct conversations must produce two flows"

    def test_three_packets_same_flow(self):
        """Multiple packets in both directions all land in one flow."""
        pkts = [
            _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80, 1.0, 60),
            _make_ip_tcp_packet("10.0.0.2", 80, "10.0.0.1", 1234, 1.1, 80),
            _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80, 1.2, 70),
        ]

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect(pkts)):
            flows = parse("fake.pcap")

        assert len(flows) == 1
        assert flows[0].packets == 3
        assert flows[0].bytes_total == 210


# ---------------------------------------------------------------------------
# Test 2 – minimum duration guard (Req 2.4)
# ---------------------------------------------------------------------------

class TestMinimumDurationGuard:
    """Single-packet flows must use 0.001 s as duration."""

    def test_single_packet_duration_is_0001(self):
        pkt = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                  timestamp=5.0, size=100)

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([pkt])):
            flows = parse("fake.pcap")

        assert len(flows) == 1
        assert flows[0].duration_s == pytest.approx(0.001)

    def test_single_packet_bytes_per_sec_uses_guard(self):
        """bytes_per_sec must be computed with the 0.001 s guard, not zero."""
        pkt = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                  timestamp=5.0, size=500)

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([pkt])):
            flows = parse("fake.pcap")

        flow = flows[0]
        expected_bps = 500 / 0.001
        assert flow.bytes_per_sec == pytest.approx(expected_bps)

    def test_two_packet_very_close_timestamps_uses_guard(self):
        """When two packets are < 0.001 s apart the guard still applies."""
        pkt1 = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                   timestamp=1.0000, size=100)
        pkt2 = _make_ip_tcp_packet("10.0.0.2", 80, "10.0.0.1", 1234,
                                   timestamp=1.0000001, size=100)  # 0.0000001 s apart

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([pkt1, pkt2])):
            flows = parse("fake.pcap")

        assert flows[0].duration_s == pytest.approx(0.001)

    def test_multi_packet_normal_duration_not_clamped(self):
        """Flows with duration > 0.001 s must keep their real duration."""
        pkt1 = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                   timestamp=0.0, size=100)
        pkt2 = _make_ip_tcp_packet("10.0.0.2", 80, "10.0.0.1", 1234,
                                   timestamp=2.0, size=100)

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([pkt1, pkt2])):
            flows = parse("fake.pcap")

        assert flows[0].duration_s == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Test 3 – ValueError when no IP packets present (Req 2.5)
# ---------------------------------------------------------------------------

class TestNoIPPacketsRaisesValueError:
    """parse() must raise ValueError when the capture has no IP packets."""

    def test_empty_capture_raises(self):
        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([])):
            with pytest.raises(ValueError, match="No IP flows found"):
                parse("fake.pcap")

    def test_only_non_ip_packets_raises(self):
        non_ip_pkts = [_make_non_ip_packet(t, 60) for t in [1.0, 2.0, 3.0]]

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect(non_ip_pkts)):
            with pytest.raises(ValueError, match="No IP flows found"):
                parse("fake.pcap")

    def test_mixed_non_ip_and_ip_does_not_raise(self):
        """At least one IP packet means no ValueError."""
        non_ip = _make_non_ip_packet(1.0, 60)
        ip_pkt = _make_ip_tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80,
                                     timestamp=2.0, size=100)

        with patch("scapy.all.sniff", side_effect=_sniff_side_effect([non_ip, ip_pkt])):
            flows = parse("fake.pcap")  # must not raise

        assert len(flows) == 1
