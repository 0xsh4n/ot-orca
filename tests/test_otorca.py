"""OT-ORCA test suite — runs without root or live capture (uses synthetic rows).

Covers the deterministic core: dissection, the rules engine, severity ordering,
report serialization and the AI fallback narrative.
"""

import os
import tempfile

import pytest

from otorca.core.inventory import Inventory
from otorca.core.models import Severity
from otorca.analysis import rules_engine, statistics
from otorca.core.capture import CaptureConfig, LiveCapture
from otorca.ai.analyst import deterministic_narrative


def feed(rows):
    inv = Inventory()
    for r in rows:
        inv.observe(r)
    return inv


MODBUS_WRITE = {
    "ts": "1", "len": "60", "protostack": "eth:ethertype:ip:tcp:mbtcp:modbus",
    "eth_src": "00:1b:1b:aa:bb:cc", "eth_dst": "00:0f:ab:11:22:33",
    "ip_src": "192.168.1.50", "ip_dst": "192.168.1.10", "tcp_dport": "502",
    "mb_func": "16", "mb_unit": "1",
}
S7_STOP = {
    "ts": "2", "protostack": "eth:ethertype:ip:tcp:tpkt:cotp:s7comm",
    "ip_src": "192.168.1.5", "ip_dst": "192.168.1.11", "tcp_dport": "102",
    "s7_rosctr": "1", "s7_func": "0x29",
}
EXTERNAL_MODBUS = {
    "ts": "3", "protostack": "eth:ethertype:ip:tcp:mbtcp:modbus",
    "ip_src": "45.133.1.9", "ip_dst": "192.168.1.10", "tcp_dport": "502",
    "mb_func": "6",
}


def test_modbus_write_detected():
    inv = feed([MODBUS_WRITE])
    findings = rules_engine.analyze(inv)
    ids = {f.rule_id for f in findings}
    assert "OTO-MODBUS-WRITE" in ids
    assert "OTO-PROTO-CLEARTEXT" in ids


def test_s7_stop_is_critical():
    inv = feed([S7_STOP])
    findings = rules_engine.analyze(inv)
    stop = [f for f in findings if f.rule_id == "OTO-S7-STOP"]
    assert stop and stop[0].severity == Severity.CRITICAL


def test_it_ot_crossing():
    inv = feed([MODBUS_WRITE, EXTERNAL_MODBUS])
    findings = rules_engine.analyze(inv)
    assert any(f.rule_id == "OTO-IT-OT-CROSSING" for f in findings)


def test_findings_sorted_by_severity():
    inv = feed([MODBUS_WRITE, S7_STOP, EXTERNAL_MODBUS])
    findings = rules_engine.analyze(inv)
    ranks = [int(f.severity) for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_arp_anomaly():
    rows = [
        {"ts": "1", "protostack": "eth:arp", "eth_src": "00:0f:ab:00:00:10",
         "arp_op": "2", "arp_src_ip": "192.168.1.10",
         "arp_src_mac": "00:0f:ab:00:00:10"},
        {"ts": "2", "protostack": "eth:arp", "eth_src": "de:ad:be:ef:00:10",
         "arp_op": "2", "arp_src_ip": "192.168.1.10",
         "arp_src_mac": "de:ad:be:ef:00:10"},
    ]
    inv = feed(rows)
    findings = rules_engine.analyze(inv)
    assert any(f.rule_id == "OTO-ARP-ANOMALY" for f in findings)


def test_goose_stnum_regression():
    rows = [
        {"ts": "1", "protostack": "eth:goose", "eth_src": "00:11:22:33:44:55",
         "goose_ref": "IED1$GO$g1", "goose_stnum": "7", "goose_sqnum": "1"},
        {"ts": "2", "protostack": "eth:goose", "eth_src": "00:11:22:33:44:55",
         "goose_ref": "IED1$GO$g1", "goose_stnum": "3", "goose_sqnum": "1"},
    ]
    inv = feed(rows)
    findings = rules_engine.analyze(inv)
    assert any(f.rule_id == "OTO-GOOSE-STNUM-REGRESS" for f in findings)


def test_broadcast_mac_not_an_asset():
    rows = [{"ts": "1", "protostack": "eth:arp",
             "eth_src": "00:0f:ab:00:00:10", "eth_dst": "ff:ff:ff:ff:ff:ff"}]
    inv = feed(rows)
    assert not any(a.key == "mac:ff:ff:ff:ff:ff:ff" for a in inv.assets.values())


def test_capture_command_build_is_passive():
    cfg = CaptureConfig(interface="eth0", duration=10)
    cmd = LiveCapture(cfg).build_command()
    assert "tshark" in cmd[0]
    assert "-i" in cmd and "eth0" in cmd
    assert "-T" in cmd and "fields" in cmd
    # passive: no injection flags, name resolution disabled
    assert "-n" in cmd


def test_statistics_overview():
    inv = feed([MODBUS_WRITE, S7_STOP])
    findings = rules_engine.analyze(inv)
    ov = statistics.overview(inv, findings)
    assert ov["summary"]["assets"] >= 2
    assert "protocol_distribution" in ov


def test_deterministic_narrative():
    inv = feed([MODBUS_WRITE, S7_STOP])
    findings = rules_engine.analyze(inv)

    class R:
        def to_dict(self):
            return {
                "meta": {"source": "test"},
                "summary": inv.summary(),
                "stats": statistics.overview(inv, findings),
                "findings": [f.to_dict() for f in findings],
            }
    text = deterministic_narrative(R())
    assert "## Executive Summary" in text
    assert "Remediation" in text


def test_report_roundtrip(tmp_path):
    from otorca.core.capture import CaptureConfig
    from otorca.core.session import ScanSession
    pcap = os.path.join(os.path.dirname(__file__), "..", "sample", "otdemo.pcap")
    if not os.path.isfile(pcap):
        pytest.skip("sample pcap not generated")
    s = ScanSession(CaptureConfig(pcap=pcap))
    s.run_blocking()
    result = s.build_result()
    from otorca import report
    j = report.write_json(result, str(tmp_path / "r.json"))
    m = report.write_markdown(result, str(tmp_path / "r.md"))
    assert os.path.getsize(j) > 0 and os.path.getsize(m) > 0
    assert len(result.findings) > 0
