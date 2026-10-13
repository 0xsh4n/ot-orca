#!/usr/bin/env python3
"""Generate a synthetic OT/ICS capture for demoing and testing OT-ORCA.

Crafts a small pcap containing a realistic mix of OT and IT-management traffic
so every major rule category has something to fire on:

  * Modbus/TCP write (func 16) from an HMI to a PLC
  * Modbus/TCP write from an *external* host (IT/OT boundary crossing)
  * EtherNet/IP session to a controller
  * Telnet, FTP creds, HTTP Basic auth, SNMP 'public', TFTP firmware pull
  * An ARP conflict (two MACs claim one IP)

This is purely offline test data — no traffic touches any network.

Usage:  python sample/make_sample_pcap.py sample/otdemo.pcap
"""
from __future__ import annotations

import sys

from scapy.all import (Ether, IP, TCP, UDP, ARP, Raw, wrpcap)
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
from scapy.all import ASN1_OID, ASN1_NULL


def modbus_tcp(src, dst, smac, dmac, trans, unit, pdu):
    mbap = (trans.to_bytes(2, "big") + b"\x00\x00" +
            (len(pdu) + 1).to_bytes(2, "big") + bytes([unit]))
    return (Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) /
            TCP(sport=50000 + trans, dport=502, flags="PA", seq=trans * 10) /
            Raw(load=mbap + pdu))


def main(out="sample/otdemo.pcap"):
    hmi, plc, plc2, hist, sw, ext = ("192.168.95.50", "192.168.95.10",
                                     "192.168.95.11", "192.168.95.20",
                                     "192.168.95.60", "45.133.1.9")
    m_hmi = "00:1b:1b:00:00:50"      # Siemens OUI
    m_plc = "00:0f:ab:00:00:10"      # Rockwell OUI
    m_plc2 = "00:0f:ab:00:00:11"
    m_sw = "00:1b:6d:00:00:60"       # Moxa OUI
    m_ext = "00:50:56:00:00:09"      # VMware OUI
    m_rogue = "de:ad:be:ef:00:10"

    pkts = []

    # Modbus write-multiple-registers (func 16) HMI -> PLC
    for i in range(6):
        pdu = b"\x10" + (0).to_bytes(2, "big") + (2).to_bytes(2, "big") + \
              b"\x04" + b"\x00\x01\x00\x02"
        pkts.append(modbus_tcp(hmi, plc, m_hmi, m_plc, 100 + i, 1, pdu))

    # Modbus read holding registers (func 3) — benign polling, periodic
    for i in range(10):
        pdu = b"\x03" + (0).to_bytes(2, "big") + (10).to_bytes(2, "big")
        pkts.append(modbus_tcp(hmi, plc2, m_hmi, m_plc2, 200 + i, 1, pdu))

    # Modbus write single register (func 6) from EXTERNAL host -> PLC  (crossing)
    pdu = b"\x06" + (5).to_bytes(2, "big") + (999).to_bytes(2, "big")
    pkts.append(modbus_tcp(ext, plc, m_ext, m_plc, 300, 1, pdu))

    # EtherNet/IP ListIdentity (cmd 0x63) HMI -> controller
    enip = (0x63).to_bytes(2, "little") + (0).to_bytes(2, "little") + \
           (0).to_bytes(4, "little") + (0).to_bytes(4, "little") + \
           b"\x00" * 8 + (0).to_bytes(4, "little")
    pkts.append(Ether(src=m_hmi, dst=m_plc) / IP(src=hmi, dst=plc) /
                TCP(sport=51000, dport=44818, flags="PA") / Raw(load=enip))

    # Telnet (cleartext) switch admin
    pkts.append(Ether(src=m_sw, dst=m_hmi) / IP(src=sw, dst=hmi) /
                TCP(sport=23, dport=52000, flags="PA") /
                Raw(load=b"\xff\xfd\x18Username: "))

    # FTP creds
    pkts.append(Ether(src=m_hmi, dst=m_plc2) / IP(src=hmi, dst=plc2) /
                TCP(sport=52100, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"))
    pkts.append(Ether(src=m_hmi, dst=m_plc2) / IP(src=hmi, dst=plc2) /
                TCP(sport=52100, dport=21, flags="PA") / Raw(load=b"PASS plc1234\r\n"))

    # HTTP Basic auth to device web UI  (user:pass -> dXNlcjpwYXNz)
    http = (b"GET /config HTTP/1.1\r\nHost: 192.168.95.20\r\n"
            b"Authorization: Basic dXNlcjpwYXNz\r\n\r\n")
    pkts.append(Ether(src=m_hmi, dst=m_sw) / IP(src=hmi, dst=hist) /
                TCP(sport=52200, dport=80, flags="PA") / Raw(load=http))

    # SNMP get with community 'public'
    snmp = SNMP(community="public",
                PDU=SNMPget(varbindlist=[SNMPvarbind(
                    oid=ASN1_OID("1.3.6.1.2.1.1.1.0"), value=ASN1_NULL(0))]))
    pkts.append(Ether(src=m_hmi, dst=m_sw) / IP(src=hmi, dst=sw) /
                UDP(sport=52300, dport=161) / snmp)

    # TFTP firmware read request
    pkts.append(Ether(src=m_hmi, dst=m_plc2) / IP(src=hmi, dst=plc2) /
                UDP(sport=52400, dport=69) /
                Raw(load=b"\x00\x01firmware.bin\x00octet\x00"))

    # ARP conflict: rogue MAC claims the PLC's IP (spoofing indicator)
    pkts.append(Ether(src=m_plc, dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=2, psrc=plc, hwsrc=m_plc, pdst=plc))
    pkts.append(Ether(src=m_rogue, dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=2, psrc=plc, hwsrc=m_rogue, pdst=plc))

    wrpcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample/otdemo.pcap")
