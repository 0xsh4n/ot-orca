"""Protocol dissection dispatcher.

Each packet row (a dict of short-alias -> string from ``capture.py``) is handed
to :func:`dissect`, which enriches the relevant :class:`Asset` objects and emits
:class:`ProtocolEvent` objects for anything a rule might care about.

Dissectors are intentionally small and table-driven (see :mod:`tables`). They
never raise on malformed input — a passive scanner must survive whatever is on
the wire — so every field access is defensive.
"""

from __future__ import annotations

from typing import Callable, Optional

from . import tables as T
from ..core.models import ProtocolEvent


def _int(val: str, base: int = 10) -> Optional[int]:
    """Parse a possibly-multi-valued tshark field ('3', '0x05', '3,4')."""
    if not val:
        return None
    first = val.split(",")[0].strip()
    if not first:
        return None
    try:
        if first.lower().startswith("0x"):
            return int(first, 16)
        return int(first, base)
    except ValueError:
        try:
            return int(first, 16)
        except ValueError:
            return None


def _emit(events, ts, proto, kind, row, summary, **data) -> None:
    events.append(ProtocolEvent(
        ts=ts, protocol=proto, kind=kind,
        src=row.get("ip_src") or row.get("eth_src"),
        dst=row.get("ip_dst") or row.get("eth_dst"),
        dport=_int(row.get("tcp_dport", "")) or _int(row.get("udp_dport", "")),
        summary=summary, data=data,
    ))


# --- individual protocol dissectors -----------------------------------------
def d_modbus(row, ts, inv, events) -> None:
    func = _int(row.get("mb_func", ""))
    if func is None:
        return
    name = T.MODBUS_FUNC.get(func, f"Func {func}")
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="modbus", role_hint="plc", port=502, proto_tcp=True)
    inv.tag_asset(src, protocol="modbus", role_hint="scada")
    inv.flow(src, dst, "modbus", 502, func=name)
    if row.get("mb_exc"):
        _emit(events, ts, "modbus", "modbus.exception", row,
              f"Modbus exception {row['mb_exc']} on {name}")
    if func in T.MODBUS_WRITE:
        _emit(events, ts, "modbus", "modbus.write", row,
              f"Modbus {name} (write) -> {dst} unit {row.get('mb_unit','?')}",
              func=func, func_name=name)
    if func in T.MODBUS_PROGRAM:
        _emit(events, ts, "modbus", "modbus.program", row,
              f"Modbus {name} (diagnostic/programming) -> {dst}",
              func=func, func_name=name)


def d_dnp3(row, ts, inv, events) -> None:
    af = _int(row.get("dnp3_alfunc", ""))
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="dnp3", role_hint="rtu", port=20000, proto_tcp=True)
    inv.tag_asset(src, protocol="dnp3", role_hint="scada")
    inv.flow(src, dst, "dnp3", 20000)
    if af is None:
        return
    name = T.DNP3_AL_FUNC.get(af, f"AL func {af}")
    if af in T.DNP3_DANGEROUS:
        _emit(events, ts, "dnp3", "dnp3.dangerous", row,
              f"DNP3 {T.DNP3_DANGEROUS[af]} -> {dst}", func=af, func_name=name)
    elif af in T.DNP3_WRITE:
        _emit(events, ts, "dnp3", "dnp3.write", row,
              f"DNP3 {name} (control/write) -> {dst}", func=af, func_name=name)


def d_s7(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    if row.get("s7_rosctr") or row.get("cotp_type"):
        inv.tag_asset(dst, protocol="s7comm", role_hint="plc", port=102, proto_tcp=True)
        inv.tag_asset(src, protocol="s7comm", role_hint="engineering")
        inv.flow(src, dst, "s7comm", 102)
    func = _int(row.get("s7_func", ""))
    if func is None:
        return
    name = T.S7_FUNC.get(func, f"Func 0x{func:02x}")
    if func in T.S7_STOP:
        _emit(events, ts, "s7comm", "s7.stop", row, f"S7 PLC STOP -> {dst}")
    elif func in T.S7_PROGRAM:
        _emit(events, ts, "s7comm", "s7.program", row,
              f"S7 {name} (block up/download / program) -> {dst}", func_name=name)
    elif func in T.S7_WRITE:
        _emit(events, ts, "s7comm", "s7.write", row, f"S7 Write Var -> {dst}")


def d_enip_cip(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="enip", role_hint="plc", port=44818, proto_tcp=True)
    inv.flow(src, dst, "enip", 44818)
    # Identity disclosure via ListIdentity response
    vendor = row.get("enip_vendor") or row.get("cip_vendor")
    product = row.get("enip_name") or row.get("cip_product")
    serial = row.get("enip_serial") or row.get("cip_serial")
    if product or serial:
        inv.tag_asset(dst, vendor=vendor, product=product, serial=serial)
        _emit(events, ts, "enip", "enip.identity", row,
              f"EtherNet/IP identity disclosed by {dst}: "
              f"{product or '?'} (vendor {vendor or '?'}, s/n {serial or '?'})",
              product=product, vendor=vendor, serial=serial)
    svc = _int(row.get("cip_service", "")) or _int(row.get("cip_sc", ""))
    if svc is None:
        return
    svc &= 0x7F  # strip response bit
    name = T.CIP_SERVICE.get(svc, f"Service 0x{svc:02x}")
    if svc in T.CIP_DANGEROUS:
        _emit(events, ts, "enip", "cip.dangerous", row,
              f"CIP {T.CIP_DANGEROUS[svc]} -> {dst}", svc_name=name)
    elif svc in T.CIP_WRITE:
        _emit(events, ts, "enip", "cip.write", row,
              f"CIP {name} (write) -> {dst}", svc_name=name)


def d_iec104(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="iec60870_104", role_hint="rtu", port=2404, proto_tcp=True)
    inv.tag_asset(src, protocol="iec60870_104", role_hint="scada")
    inv.flow(src, dst, "iec104", 2404)
    tid = _int(row.get("iec104_typeid", ""))
    if tid is None:
        return
    name = T.IEC104_TYPEID.get(tid, f"TypeID {tid}")
    if tid in T.IEC104_DANGEROUS:
        _emit(events, ts, "iec104", "iec104.dangerous", row,
              f"IEC-104 {T.IEC104_DANGEROUS[tid]} -> {dst}", type_name=name)
    elif tid in T.IEC104_CONTROL:
        _emit(events, ts, "iec104", "iec104.control", row,
              f"IEC-104 {name} (command/setpoint) -> {dst}", type_name=name)


def d_bacnet(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(src, protocol="bacnet", role_hint="bas", port=47808, proto_udp=True)
    if row.get("bac_objname"):
        inv.tag_asset(src, product=row.get("bac_objname"))
    csvc = _int(row.get("bac_csvc", ""))
    if csvc is None:
        return
    name = T.BACNET_CONF.get(csvc, f"Service {csvc}")
    if csvc in T.BACNET_DANGEROUS:
        _emit(events, ts, "bacnet", "bacnet.dangerous", row,
              f"BACnet {T.BACNET_DANGEROUS[csvc]}", svc_name=name)
    elif csvc in (15, 16):
        _emit(events, ts, "bacnet", "bacnet.write", row,
              f"BACnet {name} (write)", svc_name=name)


def d_opcua(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="opcua", role_hint="opc-server", port=4840, proto_tcp=True)
    inv.flow(src, dst, "opcua", 4840)
    secpol = row.get("opcua_secpol", "")
    if secpol and secpol.endswith("#None"):
        _emit(events, ts, "opcua", "opcua.nosec", row,
              f"OPC UA session to {dst} using SecurityPolicy=None (no encryption)")


def d_omron(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="omron", role_hint="plc", port=9600)
    cmd = (row.get("omron_cmd") or "").replace("0x", "").replace(",", "").strip().lower()
    if not cmd:
        return
    cmd = cmd[-4:].zfill(4)
    name = T.OMRON_FINS.get(cmd, f"FINS {cmd}")
    if cmd in T.OMRON_DANGEROUS:
        _emit(events, ts, "omron", "omron.dangerous", row,
              f"Omron FINS {T.OMRON_DANGEROUS[cmd]} -> {dst}", cmd_name=name)
    elif cmd == "0102":
        _emit(events, ts, "omron", "omron.write", row,
              f"Omron FINS Memory Write -> {dst}", cmd_name=name)


def d_goose(row, ts, inv, events) -> None:
    ref = row.get("goose_ref")
    if not ref:
        return
    src = row.get("eth_src")
    inv.tag_asset(None, mac=src, protocol="goose", role_hint="ied", layer2=True)
    data = {
        "ref": ref,
        "stnum": _int(row.get("goose_stnum", "")),
        "sqnum": _int(row.get("goose_sqnum", "")),
        "sim": row.get("goose_sim") in ("1", "True", "true"),
        "ndscom": row.get("goose_ndscom") in ("1", "True", "true"),
    }
    events.append(ProtocolEvent(
        ts=ts, protocol="goose", kind="goose.frame", src=src, dst=row.get("eth_dst"),
        summary=f"GOOSE {ref} stNum={data['stnum']} sqNum={data['sqnum']}", data=data))


def d_profinet(row, ts, inv, events) -> None:
    station = row.get("pn_station")
    src = row.get("eth_src")
    if station:
        inv.tag_asset(None, mac=src, protocol="profinet", role_hint="io-device",
                      hostname=station, layer2=True)
    svc = row.get("pn_svc_id")
    if svc == "4":  # DCP Set — a configuration/write operation
        _emit(events, ts, "profinet", "profinet.dcp_set", row,
              f"PROFINET DCP Set (device reconfiguration) by {src}")


def d_mqtt(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    inv.tag_asset(dst, protocol="mqtt", role_hint="broker", port=1883, proto_tcp=True)
    if row.get("mqtt_user") or row.get("mqtt_pass"):
        _emit(events, ts, "mqtt", "mqtt.cleartext_auth", row,
              f"MQTT credentials sent in cleartext to broker {dst}")


# --- generic IT/management protocols (cleartext & weak crypto) --------------
def d_generic(row, ts, inv, events) -> None:
    src, dst = row.get("ip_src"), row.get("ip_dst")
    if row.get("telnet_data") is not None and row.get("telnet_data") != "":
        _emit(events, ts, "telnet", "cleartext.telnet", row,
              f"Telnet session {src} -> {dst} (cleartext remote shell)")
    if row.get("ftp_cmd"):
        cmd = row["ftp_cmd"].upper()
        if cmd in ("USER", "PASS"):
            _emit(events, ts, "ftp", "cleartext.ftp", row,
                  f"FTP authentication in cleartext {src} -> {dst}")
    if row.get("http_auth") or row.get("http_authbasic"):
        _emit(events, ts, "http", "cleartext.http_auth", row,
              f"HTTP Basic/again cleartext authorization {src} -> {dst}")
    if row.get("snmp_comm"):
        comm = row["snmp_comm"]
        if comm.lower() in ("public", "private"):
            _emit(events, ts, "snmp", "snmp.default_community", row,
                  f"SNMP default community '{comm}' seen to {dst}", community=comm)
        else:
            _emit(events, ts, "snmp", "snmp.v1v2_cleartext", row,
                  f"SNMP v1/v2c cleartext community to {dst}")
    if row.get("tftp_op"):
        _emit(events, ts, "tftp", "cleartext.tftp", row,
              f"TFTP file transfer {src} -> {dst} (no auth, often firmware)")
    if row.get("vnc_ver"):
        _emit(events, ts, "vnc", "remote.vnc", row,
              f"VNC server reachable at {src}")
    # Weak TLS versions: 0x0300 SSLv3, 0x0301 TLS1.0, 0x0302 TLS1.1
    for key in ("tls_hs_ver", "tls_rec_ver"):
        v = _int(row.get(key, ""), base=16)
        if v in (0x0300, 0x0301, 0x0302):
            label = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}[v]
            _emit(events, ts, "tls", "tls.weak_version", row,
                  f"Deprecated {label} negotiated {src} -> {dst}", version=label)
            break


# Registry: (predicate on protostack/fields) -> dissector
_DISSECTORS: list[tuple[str, Callable]] = [
    ("modbus", d_modbus),
    ("dnp3", d_dnp3),
    ("s7comm", d_s7),
    ("cotp", d_s7),
    ("enip", d_enip_cip),
    ("cip", d_enip_cip),
    ("iec60870_104", d_iec104),
    ("bacapp", d_bacnet),
    ("bacnet", d_bacnet),
    ("opcua", d_opcua),
    ("omron", d_omron),
    ("goose", d_goose),
    ("pn_dcp", d_profinet),
    ("mqtt", d_mqtt),
]


def dissect(row: dict, ts: float, inv, events: list) -> None:
    """Run every applicable dissector for one packet row."""
    stack = row.get("protostack", "")
    for token, fn in _DISSECTORS:
        if token in stack:
            try:
                fn(row, ts, inv, events)
            except Exception:
                pass  # never let one malformed packet kill the capture
    # Generic/management always runs (fields gate it internally)
    try:
        d_generic(row, ts, inv, events)
    except Exception:
        pass
