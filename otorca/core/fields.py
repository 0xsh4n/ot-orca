"""The tshark ``-T fields`` extraction schema used by OT-ORCA.

Rather than parse full packet JSON (slow, version-brittle), OT-ORCA asks tshark
for a flat, tab-separated row of pre-selected fields per packet. ``capture.py``
validates this wish-list against the running tshark build (``tshark -G fields``)
and silently drops any field the local dissector set doesn't provide, so the
tool degrades gracefully across Wireshark versions and platforms.

``FIELDS`` is an ordered list; the order defines the column order of each row.
``ALIASES`` maps the raw tshark field name to the short key used everywhere else.
"""

from __future__ import annotations

# (tshark_field, short_key). Order matters: it is the row column order.
FIELDS: list[tuple[str, str]] = [
    # ---- frame / L2 / L3 / L4 ----------------------------------------------
    ("frame.time_epoch", "ts"),
    ("frame.len", "len"),
    ("frame.protocols", "protostack"),
    ("eth.src", "eth_src"),
    ("eth.dst", "eth_dst"),
    ("vlan.id", "vlan"),
    ("arp.opcode", "arp_op"),
    ("arp.src.hw_mac", "arp_src_mac"),
    ("arp.src.proto_ipv4", "arp_src_ip"),
    ("arp.dst.proto_ipv4", "arp_dst_ip"),
    ("ip.src", "ip_src"),
    ("ip.dst", "ip_dst"),
    ("ipv6.src", "ip6_src"),
    ("ipv6.dst", "ip6_dst"),
    ("ip.ttl", "ttl"),
    ("tcp.srcport", "tcp_sport"),
    ("tcp.dstport", "tcp_dport"),
    ("tcp.flags.syn", "tcp_syn"),
    ("tcp.flags.ack", "tcp_ack"),
    ("tcp.flags.reset", "tcp_rst"),
    ("udp.srcport", "udp_sport"),
    ("udp.dstport", "udp_dport"),
    # ---- discovery / naming -------------------------------------------------
    ("dns.qry.name", "dns_qry"),
    ("dhcp.option.hostname", "dhcp_host"),
    ("nbns.name", "nbns_name"),
    ("lldp.tlv.system.name", "lldp_name"),
    ("cdp.deviceid", "cdp_devid"),
    ("mdns.dns.resp.name", "mdns_name"),
    # ---- Modbus / TCP -------------------------------------------------------
    ("mbtcp.trans_id", "mb_trans"),
    ("mbtcp.unit_id", "mb_unit"),
    ("modbus.func_code", "mb_func"),
    ("modbus.exception_code", "mb_exc"),
    ("modbus.reference_num", "mb_ref"),
    ("modbus.word_cnt", "mb_wcnt"),
    ("modbus.bit_cnt", "mb_bcnt"),
    ("modbus.mei", "mb_mei"),
    # ---- DNP3 ---------------------------------------------------------------
    ("dnp3.ctl.prifunc", "dnp3_prifunc"),
    ("dnp3.al.func", "dnp3_alfunc"),
    ("dnp3.src", "dnp3_src"),
    ("dnp3.dst", "dnp3_dst"),
    ("dnp3.al.iin", "dnp3_iin"),
    # ---- Siemens S7comm (COTP/TPKT) ----------------------------------------
    ("cotp.type", "cotp_type"),
    ("cotp.dst-tsap", "cotp_dtsap"),
    ("cotp.src-tsap", "cotp_stsap"),
    ("s7comm.header.rosctr", "s7_rosctr"),
    ("s7comm.param.func", "s7_func"),
    ("s7comm.param.userdata.funcgroup", "s7_ud_fg"),
    ("s7comm.param.userdata.subfunc", "s7_ud_sf"),
    ("s7comm.data.returncode", "s7_ret"),
    ("s7comm.blockinfo.blocktype", "s7_blocktype"),
    # ---- EtherNet/IP + CIP --------------------------------------------------
    ("enip.command", "enip_cmd"),
    ("enip.session", "enip_session"),
    ("enip.lir.vendor", "enip_vendor"),
    ("enip.lir.devtype", "enip_devtype"),
    ("enip.lir.name", "enip_name"),
    ("enip.lir.serial", "enip_serial"),
    ("enip.lir.revision", "enip_rev"),
    ("cip.service", "cip_service"),
    ("cip.sc", "cip_sc"),
    ("cip.class", "cip_class"),
    ("cip.genstat", "cip_status"),
    ("cip.id.vendor_id", "cip_vendor"),
    ("cip.id.product_name", "cip_product"),
    ("cip.id.serial_number", "cip_serial"),
    ("cip.id.major_rev", "cip_majrev"),
    ("cip.id.minor_rev", "cip_minrev"),
    ("cip.symbol", "cip_symbol"),
    # ---- IEC 60870-5-104 ----------------------------------------------------
    ("iec60870_104.type", "iec104_type"),
    ("iec60870_asdu.typeid", "iec104_typeid"),
    ("iec60870_asdu.causetx", "iec104_cot"),
    ("iec60870_asdu.addr", "iec104_ca"),
    ("iec60870_asdu.ioa", "iec104_ioa"),
    # ---- BACnet -------------------------------------------------------------
    ("bacapp.type", "bac_type"),
    ("bacapp.confirmed_service", "bac_csvc"),
    ("bacapp.unconfirmed_service", "bac_usvc"),
    ("bacapp.vendor_identifier", "bac_vendor"),
    ("bacapp.object_name", "bac_objname"),
    # ---- OPC UA -------------------------------------------------------------
    ("opcua.transport.type", "opcua_msgtype"),
    ("opcua.SecurityPolicyUri", "opcua_secpol"),
    ("opcua.servicenodeid.numeric", "opcua_svc"),
    # ---- PROFINET -----------------------------------------------------------
    ("pn_dcp.service_id", "pn_svc_id"),
    ("pn_dcp.service_type", "pn_svc_type"),
    ("pn_dcp.suboption_device_nameofstation", "pn_station"),
    ("pn_rt.frame_id", "pn_frameid"),
    # ---- IEC 61850 (GOOSE / SV / MMS) --------------------------------------
    ("goose.gocbRef", "goose_ref"),
    ("goose.stNum", "goose_stnum"),
    ("goose.sqNum", "goose_sqnum"),
    ("goose.simulation", "goose_sim"),
    ("goose.ndsCom", "goose_ndscom"),
    ("sv.svID", "sv_id"),
    ("mms.confirmedServiceRequest", "mms_csvc"),
    ("mms.domainId", "mms_domain"),
    # ---- Omron FINS ---------------------------------------------------------
    ("omron.command", "omron_cmd"),
    # ---- HART-IP ------------------------------------------------------------
    ("hart_ip.message_type", "hartip_mtype"),
    ("hart_ip.message_id", "hartip_mid"),
    # ---- MQTT (IIoT) --------------------------------------------------------
    ("mqtt.msgtype", "mqtt_type"),
    ("mqtt.topic", "mqtt_topic"),
    ("mqtt.username", "mqtt_user"),
    ("mqtt.passwd", "mqtt_pass"),
    ("mqtt.clientid", "mqtt_client"),
    # ---- EtherCAT / PROFINET PTCP (presence only) --------------------------
    ("ecat.cmd", "ecat_cmd"),
    # ---- IT / management protocols (cleartext & weak-crypto detection) -----
    ("ftp.request.command", "ftp_cmd"),
    ("ftp.request.arg", "ftp_arg"),
    ("telnet.data", "telnet_data"),
    ("http.request.method", "http_method"),
    ("http.request.uri", "http_uri"),
    ("http.host", "http_host"),
    ("http.user_agent", "http_ua"),
    ("http.authorization", "http_auth"),
    ("http.authbasic", "http_authbasic"),
    ("snmp.community", "snmp_comm"),
    ("snmp.name", "snmp_oid"),
    ("smb.cmd", "smb_cmd"),
    ("smb2.cmd", "smb2_cmd"),
    ("smb.native_os", "smb_os"),
    ("ntlmssp.auth.username", "ntlm_user"),
    ("tftp.opcode", "tftp_op"),
    ("tftp.source_file", "tftp_src"),
    ("tftp.destination_file", "tftp_dst"),
    ("ssh.protocol", "ssh_proto"),
    ("vnc.server_proto_ver", "vnc_ver"),
    ("rdp.neg_type", "rdp_neg"),
    ("tls.handshake.version", "tls_hs_ver"),
    ("tls.record.version", "tls_rec_ver"),
    ("tls.handshake.type", "tls_hs_type"),
    ("tls.handshake.extensions_server_name", "tls_sni"),
]

# Fields we must never render verbatim into reports (secrets). We still *detect*
# their presence to raise a cleartext-credential finding.
SECRET_KEYS = {"mqtt_pass", "snmp_comm", "http_auth", "http_authbasic", "telnet_data"}


def field_names() -> list[str]:
    return [f for f, _ in FIELDS]


def aliases() -> dict[str, str]:
    return {f: a for f, a in FIELDS}
