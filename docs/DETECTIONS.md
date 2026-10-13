# OT-ORCA Detection Catalog

OT-ORCA ships **35 built-in detections**. Each finding carries a severity, a plain-English description, a concrete mitigation and standards references (IEC 62443, NIST SP 800-82r3, MITRE ATT&CK for ICS, CWE).

| Rule ID | Severity | Category | Title |
|---|---|---|---|
| `OTO-S7-STOP` | Critical | Loss of Control | Siemens S7 PLC STOP command observed |
| `OTO-S7-PROGRAM` | Critical | Program Modification | Siemens S7 block up/download (program change) |
| `OTO-DNP3-DANGEROUS` | Critical | Loss of Control | DNP3 restart / application control observed |
| `OTO-CIP-DANGEROUS` | Critical | Loss of Control | CIP device Reset/Start/Stop observed |
| `OTO-OMRON-DANGEROUS` | Critical | Loss of Control | Omron FINS Run/Stop/Program-Write observed |
| `OTO-GOOSE-STNUM-REGRESS` | Critical | Protocol Manipulation | GOOSE stNum regression / possible spoofing |
| `OTO-MODBUS-WRITE` | High | Unauthorized Control | Modbus write command observed |
| `OTO-MODBUS-PROGRAM` | High | Unauthorized Control | Modbus diagnostic / programming function observed |
| `OTO-S7-WRITE` | High | Unauthorized Control | Siemens S7 variable write observed |
| `OTO-DNP3-WRITE` | High | Unauthorized Control | DNP3 control/write (Operate/Select) observed |
| `OTO-CIP-WRITE` | High | Unauthorized Control | CIP write / Set-Attribute observed |
| `OTO-IEC104-DANGEROUS` | High | Unauthorized Control | IEC 60870-5-104 reset/interrogation observed |
| `OTO-IEC104-CONTROL` | High | Unauthorized Control | IEC 60870-5-104 command/setpoint observed |
| `OTO-BACNET-DANGEROUS` | High | Unauthorized Control | BACnet device-control / reinitialize observed |
| `OTO-OMRON-WRITE` | High | Unauthorized Control | Omron FINS memory write observed |
| `OTO-PROFINET-DCPSET` | High | Unauthorized Control | PROFINET DCP Set (device reconfiguration) observed |
| `OTO-GOOSE-TEST-SIM` | High | Protocol Manipulation | GOOSE test/simulation flag set in production |
| `OTO-OPCUA-NOSEC` | High | Weak Cryptography | OPC UA session without security (SecurityPolicy=None) |
| `OTO-CLEARTEXT-TELNET` | High | Cleartext Credentials | Telnet (cleartext remote administration) |
| `OTO-SNMP-DEFAULT` | High | Weak Authentication | SNMP default community string |
| `OTO-MQTT-CLEARTEXT-AUTH` | High | Cleartext Credentials | MQTT credentials over cleartext |
| `OTO-IT-OT-CROSSING` | High | Segmentation | IT/OT boundary crossing (external host talking OT protocol) |
| `OTO-ARP-ANOMALY` | High | Protocol Manipulation | ARP anomaly (possible spoofing / duplicate IP) |
| `OTO-PROTO-CLEARTEXT` | Medium | Insecure by Design | Unauthenticated OT protocol in use |
| `OTO-BACNET-WRITE` | Medium | Unauthorized Control | BACnet WriteProperty observed |
| `OTO-CLEARTEXT-FTP` | Medium | Cleartext Credentials | FTP authentication in cleartext |
| `OTO-CLEARTEXT-HTTP-AUTH` | Medium | Cleartext Credentials | HTTP Basic authentication in cleartext |
| `OTO-TFTP` | Medium | Insecure Service | TFTP file transfer (no authentication) |
| `OTO-SNMP-V1V2` | Medium | Weak Authentication | SNMP v1/v2c cleartext in use |
| `OTO-TLS-WEAK` | Medium | Weak Cryptography | Deprecated SSL/TLS version negotiated |
| `OTO-VNC` | Medium | Remote Access | VNC remote-desktop service reachable |
| `OTO-NEW-MASTER` | Medium | Unauthorized Control | Multiple masters issuing commands to one controller |
| `OTO-FLAT-NETWORK` | Medium | Segmentation | Flat network — OT and IT assets share one broadcast domain |
| `OTO-ENIP-IDENTITY` | Low | Information Disclosure | Device identity/firmware disclosed on the network |
| `OTO-UNENCRYPTED-DISCOVERY` | Low | Information Disclosure | Unauthenticated L2 discovery protocol active |

## Protocol coverage (passive dissection)

Modbus/TCP · DNP3 · Siemens S7comm (COTP/TPKT) · EtherNet/IP + CIP · IEC 60870-5-104 · BACnet/IP · OPC UA · PROFINET (DCP/RT) · IEC 61850 GOOSE / Sampled Values / MMS · Omron FINS · HART-IP · MQTT (IIoT) · EtherCAT (presence).

Plus IT/management protocols for cleartext & weak-crypto detection: Telnet, FTP, HTTP Basic, SNMP v1/v2c, TFTP, VNC, SSH, RDP, SMB, and TLS/SSL version analysis; discovery via LLDP, CDP, mDNS, NBNS, DHCP.

