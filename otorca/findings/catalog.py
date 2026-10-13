"""The OT-ORCA findings catalog.

Each entry is a reusable finding *template*: a stable ``rule_id`` mapped to a
title, default severity, category, a plain-English description, a concrete
mitigation, and standards/framework references (IEC 62443, NIST SP 800-82,
MITRE ATT&CK for ICS, relevant CWEs). The rules engine instantiates these with
run-time evidence.

Keeping this knowledge in one declarative place is what lets OT-ORCA read like
a consultant's report rather than a packet dump.
"""

from __future__ import annotations

from ..core.models import Severity

# rule_id -> template dict
CATALOG: dict[str, dict] = {

    # ======================= insecure-by-design protocols ==================
    "OTO-PROTO-CLEARTEXT": {
        "title": "Unauthenticated OT protocol in use",
        "severity": Severity.MEDIUM,
        "category": "Insecure by Design",
        "description": (
            "A legacy OT protocol that provides no authentication, authorization "
            "or encryption was observed carrying operational traffic. Any host "
            "with network access to the controller can read process data and, in "
            "most cases, issue commands indistinguishable from a legitimate master."
        ),
        "mitigation": (
            "Segment the protocol into a dedicated control zone with an enforcing "
            "firewall/conduit (IEC 62443 zones & conduits). Restrict the protocol "
            "to an explicit allow-list of master/engineering hosts, enable any "
            "available secure variant (e.g. DNP3-SA, Modbus/TLS, OPC UA with "
            "Sign&Encrypt), and deploy protocol-aware monitoring/DPI."
        ),
        "references": [
            "IEC 62443-3-3 SR 1.1/SR 1.2", "NIST SP 800-82r3 §6",
            "MITRE ATT&CK for ICS T0830 (Adversary-in-the-Middle)",
            "CWE-319 Cleartext Transmission", "CWE-306 Missing Authentication",
        ],
    },

    "OTO-MODBUS-WRITE": {
        "title": "Modbus write command observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "A Modbus write function (coil/register write) was seen on the wire. "
            "Because Modbus has no authentication, the ability to write process "
            "variables is available to anyone on the segment and can directly "
            "change actuator states or setpoints."
        ),
        "mitigation": (
            "Confirm the writing host is an authorized master. Place the PLC "
            "behind a control-zone firewall that limits Modbus/TCP (502) to known "
            "masters, consider a unidirectional gateway for monitoring-only "
            "consumers, and enable write-protection/key-switch RUN mode on the PLC."
        ),
        "references": ["MITRE ATT&CK for ICS T0836 (Modify Parameter)",
                       "IEC 62443-3-3 SR 2.1", "CWE-306"],
    },

    "OTO-MODBUS-PROGRAM": {
        "title": "Modbus diagnostic / programming function observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "A Modbus diagnostic, file-record or encapsulated-interface function "
            "was observed. These can restart communications, force listen-only "
            "mode, or read/write device files — behaviour normally reserved for "
            "engineering tools, not routine polling."
        ),
        "mitigation": (
            "Restrict diagnostic function codes to engineering workstations only, "
            "during maintenance windows. Monitor for function codes 8/20/21/43 and "
            "alert on any source outside the engineering allow-list."
        ),
        "references": ["MITRE ATT&CK for ICS T0831 (Manipulation of Control)",
                       "IEC 62443-3-3 SR 2.1"],
    },

    "OTO-S7-STOP": {
        "title": "Siemens S7 PLC STOP command observed",
        "severity": Severity.CRITICAL,
        "category": "Loss of Control",
        "description": (
            "An S7comm PLC-STOP was observed. Stopping a running controller halts "
            "the process it governs and is a classic denial-of-control action; it "
            "requires no authentication on S7-300/400 and legacy S7-1200/1500 "
            "configurations."
        ),
        "mitigation": (
            "Treat this as a potential incident unless it maps to a scheduled "
            "maintenance action. Enable the PLC's access-protection/password and "
            "'RUN' key-switch, restrict TCP/102 to engineering hosts, and alert on "
            "any STOP ROSCTR in production."
        ),
        "references": ["MITRE ATT&CK for ICS T0813 (Denial of Control), "
                       "T0881 (Service Stop)", "IEC 62443-3-3 SR 7.1"],
    },

    "OTO-S7-PROGRAM": {
        "title": "Siemens S7 block up/download (program change)",
        "severity": Severity.CRITICAL,
        "category": "Program Modification",
        "description": (
            "An S7comm block download/upload or program-invocation function was "
            "observed, indicating logic is being read from or written to the PLC. "
            "An attacker with this capability can implant or alter control logic "
            "(cf. Stuxnet, TRITON-style attacks)."
        ),
        "mitigation": (
            "Verify the engineering host and change-control ticket. Enforce PLC "
            "access protection and know-how protection, limit TCP/102 to the "
            "engineering VLAN, and baseline program block checksums for integrity "
            "monitoring."
        ),
        "references": ["MITRE ATT&CK for ICS T0843 (Program Download), "
                       "T0889 (Modify Program)", "IEC 62443-3-3 SR 3.4"],
    },

    "OTO-S7-WRITE": {
        "title": "Siemens S7 variable write observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": "An S7comm Write-Var operation modified PLC memory/variables.",
        "mitigation": (
            "Confirm the source is an authorized HMI/engineering station; enable "
            "PLC access protection and segment TCP/102."),
        "references": ["MITRE ATT&CK for ICS T0836", "IEC 62443-3-3 SR 2.1"],
    },

    "OTO-DNP3-DANGEROUS": {
        "title": "DNP3 restart / application control observed",
        "severity": Severity.CRITICAL,
        "category": "Loss of Control",
        "description": (
            "A DNP3 cold/warm restart, stop- or start-application function was "
            "observed. These reset or halt outstation applications and can cause "
            "loss of monitoring and control across an electric/water SCADA network."
        ),
        "mitigation": (
            "Enable DNP3 Secure Authentication (IEEE 1815-2012), restrict TCP/UDP "
            "20000 to the authorized master, and alert on restart function codes."
        ),
        "references": ["MITRE ATT&CK for ICS T0816 (Device Restart/Shutdown)",
                       "IEEE 1815 DNP3-SA", "IEC 62443-3-3 SR 2.1"],
    },

    "OTO-DNP3-WRITE": {
        "title": "DNP3 control/write (Operate/Select) observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "A DNP3 Select/Operate/Direct-Operate or write function was observed, "
            "driving an outstation control point (e.g. breaker, valve)."
        ),
        "mitigation": "Enable DNP3-SA; allow-list the master; monitor Operate CROBs.",
        "references": ["MITRE ATT&CK for ICS T0855 (Unauthorized Command Message)"],
    },

    "OTO-CIP-DANGEROUS": {
        "title": "CIP device Reset/Start/Stop observed",
        "severity": Severity.CRITICAL,
        "category": "Loss of Control",
        "description": (
            "A CIP Reset, Start, Stop or Execute-PCCC service was observed on "
            "EtherNet/IP. These can reboot or change the run-state of Allen-Bradley "
            "/ CIP controllers without authentication."
        ),
        "mitigation": (
            "Set the controller key-switch to RUN, enable CIP Security (where "
            "supported), and restrict TCP 44818 / UDP 2222 to engineering hosts."
        ),
        "references": ["MITRE ATT&CK for ICS T0816, T0831",
                       "IEC 62443-3-3 SR 2.1", "ODVA CIP Security"],
    },

    "OTO-CIP-WRITE": {
        "title": "CIP write / Set-Attribute observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": "A CIP write (Set_Attribute / Logix write) modified a device tag.",
        "mitigation": "Enable CIP Security; allow-list masters; key-switch to RUN.",
        "references": ["MITRE ATT&CK for ICS T0836"],
    },

    "OTO-IEC104-DANGEROUS": {
        "title": "IEC 60870-5-104 reset/interrogation observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "An IEC-104 reset-process or general-interrogation command was seen. "
            "Reset-process can disrupt an RTU; interrogation reveals full process "
            "state to any connected client."
        ),
        "mitigation": (
            "Restrict TCP/2404 to the authorized SCADA master, deploy an IEC-104 "
            "aware firewall, and consider TLS per IEC 62351-3."
        ),
        "references": ["IEC 62351-3/-5", "MITRE ATT&CK for ICS T0855"],
    },

    "OTO-IEC104-CONTROL": {
        "title": "IEC 60870-5-104 command/setpoint observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "An IEC-104 single/double command or setpoint (C_SC/C_DC/C_SE) was "
            "observed, actuating a field point."),
        "mitigation": "Allow-list the master; apply IEC 62351 authentication/TLS.",
        "references": ["MITRE ATT&CK for ICS T0855", "IEC 62351-5"],
    },

    "OTO-BACNET-DANGEROUS": {
        "title": "BACnet device-control / reinitialize observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "A BACnet DeviceCommunicationControl or ReinitializeDevice service was "
            "observed, which can silence or reboot building-automation controllers."
        ),
        "mitigation": (
            "Require BACnet passwords for these services, segment UDP/47808, and "
            "deploy BACnet/SC (Secure Connect) where available."),
        "references": ["ASHRAE 135 Annex", "MITRE ATT&CK for ICS T0816"],
    },

    "OTO-BACNET-WRITE": {
        "title": "BACnet WriteProperty observed",
        "severity": Severity.MEDIUM,
        "category": "Unauthorized Control",
        "description": "A BACnet WriteProperty modified an object value/setpoint.",
        "mitigation": "Restrict writers; adopt BACnet/SC; monitor write services.",
        "references": ["MITRE ATT&CK for ICS T0836"],
    },

    "OTO-OMRON-DANGEROUS": {
        "title": "Omron FINS Run/Stop/Program-Write observed",
        "severity": Severity.CRITICAL,
        "category": "Loss of Control",
        "description": (
            "An Omron FINS Run, Stop or Program-Area-Write command was observed, "
            "changing controller run-state or logic without authentication."),
        "mitigation": (
            "Restrict UDP/TCP 9600 to engineering hosts, enable the CPU write-"
            "protect switch, and monitor FINS command codes 0401/0402/2306."),
        "references": ["MITRE ATT&CK for ICS T0813, T0843"],
    },

    "OTO-OMRON-WRITE": {
        "title": "Omron FINS memory write observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": "An Omron FINS Memory-Area-Write modified controller memory.",
        "mitigation": "Allow-list masters; enable write-protect; segment FINS.",
        "references": ["MITRE ATT&CK for ICS T0836"],
    },

    "OTO-PROFINET-DCPSET": {
        "title": "PROFINET DCP Set (device reconfiguration) observed",
        "severity": Severity.HIGH,
        "category": "Unauthorized Control",
        "description": (
            "A PROFINET DCP 'Set' request was observed. DCP Set can change a "
            "device's name-of-station or IP at layer 2 with no authentication, "
            "which can knock an IO device offline or hijack its identity."),
        "mitigation": (
            "Lock device parameters in the IO controller, disable DCP write where "
            "possible, and monitor L2 for DCP Set from unexpected sources."),
        "references": ["MITRE ATT&CK for ICS T0856 (Spoof Reporting Message)",
                       "IEC 62443-3-3 SR 1.2"],
    },

    # ======================= IEC 61850 GOOSE =============================
    "OTO-GOOSE-STNUM-REGRESS": {
        "title": "GOOSE stNum regression / possible spoofing",
        "severity": Severity.CRITICAL,
        "category": "Protocol Manipulation",
        "description": (
            "The GOOSE state number (stNum) for a control block decreased, or a "
            "duplicate stNum appeared with different content. Legitimate GOOSE "
            "stNum only increments on state change; a regression is a strong "
            "indicator of a GOOSE spoofing / replay attack against protection."
        ),
        "mitigation": (
            "Enable IEC 62351-6 GOOSE authentication (R-GOOSE/MAC), validate "
            "stNum/sqNum continuity in the IDS, and physically restrict the "
            "process-bus/station-bus VLAN."),
        "references": ["IEC 62351-6", "MITRE ATT&CK for ICS T0832 (Manipulation "
                       "of View), T0856"],
    },

    "OTO-GOOSE-TEST-SIM": {
        "title": "GOOSE test/simulation flag set in production",
        "severity": Severity.HIGH,
        "category": "Protocol Manipulation",
        "description": (
            "A GOOSE message with the simulation or test/ndsCom flag set was "
            "observed. If subscribers are not in test mode, an attacker can use "
            "the simulation bit to inject crafted values that override real ones."
        ),
        "mitigation": (
            "Ensure IEDs ignore simulated GOOSE unless explicitly in test mode; "
            "alert on simulation/test flags on the production bus."),
        "references": ["IEC 61850-8-1", "IEC 62351-6"],
    },

    # ======================= OPC UA =====================================
    "OTO-OPCUA-NOSEC": {
        "title": "OPC UA session without security (SecurityPolicy=None)",
        "severity": Severity.HIGH,
        "category": "Weak Cryptography",
        "description": (
            "An OPC UA session negotiated SecurityPolicy=None, meaning no signing "
            "or encryption. Credentials and process data traverse the network in "
            "cleartext and messages can be forged."),
        "mitigation": (
            "Disable the None security policy on the server, require "
            "Basic256Sha256 or Aes256 with Sign&Encrypt, and use certificate-based "
            "mutual authentication."),
        "references": ["OPC UA Part 2 Security", "IEC 62443-3-3 SR 4.1/SR 1.5",
                       "CWE-319"],
    },

    # ======================= cleartext IT mgmt ==========================
    "OTO-CLEARTEXT-TELNET": {
        "title": "Telnet (cleartext remote administration)",
        "severity": Severity.HIGH,
        "category": "Cleartext Credentials",
        "description": (
            "Telnet traffic was observed. Telnet transmits credentials and session "
            "data in cleartext and is trivially sniffed or hijacked on a shared "
            "segment — a common finding on OT switches, serial servers and RTUs."),
        "mitigation": "Replace Telnet with SSH; disable Telnet on all devices.",
        "references": ["CWE-319", "IEC 62443-3-3 SR 1.5", "NIST 800-82r3"],
    },

    "OTO-CLEARTEXT-FTP": {
        "title": "FTP authentication in cleartext",
        "severity": Severity.MEDIUM,
        "category": "Cleartext Credentials",
        "description": (
            "FTP USER/PASS were observed. FTP sends credentials in cleartext; it "
            "is frequently used to push PLC firmware and recipes."),
        "mitigation": "Use SFTP/FTPS; restrict and monitor firmware-transfer paths.",
        "references": ["CWE-319"],
    },

    "OTO-CLEARTEXT-HTTP-AUTH": {
        "title": "HTTP Basic authentication in cleartext",
        "severity": Severity.MEDIUM,
        "category": "Cleartext Credentials",
        "description": (
            "HTTP Basic authorization (base64, not encrypted) was observed, "
            "commonly on device web UIs and HMIs."),
        "mitigation": "Enforce HTTPS/TLS on all device web interfaces.",
        "references": ["CWE-319", "CWE-522"],
    },

    "OTO-TFTP": {
        "title": "TFTP file transfer (no authentication)",
        "severity": Severity.MEDIUM,
        "category": "Insecure Service",
        "description": (
            "TFTP traffic was observed. TFTP has no authentication and is often "
            "used for firmware/config transfer, making it an easy implant vector."),
        "mitigation": "Disable TFTP; use authenticated, integrity-checked transfer.",
        "references": ["CWE-306", "MITRE ATT&CK for ICS T0845 (Program Upload)"],
    },

    "OTO-SNMP-DEFAULT": {
        "title": "SNMP default community string",
        "severity": Severity.HIGH,
        "category": "Weak Authentication",
        "description": (
            "SNMP with a default community string ('public'/'private') was "
            "observed. This exposes device inventory and, with 'private', write "
            "access to device configuration."),
        "mitigation": (
            "Migrate to SNMPv3 with authPriv, remove default communities, and "
            "disable SNMP write access where not required."),
        "references": ["CWE-1392 Default Credentials", "CWE-319"],
    },

    "OTO-SNMP-V1V2": {
        "title": "SNMP v1/v2c cleartext in use",
        "severity": Severity.MEDIUM,
        "category": "Weak Authentication",
        "description": "SNMP v1/v2c sends community strings in cleartext.",
        "mitigation": "Move to SNMPv3 authPriv.",
        "references": ["CWE-319"],
    },

    "OTO-TLS-WEAK": {
        "title": "Deprecated SSL/TLS version negotiated",
        "severity": Severity.MEDIUM,
        "category": "Weak Cryptography",
        "description": (
            "A deprecated SSLv3/TLS1.0/TLS1.1 handshake was observed. These "
            "versions have known cryptographic weaknesses (POODLE, BEAST)."),
        "mitigation": "Require TLS 1.2+ (prefer 1.3); disable legacy versions/ciphers.",
        "references": ["CWE-326 Inadequate Encryption Strength", "RFC 8996"],
    },

    "OTO-MQTT-CLEARTEXT-AUTH": {
        "title": "MQTT credentials over cleartext",
        "severity": Severity.HIGH,
        "category": "Cleartext Credentials",
        "description": (
            "MQTT username/password were observed on an unencrypted broker "
            "connection (typically port 1883), exposing IIoT credentials."),
        "mitigation": "Use MQTT over TLS (8883) with client certificates/ACLs.",
        "references": ["CWE-319", "CWE-522"],
    },

    "OTO-VNC": {
        "title": "VNC remote-desktop service reachable",
        "severity": Severity.MEDIUM,
        "category": "Remote Access",
        "description": (
            "A VNC server was observed. VNC is frequently deployed on HMIs/engineering "
            "stations with weak or no authentication and legacy encryption."),
        "mitigation": (
            "Place remote access behind an authenticated, logged jump host; disable "
            "direct VNC; enforce strong auth and TLS tunnelling."),
        "references": ["MITRE ATT&CK for ICS T0822 (External Remote Services)"],
    },

    # ======================= topology / architecture ====================
    "OTO-IT-OT-CROSSING": {
        "title": "IT/OT boundary crossing (external host talking OT protocol)",
        "severity": Severity.HIGH,
        "category": "Segmentation",
        "description": (
            "A host outside the OT address space (public or enterprise range) was "
            "observed exchanging an OT control protocol with a controller. This "
            "indicates weak or missing segmentation between the control zone and "
            "higher Purdue levels."),
        "mitigation": (
            "Enforce an industrial DMZ (Purdue L3.5) and conduit firewalls so no "
            "enterprise/internet host speaks control protocols to L1/L2 devices. "
            "Broker all cross-zone data through the DMZ (historian replica, OPC "
            "aggregator)."),
        "references": ["IEC 62443-3-3 SR 5.1 (Network Segmentation)",
                       "NIST SP 800-82r3 §5", "ISA-95/Purdue model"],
    },

    "OTO-NEW-MASTER": {
        "title": "Multiple masters issuing commands to one controller",
        "severity": Severity.MEDIUM,
        "category": "Unauthorized Control",
        "description": (
            "More than one source host was observed sending control/write commands "
            "to the same controller. Most control architectures expect a single "
            "primary master; additional command sources may be rogue or "
            "misconfigured engineering tools."),
        "mitigation": (
            "Confirm each command source against the asset owner's expected master "
            "list; alert on any new source issuing writes."),
        "references": ["MITRE ATT&CK for ICS T0855", "IEC 62443-3-3 SR 2.1"],
    },

    "OTO-ARP-ANOMALY": {
        "title": "ARP anomaly (possible spoofing / duplicate IP)",
        "severity": Severity.HIGH,
        "category": "Protocol Manipulation",
        "description": (
            "The same IP address was seen claimed by more than one MAC address "
            "(or a MAC rapidly changed IPs). On a flat OT segment this is a strong "
            "indicator of ARP spoofing / adversary-in-the-middle, or a duplicate-IP "
            "misconfiguration that can disrupt control traffic."),
        "mitigation": (
            "Enable Dynamic ARP Inspection and DHCP snooping on managed switches, "
            "use static ARP for critical control paths, and investigate the "
            "conflicting MAC."),
        "references": ["MITRE ATT&CK for ICS T0830 (Adversary-in-the-Middle)",
                       "CWE-300"],
    },

    "OTO-ENIP-IDENTITY": {
        "title": "Device identity/firmware disclosed on the network",
        "severity": Severity.LOW,
        "category": "Information Disclosure",
        "description": (
            "A controller disclosed vendor, product, serial and/or firmware "
            "revision (e.g. via EtherNet/IP ListIdentity). This reconnaissance "
            "data lets an attacker match devices to public vulnerabilities."),
        "mitigation": (
            "Restrict unconnected identity requests to engineering hosts, segment "
            "discovery protocols, and track disclosed firmware against vendor "
            "advisories for patch planning."),
        "references": ["MITRE ATT&CK for ICS T0888 (Remote System Info Discovery)",
                       "CWE-200"],
    },

    "OTO-FLAT-NETWORK": {
        "title": "Flat network — OT and IT assets share one broadcast domain",
        "severity": Severity.MEDIUM,
        "category": "Segmentation",
        "description": (
            "Controllers and general-purpose IT hosts were observed in the same "
            "subnet/broadcast domain with no VLAN separation evident in the "
            "capture. Flat OT networks let commodity malware and lateral movement "
            "reach controllers directly."),
        "mitigation": (
            "Introduce VLANs/zoning per IEC 62443, separate control traffic from "
            "IT, and place an enforcing firewall between zones."),
        "references": ["IEC 62443-3-3 SR 5.1", "NIST SP 800-82r3 §5"],
    },

    "OTO-UNENCRYPTED-DISCOVERY": {
        "title": "Unauthenticated L2 discovery protocol active",
        "severity": Severity.LOW,
        "category": "Information Disclosure",
        "description": (
            "Layer-2 discovery (PROFINET DCP, LLDP, CDP, mDNS/NBNS) revealed "
            "device names and topology. Useful for operations, but also hands an "
            "attacker a free network map."),
        "mitigation": (
            "Disable unneeded discovery on edge/untrusted ports; keep it within "
            "trusted control VLANs only."),
        "references": ["CWE-200", "MITRE ATT&CK for ICS T0842 (Network Sniffing)"],
    },
}


def get(rule_id: str) -> dict:
    return CATALOG[rule_id]
