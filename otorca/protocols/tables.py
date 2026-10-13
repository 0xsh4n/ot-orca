"""OT/ICS protocol knowledge tables.

This module encodes the domain knowledge a senior OT analyst carries in their
head: which function codes mean *read* vs *write* vs *programming/management*,
and which are outright dangerous on a production control network. The dissectors
and rules engine consume these tables, so adding protocol coverage is mostly a
matter of extending the data here.
"""

from __future__ import annotations

# --- Modbus -----------------------------------------------------------------
MODBUS_FUNC = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil",
    6: "Write Single Register", 7: "Read Exception Status",
    8: "Diagnostics", 11: "Get Comm Event Counter", 12: "Get Comm Event Log",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    17: "Report Server ID", 20: "Read File Record", 21: "Write File Record",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue", 43: "Encapsulated Interface (MEI/Device ID)",
    90: "Vendor: Schneider UMAS (90)", 100: "Vendor-specific (100)",
}
MODBUS_WRITE = {5, 6, 15, 16, 22, 23, 21}
MODBUS_PROGRAM = {8, 20, 21, 43, 90, 100}   # diagnostics/file/vendor programming
# Modbus diagnostics sub-functions that force controller state changes:
MODBUS_DIAG_DANGEROUS = {1: "Restart Comm Option", 4: "Force Listen-Only Mode"}

# --- DNP3 (application-layer function codes) --------------------------------
DNP3_AL_FUNC = {
    0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate",
    5: "Direct Operate", 6: "Direct Operate No-Ack", 7: "Immediate Freeze",
    9: "Freeze and Clear", 13: "Cold Restart", 14: "Warm Restart",
    15: "Initialize Data", 16: "Initialize Application",
    17: "Start Application", 18: "Stop Application", 19: "Save Config",
    20: "Enable Unsolicited", 21: "Disable Unsolicited", 23: "Delay Measure",
    24: "Record Current Time", 31: "Activate Config",
}
DNP3_WRITE = {2, 3, 4, 5, 6, 9, 15, 31}
DNP3_DANGEROUS = {13: "Cold Restart", 14: "Warm Restart", 18: "Stop Application",
                  17: "Start Application", 16: "Initialize Application"}

# --- S7comm (ROSCTR / function / userdata) ----------------------------------
S7_ROSCTR = {1: "Job Request", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}
S7_FUNC = {
    0x00: "CPU Services", 0x04: "Read Var", 0x05: "Write Var",
    0x1A: "Request Download", 0x1B: "Download Block", 0x1C: "Download Ended",
    0x1D: "Start Upload", 0x1E: "Upload", 0x1F: "End Upload",
    0x28: "PI Service (Program Invocation)", 0x29: "PLC Stop",
}
S7_WRITE = {0x05}
S7_PROGRAM = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28}  # block up/download
S7_STOP = {0x29}
# Userdata function groups of interest (funcgroup low nibble)
S7_UD_FUNCGROUP = {
    0x0: "Mode-transition", 0x1: "Programmer commands", 0x2: "Cyclic data",
    0x3: "Block functions", 0x4: "CPU functions (SZL/diag)",
    0x5: "Security", 0x7: "Time functions",
}

# --- EtherNet/IP ENIP commands ----------------------------------------------
ENIP_CMD = {
    0x04: "ListServices", 0x63: "ListIdentity", 0x64: "ListInterfaces",
    0x65: "RegisterSession", 0x66: "UnRegisterSession",
    0x6F: "SendRRData (unconnected CIP)", 0x70: "SendUnitData (connected CIP)",
}
# CIP generic service codes
CIP_SERVICE = {
    0x01: "Get_Attributes_All", 0x02: "Set_Attributes_All",
    0x0E: "Get_Attribute_Single", 0x10: "Set_Attribute_Single",
    0x4C: "CIP Read (Logix)", 0x4D: "CIP Write (Logix)",
    0x52: "Unconnected_Send", 0x54: "Forward_Open", 0x4E: "Forward_Close",
    0x05: "Reset", 0x06: "Start", 0x07: "Stop", 0x08: "Create",
    0x09: "Delete", 0x4B: "Execute_PCCC",
}
CIP_WRITE = {0x02, 0x10, 0x4D}
CIP_DANGEROUS = {0x05: "Reset", 0x06: "Start", 0x07: "Stop", 0x4B: "Execute_PCCC"}

# --- IEC 60870-5-104 ASDU type IDs ------------------------------------------
IEC104_TYPEID = {
    1: "M_SP_NA (single point)", 3: "M_DP_NA (double point)",
    9: "M_ME_NA (measured normalized)", 13: "M_ME_NC (measured float)",
    30: "M_SP_TB (single point w/ time)", 36: "M_ME_TF (float w/ time)",
    45: "C_SC_NA (single command)", 46: "C_DC_NA (double command)",
    47: "C_RC_NA (regulating step command)", 48: "C_SE_NA (setpoint normalized)",
    49: "C_SE_NB (setpoint scaled)", 50: "C_SE_NC (setpoint float)",
    58: "C_SC_TA (single command w/ time)", 100: "C_IC_NA (interrogation)",
    101: "C_CI_NA (counter interrogation)", 103: "C_CS_NA (clock sync)",
    104: "C_TS_NA (test)", 105: "C_RP_NA (reset process)",
    107: "C_TS_TA (test w/ time)",
}
IEC104_CONTROL = {45, 46, 47, 48, 49, 50, 58}       # setpoint/command => actuation
IEC104_DANGEROUS = {105: "Reset Process", 100: "General Interrogation"}
IEC104_UTYPE = {1: "STARTDT act", 2: "STARTDT con", 4: "STOPDT act",
                8: "STOPDT con", 16: "TESTFR act", 32: "TESTFR con"}

# --- BACnet confirmed services ----------------------------------------------
BACNET_CONF = {
    0: "acknowledgeAlarm", 6: "atomicWriteFile", 15: "writeProperty",
    16: "writePropertyMultiple", 12: "readProperty",
    14: "readPropertyMultiple", 17: "deviceCommunicationControl",
    18: "confirmedPrivateTransfer", 20: "reinitializeDevice",
}
BACNET_DANGEROUS = {17: "DeviceCommunicationControl (disable comms)",
                    20: "ReinitializeDevice (reboot/factory)",
                    6: "AtomicWriteFile"}

# --- Omron FINS command codes (MRC/SRC) -------------------------------------
OMRON_FINS = {
    "0101": "Memory Area Read", "0102": "Memory Area Write",
    "0103": "Memory Area Fill", "0401": "Run", "0402": "Stop",
    "0501": "CPU Unit Data Read", "0601": "CPU Unit Status Read",
    "0701": "Clock Read", "2101": "Error Clear", "2201": "File Name Read",
    "2306": "Program Area Write",
}
OMRON_DANGEROUS = {"0401": "Run", "0402": "Stop", "2306": "Program Area Write"}

# --- Protocols considered inherently unauthenticated/cleartext in OT --------
# (name -> (severity_hint, note)) used for the "insecure-by-design" finding.
INSECURE_OT_PROTOCOLS = {
    "modbus": "Modbus/TCP has no authentication, authorization or encryption.",
    "dnp3": "DNP3 (without Secure Authentication) is unauthenticated.",
    "s7comm": "S7comm/S7-0x32 is unauthenticated (legacy S7-300/400).",
    "enip": "EtherNet/IP + CIP has no built-in authentication.",
    "cip": "CIP has no built-in authentication.",
    "iec60870_104": "IEC 60870-5-104 is unauthenticated and cleartext.",
    "bacapp": "BACnet/IP has no authentication by default.",
    "goose": "IEC 61850 GOOSE is L2 multicast with no authentication.",
    "sv": "IEC 61850 Sampled Values are unauthenticated multicast.",
    "omron": "Omron FINS is unauthenticated.",
    "pn_dcp": "PROFINET DCP is unauthenticated L2 discovery/config.",
    "hart_ip": "HART-IP typically runs without authentication.",
}

# Well-known OT service ports -> protocol label (for role/asset inference).
OT_PORTS = {
    502: "modbus", 20000: "dnp3", 102: "s7comm", 44818: "enip",
    2222: "enip-io", 2404: "iec60870-104", 47808: "bacnet",
    4840: "opcua", 1883: "mqtt", 8883: "mqtts", 5094: "hart-ip",
    20547: "proconos", 1962: "pcworx", 789: "redlion-crimson",
    9600: "omron-fins", 18245: "ge-srtp", 18246: "ge-srtp",
    1911: "niagara-fox", 4911: "niagara-foxs", 34962: "profinet-rt",
    34964: "profinet-cm", 2455: "codesys", 11740: "codesys-v3",
}

# Cleartext IT management services that are high-risk inside OT zones.
CLEARTEXT_MGMT = {21: "FTP", 23: "Telnet", 69: "TFTP", 80: "HTTP",
                  161: "SNMP", 512: "rexec", 513: "rlogin", 514: "rsh",
                  5900: "VNC", 11211: "memcached"}
