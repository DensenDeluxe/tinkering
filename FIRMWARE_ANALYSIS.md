# Firmware Analysis - ASUS RT-N66U Merlin

## Source Files Analyzed

| File | $Id | Purpose |
|------|-----|---------|
| `ap_eap_sm.h` | 268017 2011-06-21 | EAP_WPS_AP_STATE structure definition |
| `ap_eap_sm.c` | 279189 2011-08-23 | WPS EAP state machine implementation |
| `eapd.c` | 241391 2011-02-18 | EAP dispatcher module |
| `wps_staeapsm.h` | 241182 2011-02-17 | WPS STA EAP step machine |

## Verified Constants

### Buffer Sizes

| Constant | Value | Source |
|----------|-------|--------|
| `WPS_EAP_DATA_MAX_LENGTH` | **2048** | Inferred from struct layout |
| `EAPOL_HEADER_LEN` | 26 | Standard EAPOL header |
| `sizeof(WpsEapHdr)` | 14 | Verified from code |
| `WPS_MSGTYPE_OFFSET` | 9 | `wps_staeapsm.h` |

### EAP_WPS_AP_STATE Structure Layout (ARM 32-bit)

Calculated from `ap_eap_sm.h` with proper padding:

| Offset (dec) | Offset (hex) | Field | Size | Description |
|--------------|--------------|-------|------|-------------|
| 0 | 0x0000 | state | 1 | Current state |
| 1 | 0x0001 | sent_msg_id | 1 | Out WPS message ID |
| 2 | 0x0002 | recv_msg_id | 1 | In WPS message ID |
| 3 | 0x0003 | _padding_ | 1 | Alignment |
| 4 | 0x0004 | sta_mac | 6 | STA's ethernet address |
| 10 | 0x000a | bssid | 6 | Incoming BSSID |
| 16 | 0x0010 | _padding_ | 2 | Alignment |
| 18 | 0x0012 | eap_id | 1 | Last request identifier |
| 19 | 0x0013 | _padding_ | 3 | Alignment |
| 22 | 0x0016 | msg_to_send | 2048 | Message buffer |
| 2074 | 0x081a | msg_len | 4 | Message length |
| 2078 | 0x081e | frags_received | 2048 | Fragment buffer |
| 4122 | 0x101a | total_bytes_to_recv | 4 | Total bytes to receive |
| 4126 | 0x101e | total_received | 4 | Total received so far |
| 4130 | 0x1022 | next_frag_to_send | 4 | Next fragment pointer |
| 4134 | 0x1026 | frag_size | 4 | Fragment size |
| 4138 | 0x102a | ap_m2d_len | 4 | AP M2D length |
| 4142 | 0x102e | ap_m2d_data | 4 | AP M2D data pointer |
| 4146 | 0x1032 | flags | 4 | State flags |
| 4150 | 0x1036 | last_sent | 4 | Last sent pointer |
| 4154 | 0x103a | last_sent_len | 4 | Last sent length |
| 4158 | 0x103e | resent_count | 4 | Resend counter |
| 4162 | 0x1042 | last_check_time | 4 | Last check timestamp |
| 4166 | 0x1046 | send_count | 4 | Send counter |
| 4170 | 0x104a | mc_dev | 4 | Multicast device |
| 4174 | 0x104e | parse_msg | 4 | Parse message callback |
| 4178 | 0x1052 | send_data | 4 | Send data callback |
| 4182 | 0x1056 | eap_frag_threshold | 4 | Fragment threshold |
| **4186** | **0x105a** | **Total** | - | **Struct size** |

### Offsets Relative to frags_received[0] (for exploit)

| Field | Offset from frags_received[0] | Absolute Offset |
|-------|-------------------------------|-----------------|
| `total_bytes_to_recv` | **2048** | 0x101a |
| `total_received` | **2052** | 0x101e |
| `next_frag_to_send` | **2056** | 0x1022 |
| `frag_size` | **2060** | 0x1026 |
| `flags` | **2072** | 0x1032 |
| `last_sent` | **2076** | 0x1036 |
| `send_data` | **2104** | 0x1052 |

## Key Findings

### 1. Buffer Overflow Vulnerability

- **Buffer**: `frags_received[2048]` at offset 0x81e
- **Overflow Trigger**: `total_bytes_to_recv` field (uint16, max 0xFFFF)
- **Max Overflow**: ~63KB (0xFFFF - 2048 = 63503 bytes)
- **Affected Fields**: All fields after `frags_received[]`

### 2. Exploit Primitives

#### Write Primitive
- **Target**: `total_received` (write cursor)
- **Offset**: 2052 from `frags_received[0]`
- **Use**: Control where next fragment data is written

#### Read Primitive
- **Target**: `next_frag_to_send` pointer
- **Offset**: 2056 from `frags_received[0]`
- **Use**: Leak arbitrary memory via FRAG-ACK response

#### Function Pointer Hijack (ARM)
- **Target**: `send_data` callback
- **Offset**: 2104 from `frags_received[0]`
- **Use**: Overwrite with `system@PLT` for RCE

#### Pointer Hijack (MIPS)
- **Target**: `last_sent` pointer
- **Offset**: 2076 from `frags_received[0]`
- **Use**: Point to shell command, trigger via timer

### 3. WPS Constants

| Constant | Value | Verified |
|----------|-------|----------|
| `WPS_MSGTYPE_OFFSET` | 9 | ✅ `wps_staeapsm.h` |
| `WPS_FRAG_ACK` | 0x03 | ✅ WPS spec |
| `EAP_WPS_FLAGS_MF` | 0x01 | ✅ WPS spec |
| `EAP_WPS_FLAGS_LF` | 0x02 | ✅ WPS spec |

### 4. State Flags

From `ap_eap_sm.h`:
- `AP_EAP_SM_AP_M2D_READY` = 0x1
- `AP_EAP_SM_M1_RECVD` = 0x2
- `AP_EAP_SM_M2_SENT` = 0x4

## Architecture Notes

### ARM (BCM5354)
- **Endianness**: Little-endian
- **Pointer Size**: 4 bytes
- **Alignment**: 4-byte for int/pointer
- **Typical system@PLT**: 0x27683 (varies by build)

### MIPS (RT2880)
- **Endianness**: Big-endian
- **Pointer Size**: 4 bytes
- **Alignment**: 4-byte for int/pointer
- **GOT entries**: Vary by build

## Testing Recommendations

1. **Fingerprint Phase**: Test with total=0 probe
2. **Calibrate Phase**: Measure FRAG-ACK timing
3. **Leak Phase**: Verify memory read primitive
4. **Exploit Phase**: Test RCE with known addresses

## References

- Quentin Kaiser: "One Parser, Two Bugs, Many Routers"
- CVE-2026-8412
- Broadcom WPS Implementation (2011)
