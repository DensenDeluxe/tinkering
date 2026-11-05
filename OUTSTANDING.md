# Outstanding Work Items

This document tracks outstanding work items for the WPSplinter project.

**Last Updated**: 2026-11-05  
**Total Outstanding**: 18 items across 3 categories

---

## Progress Summary

| Category | Outstanding | Completed |
|----------|:-----------:|:---------:|
| A. Missing Constants | 7 | 0 |
| B. Fuzzer & Calibration | 6 | 0 |
| C. Housekeeping & Hygiene | 5 | 0 |
| **Total** | **18** | **0** |

---

## A. Missing Constants

Target-specific values that must be confirmed per firmware build.

### A.01 - Exact `EAP_WPS_AP_STATE` Struct Layout

**Priority**: High  
**Status**: Pending

**Description**:  
Determine real offsets of all struct members including compiler padding.

**Current Inferred Values**:
```c
+2048: total_bytes_to_recv
+2052: total_received
+2056: next_frag_to_send
+2060: frag_size
+2076: flags
+2080: last_sent
+2084: last_sent_len
+2108: send_data
```

**How to Confirm**:
1. Examine `ap_eap_sm.h` in target firmware
2. Run Ghidra on `wps_monitor` binary
3. Compare struct sizes and alignments

**Impact**: Incorrect offsets may cause crashes instead of controlled overflow.

---

### A.02 - `WPS_EAP_DATA_MAX_LENGTH`

**Priority**: Medium  
**Status**: Pending

**Description**:  
Determine exact constant value for patched firmware cap.

**Current Value**: 2048 (unpatched)

**How to Confirm**:  
Search `wps_stateap.h` or `wps_api.h` in WPS SDK.

**Impact**: Only needed on patched firmware where declared total is capped.

---

### A.03 - `EAP_WPS_FLAGS_LF` / `EAP_WPS_FLAGS_MF`

**Priority**: High  
**Status**: Pending

**Description**:  
Confirm exact bit values for Length Field and More Fragments flags.

**Current Assumption**: MF=0x01, LF=0x02 (WSC specification)

**How to Confirm**:  
Check WPS headers alongside `ap_eap_sm.c`.

**Impact**: Reversed values would break fragmentation handling.

---

### A.04 - `WPS_FRAG_ACK` Opcode

**Priority**: High  
**Status**: Pending

**Description**:  
Confirm opcode number and other opcode enumerations.

**Current Value**: 0x03

**How to Confirm**:  
Check `wps_common.h` or `eap_wsc.h`.

**Impact**: Leak trigger and EAP-ID discipline depend on exact opcode.

---

### A.05 - `EAP_WPS_FRAG_MAX`

**Priority**: Medium  
**Status**: Pending

**Description**:  
Confirm default `eap_frag_threshold` value.

**Current Value**: 1500 (assumed)

**How to Confirm**:  
Check WPS headers for default definition.

**Impact**: Determines maximum leak length per FRAG_ACK round.

---

### A.06 - `system@PLT` Address (ARM)

**Priority**: High  
**Status**: Pending per target

**Description**:  
Determine PLT entry address for `system` function.

**How to Confirm**:
```bash
# On target router
nm /usr/sbin/wps-monitor | grep system
```

**Example (ASUS RT-N66U)**: 0x27683

**Impact**: Required for ARM exploit function pointer hijack.

---

### A.07 - `printf` GOT Entry and libc Offsets (MIPS)

**Priority**: High  
**Status**: Pending per target

**Description**:  
Determine GOT entry address and libc function offsets.

**How to Confirm**:
```bash
# GOT entry
nm /usr/sbin/wps-monitor | grep printf

# libc base
cat /proc/self/maps | grep libc

# Calculate offsets
printf_off = printf_addr - libc_base
system_off = system_addr - libc_base
```

**Impact**: Required for MIPS ret2libc address derivation.

---

## B. Fuzzer & Calibration — Lab Device

Validation tasks requiring access to owned or authorized hardware.

### B.08 - Run `phase_calibrate` and Refine Deltas

**Priority**: High  
**Status**: Pending

**Description**:  
Confirm inferred `OFF_NEXT_FRAG` offset and establish state-relative addressing.

**Validation Steps**:
1. Run calibrate phase on lab device
2. Compare measured vs. expected timing
3. Adjust offsets if needed

---

### B.09 - Verify Filler Arithmetic in `phase_bypass_2018patch`

**Priority**: High  
**Status**: Pending

**Description**:  
`total_received` must equal **2048** before the length-13 fragment.

**Validation Steps**:
1. Trace fragment consumption
2. Account for header and LF bytes
3. Verify `total_received == 2048` at bypass point

**Impact**: Wrong offset causes 63-byte tail to reach wrong field.

---

### B.10 - Verify First-FRAG_ACK Special Case

**Priority**: Medium  
**Status**: Pending

**Description**:  
`ap_eap_sm_sta_retrans` advances `next_frag_to_send` differently on first ACK.

**Validation Steps**:
1. Capture first FRAG_ACK exchange
2. Compare pointer advancement
3. Adjust leak timing if needed

---

### B.11 - Confirm MAC-Prefix Command Trick Survives Timer Resends

**Priority**: Medium  
**Status**: Pending

**Description**:  
`last_sent` may reference `msg_to_send`, whose header is rebuilt between transmissions.

**Validation Steps**:
1. Trigger timer resend
2. Capture rebuilt packet
3. Verify `#` comment survives

---

### B.12 - Test `wl actframe` Shell-Channel Decoding

**Priority**: Low  
**Status**: Pending

**Description**:  
Slide 93 specifies `"\x7f\x02\x00\x00XOUT"+hex` format.

**Validation Steps**:
1. Send test payload via actframe
2. Verify router decodes correctly
3. Adapt `phase_shell` if format differs

---

### B.13 - RF Reliability Soak Test

**Priority**: Medium  
**Status**: Pending

**Description**:  
Validate under attenuated RF link conditions.

**Test Conditions**:
- Signal strength: -70 to -90 dBm
- Packet loss: 5-20%
- Duration: 30+ minutes

**Existing Mechanisms**:
- Retry-frame acceptance
- Bounded EAPOL-Start/Identity retransmission
- 4 × 500-byte MAC fragments

---

## C. Housekeeping & Project Hygiene

Code quality, privacy, legal boundaries, and upstream integration.

### C.14 - Deduplicate `phase_fingerprint`

**Priority**: Low  
**Status**: Pending

**Description**:  
v5 sends the probe twice due to a leftover code path.

**Fix**: Ensure single transmission and verify EAP-Failure handling.

---

### C.15 - Sanitize Output PCAPs Before Sharing

**Priority**: Medium  
**Status**: Pending

**Description**:  
Pseudonymize sensitive data in captured packets.

**Fields to Sanitize**:
- BSSID (MAC addresses)
- SSID (network names)
- Serial numbers
- UUID-E values
- Timestamps

**Recommendation**: Prefer JSON result format (Kaiser).

---

### C.16 - Document Legal Boundaries

**Priority**: High  
**Status**: In Progress

**Description**:  
Document testing boundaries and legal risks.

**German Criminal Law (StGB)**:
- § 202a: Data spying
- § 202b: Data snatching
- § 202c: Preparing data spying
- § 303a: Data manipulation
- § 303b: Computer sabotage

**Current Status**: Legal notice added to README.md

---

### C.17 - Upstream Contribution — Wifit3 PR

**Priority**: Low  
**Status**: Pending

**Description**:  
Start with detection functionality for upstream integration.

**Scope**:
- Fingerprinting
- Broadlin IE marking
- Keep exploit phases lab-only

**Attribution**: Include Kaiser's research under applicable license.

---

### C.18 - Preserve Original Sources

**Priority**: High  
**Status**: Completed ✅

**Description**:  
Reference all original sources in derived work.

**Sources Preserved**:
- Kaiser's blog and slides
- Public `ap_eap_sm.c` (2011, $Id 279189)
- 2026-10-23 patch-reconstruction article

---

## Completion Checklist

### A. Missing Constants
- [ ] A.01: Exact `EAP_WPS_AP_STATE` struct layout
- [ ] A.02: `WPS_EAP_DATA_MAX_LENGTH`
- [ ] A.03: `EAP_WPS_FLAGS_LF` / `EAP_WPS_FLAGS_MF`
- [ ] A.04: `WPS_FRAG_ACK` opcode
- [ ] A.05: `EAP_WPS_FRAG_MAX`
- [ ] A.06: `system@PLT` address (ARM)
- [ ] A.07: `printf` GOT entry and libc offsets (MIPS)

### B. Fuzzer & Calibration
- [ ] B.08: Run `phase_calibrate` and refine deltas
- [ ] B.09: Verify filler arithmetic in `phase_bypass_2018patch`
- [ ] B.10: Verify first-FRAG_ACK special case
- [ ] B.11: Confirm MAC-prefix command trick survives timer resends
- [ ] B.12: Test `wl actframe` shell-channel decoding
- [ ] B.13: RF reliability soak test

### C. Housekeeping
- [ ] C.14: Deduplicate `phase_fingerprint`
- [ ] C.15: Sanitize output PCAPs before sharing
- [ ] C.16: Document legal boundaries
- [ ] C.17: Upstream contribution — Wifit3 PR
- [x] C.18: Preserve original sources

---

## Notes

- All findings and test results must be validated against the exact firmware build and target architecture.
- Exploit-related testing is restricted to authorized laboratory environments.
- Update this document as items are completed or requirements change.
