
# Continuing to Do — Outstanding Work Items

> **Status:** 18 outstanding work items across three categories.  
> **Scope:** Target-specific constants, lab validation, and project hygiene.

---

## A. Missing Constants

**7 items** · Must be confirmed per target, mostly one header fetch away.

| # | Item | Where to Get It | Why It Matters |
|:--:|---|---|---|
| **01** | **Exact `EAP_WPS_AP_STATE` struct layout**<br>Real offsets of `total_bytes_to_recv`, `total_received`, `next_frag_to_send`, `frag_size`, `eap_id`, `state`, `last_sent`, `msg_to_send`, `parse_msg`, `send_data`, plus compiler padding. | `ap_eap_sm.h` (same directory as `ap_eap_sm.c`) and Ghidra analysis of the target's `wps_monitor` binary. | All `OFF_*` constants are inferred. Incorrect offsets may cause a crash instead of control. |
| **02** | **`WPS_EAP_DATA_MAX_LENGTH`**<br>Determine the exact constant value. | `wps_staeap.h` / `wps_api.h` in the WPS SDK. | Only needed on patched firmware, where the declared total is capped. Pre-patch versions are unchecked. |
| **03** | **`EAP_WPS_FLAGS_LF` / `EAP_WPS_FLAGS_MF`**<br>Confirm exact bit values. | WPS headers alongside `ap_eap_sm.c`. | v5 assumes `MF=0x01` and `LF=0x02` (WSC specification). Reversed values would break fragmentation. |
| **04** | **`WPS_FRAG_ACK` opcode**<br>Confirm opcode number and other opcode enumerations. | `wps_common.h` / `eap_wsc.h`. | The leak trigger and EAP-ID discipline depend on the exact opcode. |
| **05** | **`EAP_WPS_FRAG_MAX`**<br>Confirm default `eap_frag_threshold`. | WPS headers. | Determines the maximum leak length per FRAG_ACK round. |
| **06** | **`system@PLT` address (ARM)** | Ghidra: PLT entry for `system` in the non-PIE `wps_monitor` binary. | Fixed hijack target. |
| **07** | **`printf` GOT entry and libc offsets (MIPS)**<br>Determine `printf` GOT address and libc `printf` / `system` offsets. | Ghidra and the exact libc shipped with the firmware. | Required for ret2libc address derivation on MIPS. |

---

## B. Fuzzer & Calibration — Lab Device

**6 items** · Validation against an owned or explicitly authorized laboratory device.

| # | Task | Validation Notes |
|:--:|---|---|
| **08** | **Run `phase_calibrate` and refine deltas** | Confirm the inferred `OFF_NEXT_FRAG` offset and establish the state-relative relationship used for absolute addressing. |
| **09** | **Verify filler arithmetic in `phase_bypass_2018patch`** | `total_received` must equal **2048** before the length-13 fragment. Otherwise, the 63-byte tail reaches the wrong field. Account precisely for header and LF consumption on each firmware version. |
| **10** | **Verify first-FRAG_ACK special case** | `ap_eap_sm_sta_retrans` advances `next_frag_to_send` differently on the first ACK. Account for that initial ACK before armed leaks. |
| **11** | **Confirm MAC-prefix command trick survives timer resends** | `last_sent` may reference `msg_to_send`, whose header is rebuilt between transmissions. Verify whether the `#` comment survives. |
| **12** | **Test `wl actframe` shell-channel decoding** | Slide 93 specifies `"\x7f\x02\x00\x00XOUT"+hex`. Adapt `phase_shell` if the actual vendor payload differs. |
| **13** | **RF reliability soak test** | Validate under an attenuated RF link. Existing mechanisms: retry-frame acceptance, bounded EAPOL-Start/Identity retransmission, and **4 × 500-byte** MAC fragments. |

---

## C. Housekeeping & Project Hygiene

**5 items** · Code quality, privacy, legal boundaries, and upstream integration.

| # | Task | Notes |
|:--:|---|---|
| **14** | **Deduplicate `phase_fingerprint`** | v5 sends the probe twice due to a leftover code path. Ensure a single transmission and verify EAP-Failure handling. |
| **15** | **Sanitize output PCAPs before sharing** | Pseudonymize BSSID, SSID, serial numbers, UUID-E, and timestamps. Prefer the JSON result format recommended by Kaiser. |
| **16** | **Document legal boundaries** | Active testing only against owned or explicitly authorized devices. Relevant German criminal-law risks include §§ 202a, 202b, 202c StGB; memory corruption may additionally implicate §§ 303a, 303b StGB. |
| **17** | **Upstream contribution — Wifit3 PR** | Start with detection functionality: fingerprinting and Broadlin IE marking. Keep exploit phases lab-only. Include appropriate attribution to Kaiser's research under the applicable license. |
| **18** | **Preserve original sources** | Reference Kaiser's blog and slides, the public `ap_eap_sm.c` (2011, `$Id 279189`), and the **2026-10-23** patch-reconstruction article in derived work. |

---

## Progress Tracker

- [ ] **01–07:** Confirm target-specific constants and binary offsets.
- [ ] **08–13:** Complete laboratory calibration and reliability validation.
- [ ] **14:** Remove duplicate fingerprint transmissions.
- [ ] **15:** Implement PCAP sanitization.
- [ ] **16:** Document legal testing boundaries.
- [ ] **17:** Prepare detection-only upstream contribution.
- [ ] **18:** Preserve source references and attribution.

### Completion Summary

| Category | Outstanding | Completed |
|---|:---:|:---:|
| A. Missing Constants | 7 | 0 |
| B. Fuzzer & Calibration | 6 | 0 |
| C. Housekeeping & Hygiene | 5 | 0 |
| **Total** | **18** | **0** |

---

*All findings and test results must be validated against the exact firmware build and target architecture. Exploit-related testing is restricted to authorized laboratory environments.*
