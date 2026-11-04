Continuing to Do — Outstanding Work Items
A. Missing constants (must be confirmed per target, mostly one header fetch away)
#	Item	Where to get it	Why it matters
1	Exact EAP_WPS_AP_STATE struct layout: real offsets of total_bytes_to_recv, total_received, next_frag_to_send, frag_size, eap_id, state, last_sent, msg_to_send, parse_msg, send_data, plus any compiler padding	ap_eap_sm.h (same repo dir as ap_eap_sm.c) and Ghidra analysis of the target's wps_monitor binary	All OFF_* constants are inferred; wrong offsets = crash instead of control
2	WPS_EAP_DATA_MAX_LENGTH value	wps_staeap.h / wps_api.h in the WPS SDK	Only needed on patched firmware (cap for declared total); pre-patch is unchecked
3	EAP_WPS_FLAGS_LF / EAP_WPS_FLAGS_MF bit values	WPS headers next to ap_eap_sm.c	v5 assumes MF=0x01, LF=0x02 (per WSC spec); a swap would break every fragment
4	WPS_FRAG_ACK opcode number and other opcode enums	wps_common.h / eap_wsc.h	The leak trigger and ID discipline depend on the exact opcode
5	EAP_WPS_FRAG_MAX (default eap_frag_threshold)	WPS headers	Determines max leak length per FRAG_ACK round
6	system@PLT address (ARM)	Ghidra: PLT entry of system in the non-PIE wps_monitor binary	The fixed hijack target
7	printf GOT entry address + libc printf/system offsets (MIPS)	Ghidra + the exact libc shipped in the firmware	ret2libc derivation on MIPS
B. Fuzzer/calibration work against a lab device
#	Task	Notes
8	Run phase_calibrate and refine deltas	Confirms the inferred OFF_NEXT_FRAG offset and yields the state-relative relationship for absolute addressing
9	Verify filler arithmetic in phase_bypass_2018patch	total_received must be exactly 2048 before the length-13 fragment, or the 63-byte tail lands on the wrong field; count header/LF consumption precisely per firmware
10	Verify first-FRAG_ACK special case in the leak flow	ap_eap_sm_sta_retrans advances next_frag_to_send differently on the first ACK; consume it before armed leaks
11	Confirm the MAC-prefix command trick survives timer resends	last_sent may point to msg_to_send whose header gets rebuilt between sends; check whether the # comment survives
12	Test wl actframe shell channel decode	Slide-93 format "\x7f\x02\x00\x00XOUT"+hex; adapt phase_shell if the real vendor payload differs
13	RF reliability soak test	Weak RF requires: retry-frame acceptance (already implemented), EAPOL-Start/Identity bounded retransmit (implemented), 4×500-byte MAC fragments (implemented); validate under attenuated link
C. Housekeeping / hygiene
#	Task	Notes
14	Deduplicate code paths phase_fingerprint (double send bug)	v5 sends the probe twice in phase_fingerprint (leftover); call only once and verify EAP-Failure
15	Sanitize output PCAPs before sharing	BSSID, SSID, serial numbers, UUID-E and timestamps must be pseudonymized; prefer the JSON result format Kaiser recommends
16	Legal boundary documentation	Active probes only against owned/authorized devices; § 202a/202b/202c StGB exposure in Germany; memory corruption additionally risks § 303a/303b
17	Upstream contribution (Wifit3 PR)	Detection part (fingerprint + Broadlin IE marking) is the clean first PR; exploit phases stay lab-only; MIT attribution of Kaiser's research
18	Preserve original sources	Cite Kaiser's blog/slides, the public ap_eap_sm.c (2011, $Id 279189) and the 2026-10-23 patch-reconstruction article in any derived work
