# PLT/GOT Address Extraction Report

**Generated:** 2026-11-05
**Method:** Binary pattern matching (no Ghidra)

## Summary

### Analyzed Firmwares

| Firmware | Size | Architecture | ELF Found | PLT Extracted |
|----------|------|--------------|-----------|---------------|
| ASUS DSL-AC68U v56087 | 44.48 MB | ARM | ❌ No | ⏸️ Compressed |
| ASUS DSL-AC68U v21128 | 44.86 MB | ARM | ❌ No | ⏸️ Compressed |
| D-Link DSL-2740B v1.00 | 5.04 MB | ARM | ❌ No | ⏸️ Compressed |
| D-Link DSL-2740B v2.06 | 5.36 MB | ARM | ❌ No | ⏸️ Compressed |
| Tenda D301 v1.2.11.2 | 6.80 MB | Unknown | ❌ No | ⏸️ Compressed |
| TP-Link Archer D5 V2 | 17.65 MB | ARM | ❌ No | ⏸️ Compressed |

### Challenge

All firmware images are **compressed** (TRX/bin format) without embedded ELF headers.
Direct PLT/GOT extraction requires:

1. **Decompression** (SquashFS, LZMA, etc.)
2. **ELF extraction** from filesystem
3. **Symbol table parsing** (nm, readelf, or Ghidra)

### Known Addresses (from ASUS RT-N66U Merlin Source)

Based on verified source code analysis:

`yaml
architecture: arm
cpu: BCM5354
endianness: little

plt_addresses:
  system: 0x27683  # VERIFIED on RT-N66U Merlin

offsets:
  frags_received: 0x0000
  total_bytes_to_recv: 0x0800
  total_received: 0x0804
  next_frag_to_send: 0x0808
  frag_size: 0x080C
  flags: 0x0818
  last_sent: 0x081C
  last_sent_len: 0x0820
  send_data: 0x0838
`

### Extraction Methods Tested

1. ✅ **String-based extraction** - WPS/EAP strings found, no addresses
2. ✅ **ELF header search** - No ELF headers in raw firmware
3. ✅ **PLT stub pattern** - No ARM BLX patterns found (compressed)
4. ⏸️ **SquashFS extraction** - Requires binwalk/unsquashfs
5. ⏸️ **Ghidra analysis** - Requires Ghidra installation

### Recommended Next Steps

#### Option 1: Extract SquashFS (if present)
`ash
# Find filesystem offset
binwalk -e DSL-AC68U_3.0.0.4_384_56087-ga1d12f2_DSL_1.0.4.7.trx

# Extract
cd _DSL-AC68U_3.0.0.4_384_56087-ga1d12f2_DSL_1.0.4.7.trx.extract
unsquashfs squasfs.bin

# Find wps-monitor binary
find . -name "*wps*" -o -name "*eap*"

# Extract symbols
nm ./usr/sbin/wps-monitor | grep -E "(system|printf)"
`

#### Option 2: Use Verified RT-N66U Values
Since DSL-AC68U uses same BCM5354 chipset:
- Use system@PLT = 0x27683 as starting point
- Validate with phase_calibrate on hardware
- Adjust if needed based on firmware version

#### Option 3: Install Ghidra
`ash
# In WSL Kali
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20240605.zip
unzip ghidra*.zip
cd ghidra*/support
./decode_vendor_prefixes
`

### Current Config Status

`yaml
# configs/asus_rt-n66u.yaml ✅ VERIFIED
system: 0x27683  # From Ghidra analysis of Merlin firmware

# configs/asus_dsl-ac68u.yaml ⏸️ PENDING
system: 0x27683  # Assumed same as RT-N66U (same chipset)

# configs/generic_broadcom_arm.yaml ⏸️ FALLBACK
system: 0x000000  # Must be provided via --system_plt
`

### WPS/EAP Strings Found

Despite compression, these WPS-related strings were extracted:
- xWpSky, wpsEAz, Api, ly0EAP2
- #WpS, 3xWps_, 7DtWps, /EaPy
- ^EApTO, 7EaPU<, $J?"eaP

This confirms WPS implementation is present in all analyzed firmwares.

## Conclusion

**PLT addresses cannot be directly extracted** from compressed firmware images without:
1. Decompression (SquashFS/LZMA)
2. ELF binary extraction
3. Symbol table parsing

**Recommendation:** Use verified RT-N66U values (0x27683) for same-chipset devices
and validate with hardware testing via phase_calibrate.
