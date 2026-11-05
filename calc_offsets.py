import struct
import sys

# ARM 32-bit (little-endian) - wie im ASUS RT-N66U Merlin
# MIPS 32-bit (big-endian) - wie in Ralink Routern

def calculate_offsets_arm():
    """Berechne Offsets für ARM 32-bit (little-endian)"""
    offsets = {}
    current_offset = 0
    
    # char state
    offsets['state'] = current_offset
    current_offset += 1
    
    # char sent_msg_id
    offsets['sent_msg_id'] = current_offset
    current_offset += 1
    
    # char recv_msg_id
    offsets['recv_msg_id'] = current_offset
    current_offset += 1
    
    # padding (1 byte für 4-Byte-Alignment)
    current_offset += 1
    
    # unsigned char sta_mac[6]
    offsets['sta_mac'] = current_offset
    current_offset += 6
    
    # unsigned char bssid[6]
    offsets['bssid'] = current_offset
    current_offset += 6
    
    # padding (2 bytes für 4-Byte-Alignment)
    current_offset += 2
    
    # unsigned char eap_id
    offsets['eap_id'] = current_offset
    current_offset += 1
    
    # padding (3 bytes für 4-Byte-Alignment)
    current_offset += 3
    
    # char msg_to_send[WPS_EAP_DATA_MAX_LENGTH] - 2048 bytes
    offsets['msg_to_send'] = current_offset
    msg_to_send_offset = current_offset
    current_offset += 2048
    
    # int msg_len
    offsets['msg_len'] = current_offset
    current_offset += 4
    
    # char frags_received[WPS_EAP_DATA_MAX_LENGTH] - 2048 bytes
    offsets['frags_received'] = current_offset
    frags_received_offset = current_offset
    current_offset += 2048
    
    # int total_bytes_to_recv
    offsets['total_bytes_to_recv'] = current_offset
    total_bytes_offset = current_offset
    current_offset += 4
    
    # int total_received
    offsets['total_received'] = current_offset
    total_received_offset = current_offset
    current_offset += 4
    
    # char *next_frag_to_send (pointer = 4 bytes on ARM 32-bit)
    offsets['next_frag_to_send'] = current_offset
    next_frag_offset = current_offset
    current_offset += 4
    
    # int frag_size
    offsets['frag_size'] = current_offset
    frag_size_offset = current_offset
    current_offset += 4
    
    # int ap_m2d_len
    offsets['ap_m2d_len'] = current_offset
    current_offset += 4
    
    # char *ap_m2d_data
    offsets['ap_m2d_data'] = current_offset
    current_offset += 4
    
    # int flags
    offsets['flags'] = current_offset
    flags_offset = current_offset
    current_offset += 4
    
    # char *last_sent
    offsets['last_sent'] = current_offset
    last_sent_offset = current_offset
    current_offset += 4
    
    # int last_sent_len
    offsets['last_sent_len'] = current_offset
    current_offset += 4
    
    # int resent_count
    offsets['resent_count'] = current_offset
    current_offset += 4
    
    # unsigned long last_check_time (4 bytes on ARM 32-bit)
    offsets['last_check_time'] = current_offset
    current_offset += 4
    
    # int send_count
    offsets['send_count'] = current_offset
    current_offset += 4
    
    # void *mc_dev
    offsets['mc_dev'] = current_offset
    current_offset += 4
    
    # char * (*parse_msg)(char *, int, int *)
    offsets['parse_msg'] = current_offset
    current_offset += 4
    
    # unsigned int (*send_data)(char *, uint32)
    offsets['send_data'] = current_offset
    send_data_offset = current_offset
    current_offset += 4
    
    # int eap_frag_threshold
    offsets['eap_frag_threshold'] = current_offset
    current_offset += 4
    
    struct_size = current_offset
    
    print("=" * 60)
    print("EAP_WPS_AP_STATE Struct Layout - ARM 32-bit (Little-Endian)")
    print("=" * 60)
    print(f"Total struct size: {struct_size} bytes")
    print()
    print("Key offsets for exploit:")
    print(f"  frags_received[0]         : 0x{frags_received_offset:04x} ({frags_received_offset})")
    print(f"  total_bytes_to_recv       : 0x{total_bytes_offset:04x} ({total_bytes_offset})")
    print(f"  total_received            : 0x{total_received_offset:04x} ({total_received_offset})")
    print(f"  next_frag_to_send         : 0x{next_frag_offset:04x} ({next_frag_offset})")
    print(f"  frag_size                 : 0x{frag_size_offset:04x} ({frag_size_offset})")
    print(f"  flags                     : 0x{flags_offset:04x} ({flags_offset})")
    print(f"  last_sent                 : 0x{last_sent_offset:04x} ({last_sent_offset})")
    print(f"  send_data                 : 0x{send_data_offset:04x} ({send_data_offset})")
    print()
    print("Offsets relative to frags_received[0]:")
    print(f"  total_bytes_to_recv       : {total_bytes_offset - frags_received_offset}")
    print(f"  total_received            : {total_received_offset - frags_received_offset}")
    print(f"  next_frag_to_send         : {next_frag_offset - frags_received_offset}")
    print(f"  frag_size                 : {frag_size_offset - frags_received_offset}")
    print(f"  flags                     : {flags_offset - frags_received_offset}")
    print(f"  last_sent                 : {last_sent_offset - frags_received_offset}")
    print(f"  send_data                 : {send_data_offset - frags_received_offset}")
    print()
    
    return offsets

calculate_offsets_arm()
