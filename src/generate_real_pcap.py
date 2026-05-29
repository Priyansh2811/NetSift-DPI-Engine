import struct
import random
import time

def build_real_tls_client_hello(domain_str):
    domain_bytes = domain_str.encode('utf-8')
    domain_len = len(domain_bytes)
    
    # 1. TLS Record Layer Header
    # Content Type: Handshake (0x16), Version: TLS 1.0 (0x03 0x01), Length placeholder
    record_header = bytearray([0x16, 0x03, 0x01, 0x00, 0x00]) 
    
    # 2. Handshake Layer Header
    # Handshake Type: Client Hello (0x01), Length placeholder
    handshake_header = bytearray([0x01, 0x00, 0x00, 0x00])
    
    # 3. Client Hello Core
    # Version: TLS 1.2 (0x03 0x03), Random Bytes (32 bytes)
    client_hello_core = bytearray([0x03, 0x03]) + bytearray(random.getrandbits(8) for _ in range(32))
    # Session ID Length: 0
    client_hello_core += bytearray([0x00])
    # Cipher Suites Length: 2 bytes (0x00 0x02), Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x00 0x9c)
    client_hello_core += bytearray([0x00, 0x02, 0x00, 0x9c])
    # Compression Methods Length: 1, Method: null (0x00)
    client_hello_core += bytearray([0x01, 0x00])
    
    # 4. Extensions Layer
    # Extensions Total Length placeholder
    extensions_header = bytearray([0x00, 0x00])
    
    # Server Name Indication (SNI) Extension
    # Extension Type: Server Name (0x00 0x00), Extension Length: domain_len + 9
    sni_ext_len = domain_len + 5
    sni_total_len = domain_len + 9
    
    sni_extension = bytearray([
        0x00, 0x00,                           # Extension Type (SNI)
        (sni_total_len >> 8) & 0xff, sni_total_len & 0xff, # Extension Length
        (sni_ext_len >> 8) & 0xff, sni_ext_len & 0xff,     # Server Name List Length
        0x00,                                 # Name Type: host_name (0)
        (domain_len >> 8) & 0xff, domain_len & 0xff        # Server Name Length
    ]) + domain_bytes
    
    # Block Assembling with exact mathematical byte length calculation
    total_extensions_len = len(sni_extension)
    extensions_header[0] = (total_extensions_len >> 8) & 0xff
    extensions_header[1] = total_extensions_len & 0xff
    
    full_handshake_payload = client_hello_core + extensions_header + sni_extension
    
    total_handshake_len = len(full_handshake_payload)
    handshake_header[1] = (total_handshake_len >> 16) & 0xff
    handshake_header[2] = (total_handshake_len >> 8) & 0xff
    handshake_header[3] = total_handshake_len & 0xff
    
    full_record_payload = handshake_header + full_handshake_payload
    
    total_record_len = len(full_record_payload)
    record_header[3] = (total_record_len >> 8) & 0xff
    record_header[4] = total_record_len & 0xff
    
    return bytes(record_header + full_record_payload)

def generate_1000_real_packets(filename="traffic_real_1000.pcap"):
    domains = [
        "google.com", "www.youtube.com", "github.com", "www.facebook.com",
        "www.instagram.com", "twitter.com", "discord.com", "web.telegram.org",
        "www.amazon.com", "zoom.us", "www.cloudflare.com", "www.netflix.com",
        "www.tiktok.com", "httpbin.org"
    ]
    
    print(f"[PCAP Engine] Injecting hex patterns for 1000 real-world simulated packets...")
    
    # Global Header standard configuration
    pcap_global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    with open(filename, "wb") as f:
        f.write(pcap_global_header)
        start_time = int(time.time()) - 10
        
        for i in range(1000):
            p_time_sec = start_time + (i // 100)
            p_time_usec = (i % 100) * 10000
            
            is_tcp = random.choices([True, False], weights=[85, 15])[0]
            
            # Headers setup
            eth_header = b"\x00\x0c\x29\x3e\x54\x7a\x00\x50\x56\xc0\x00\x08\x08\x00"
            ip_proto = b"\x06" if is_tcp else b"\x11"
            ip_header = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40" + ip_proto + b"\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
            transport_header = b"\x1f\x90\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x02\x00\x00\x00\x00\x00" if is_tcp else b"\x04\xd2\x04\xd2\x00\x08\x00\x00"
            
            # Real SNI data attachment loop
            sni_payload = b""
            if is_tcp and random.random() < 0.4:  # 40% chance of standard handshake data
                chosen_domain = random.choice(domains)
                sni_payload = build_real_tls_client_hello(chosen_domain)
            
            full_packet = eth_header + ip_header + transport_header + sni_payload
            packet_len = len(full_packet)
            
            packet_header = struct.pack("<IIII", p_time_sec, p_time_usec, packet_len, packet_len)
            f.write(packet_header)
            f.write(full_packet)
            
    print(f"[PCAP Engine] Success! Fresh '{filename}' generated with deep TLS headers structure.")

if __name__ == "__main__":
    generate_1000_real_packets()