import os
import random

def create_fake_clean():
    """
    Write raw bytes that look like a low-entropy PE file.
    Uses repetitive patterns like real compiled code.
    """
    # MZ header magic bytes
    data = bytearray()
    
    # MZ signature
    data += b'MZ'
    # Pad to 64 bytes, with PE offset at byte 60
    data += b'\x00' * 58
    data += b'\x40\x00\x00\x00'  # PE header at offset 0x40
    
    # PE signature
    data += b'PE\x00\x00'
    
    # COFF machine header (x64)
    data += b'\x64\x86'          # machine: x64
    data += b'\x01\x00'          # 1 section
    data += b'\x00' * 12         # timestamp, symbol table, num symbols
    data += b'\xf0\x00'          # optional header size = 240
    data += b'\x02\x00'          # characteristics
    
    # Optional header magic (PE32+)
    data += b'\x0b\x02'
    # Pad optional header to 240 bytes
    data += b'\x00' * 238
    
    # Section header: .text
    data += b'.text\x00\x00\x00'          # name (8 bytes)
    data += b'\x00\x10\x00\x00'           # virtual size = 0x1000
    data += b'\x00\x10\x00\x00'           # virtual address = 0x1000
    data += b'\x00\x10\x00\x00'           # raw size = 0x1000
    data += b'\x00\x04\x00\x00'           # raw data offset = 0x400
    data += b'\x00' * 12                  # relocs, line numbers
    data += b'\x20\x00\x00\x60'           # characteristics: code, executable
    
    # Pad to offset 0x400 (where section data starts)
    while len(data) < 0x400:
        data += b'\x00'
    
    # LOW entropy section data: repeating instruction patterns
    # Real x86-64 code repeats opcodes heavily
    pattern = (
        b'\x55\x48\x89\xe5'   # push rbp; mov rbp, rsp
        b'\x48\x83\xec\x20'   # sub rsp, 0x20
        b'\x90\x90\x90\x90'   # NOP NOP NOP NOP
        b'\x48\x8b\x45\x08'   # mov rax, [rbp+8]
        b'\x5d\xc3\x00\x00'   # pop rbp; ret; padding
    )
    
    section_data = (pattern * (0x1000 // len(pattern) + 1))[:0x1000]
    data += section_data
    
    with open('fake_clean.exe', 'wb') as f:
        f.write(data)
    
    print(f"Created: fake_clean.exe  ({len(data)} bytes)")


def create_fake_packed():
    """
    Write raw bytes that look like a UPX-packed PE file.
    Uses random bytes to simulate encrypted/compressed payload.
    """
    data = bytearray()
    
    # MZ signature
    data += b'MZ'
    data += b'\x00' * 58
    data += b'\x40\x00\x00\x00'  # PE header at offset 0x40
    
    # PE signature
    data += b'PE\x00\x00'
    
    # COFF machine header (x64)
    data += b'\x64\x86'          # machine: x64
    data += b'\x02\x00'          # 2 sections
    data += b'\x00' * 12
    data += b'\xf0\x00'          # optional header size
    data += b'\x02\x00'          # characteristics
    
    # Optional header
    data += b'\x0b\x02'
    data += b'\x00' * 238
    
    # Section 1: UPX0 (zero data, just a placeholder — all zeros)
    data += b'UPX0\x00\x00\x00\x00'      # name
    data += b'\x00\x30\x00\x00'           # virtual size = 0x3000
    data += b'\x00\x10\x00\x00'           # virtual address
    data += b'\x00\x00\x00\x00'           # raw size = 0 (no raw data)
    data += b'\x00\x00\x00\x00'           # raw data pointer = 0
    data += b'\x00' * 12
    data += b'\xe0\x00\xe0\xe0'           # characteristics: all flags set
    
    # Section 2: UPX1 (HIGH entropy — the packed payload)
    data += b'UPX1\x00\x00\x00\x00'      # name
    data += b'\x00\x10\x00\x00'           # virtual size
    data += b'\x00\x40\x00\x00'           # virtual address
    data += b'\x00\x10\x00\x00'           # raw size = 0x1000
    data += b'\x00\x04\x00\x00'           # raw data offset = 0x400
    data += b'\x00' * 12
    data += b'\xe0\x00\xe0\xe0'
    
    # Pad to offset 0x400
    while len(data) < 0x400:
        data += b'\x00'
    
    # HIGH entropy data: pure random bytes (simulates encrypted payload)
    random.seed(99)
    high_entropy_section = bytes([random.randint(0, 255) for _ in range(0x1000)])
    data += high_entropy_section
    
    with open('fake_packed.exe', 'wb') as f:
        f.write(data)
    
    print(f"Created: fake_packed.exe ({len(data)} bytes)")


# ---- Run both ----
print("Creating test PE files...\n")
create_fake_clean()
create_fake_packed()

print("\nDone. Now run:")
print("  python pe_entropy.py fake_clean.exe")
print("  python pe_entropy.py fake_packed.exe")