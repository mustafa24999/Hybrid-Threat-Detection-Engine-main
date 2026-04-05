# tests/generate_samples.py
# Generates "malicious" but safe test samples for heuristic verification.
import os
from pathlib import Path

def generate():
    test_dir = Path("test_samples")
    test_dir.mkdir(exist_ok=True)

    # 1. PDF with Embedded JS
    with open(test_dir / "sample_js.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert('Zenith Test');) >> >>\nendobj")

    # 2. Office Doc with VBA markers
    with open(test_dir / "sample_macro.docm", "wb") as f:
        f.write(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"VBA_Project" + b"\x00" * 100 + b"macro")

    # 3. Malformed PE (Missing signature)
    with open(test_dir / "malformed_pe.exe", "wb") as f:
        header = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00") # e_lfanew points to 0x40
        header.extend(b"NOT_PE") # Should be "PE\0\0"
        f.write(header + b"\x00" * 1024)

    # 4. Binary in Text Mask
    with open(test_dir / "mask_test.txt", "wb") as f:
        f.write(b"Normal text" + b"\x00" * 10 + b"Binary payload")

    # 5. High Entropy File
    with open(test_dir / "high_entropy.bin", "wb") as f:
        f.write(os.urandom(10240))

    print(f"Generated 5 test samples in {test_dir}/")

if __name__ == "__main__":
    generate()
