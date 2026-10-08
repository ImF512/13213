#!/bin/bash
# mac_session_kit.sh - run INSIDE the GitHub Actions mac session (or any mac):
# installs the RE toolchain + fetches the decrypted module + runs the analysis.
set -euo pipefail

echo "=== 1. toolchain ==="
which lldb clang python3 || true
python3 -m pip install --quiet capstone 2>/dev/null || echo "pip offline - ok, lldb suffices"
# the analysis python (uploaded with the repo)
ls -la mac_analyze.py 2>/dev/null || echo "upload mac_analyze.py to the repo first"

echo "=== 2. fetch the decrypted mac module (from this session's extraction) ==="
# if uploaded to the repo:
ls -la EAC_mac_decrypted.bin 2>/dev/null || echo "(upload EAC_mac_decrypted.bin = the file from C:\EAC_Dumps\Dump_20261008_202600\EAC_Launcher_decrypted.dll)"

echo "=== 3. static map of the derive flow ==="
python3 - <<'PY'
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
P = "EAC_mac_decrypted.bin"
data = open(P, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
# find the derive-keys marker + the xref (the same mapping as Windows-side)
marker = data.find(b"<= derive keys")
print(f"marker @ {marker:#x}")
# __TEXT = fileoff 0; scan for the rip-ref
va = marker
for i in range(len(data) - 7):
    if data[i] == 0x48 and data[i+1] in (0x8D, 0x89, 0x8B) and data[i+2] == 0x05:
        disp = struct.unpack_from("<i", data, i+3)[0]
        if i + 7 + disp == va:
            print(f"xref @ {i:#x}")
    elif data[i] in (0x8D, 0x89, 0x8B) and data[i+1] == 0x05:
        disp = struct.unpack_from("<i", data, i+2)[0]
        if i + 6 + disp == va:
            print(f"xref @ {i:#x}")
print("map done")
PY

echo "=== 4. lldb ready for the dynamic trace (run the module if present) ==="
echo "session kit complete"
