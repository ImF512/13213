# mac_module_analyze.py - the decrypted macOS EAC module (the soft target)
import struct, collections, math, re

P = r"C:\EAC_Dumps\Dump_20261008_202600\EAC_Launcher_decrypted.dll"
data = open(P, "rb").read()
print(f"size: {len(data)}  magic: {data[:4].hex()}")

magic = struct.unpack_from("<I", data, 0)[0]
if magic == 0xFEEDFACF:   # MH_MAGIC_64
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)[0:2]
    print(f"Mach-O 64: {ncmds} load commands")
    off = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:   # LC_SEGMENT_64
            segname = data[off+8:off+24].rstrip(b"\x00").decode()
            vmaddr, vmsize = struct.unpack_from("<QQ", data, off+24)
            print(f"  SEG {segname}: vmaddr={vmaddr:#x} vmsize={vmsize:#x}")
        off += cmdsize
        if off + 8 > len(data):
            break
else:
    print("not a plain Mach-O (still wrapped?)")
    print("head:", data[:64].hex())

# entropy profile
def ent(b):
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())
for i in range(0, len(data) - 1, 512 * 1024):
    seg = data[i: i + 512 * 1024]
    if len(seg) > 0x10000:
        e = ent(seg)
        if e < 7.5:
            print(f"  low-entropy @ {i:#x}: {e:.2f}")

# strings
strs = set()
for m in re.finditer(rb"[\x20-\x7E]{8,70}", data):
    strs.add(m.group())
interesting = sorted(s for s in strs if any(k in s.lower() for k in
    (b"key", b"session", b"hmac", b"aes", b"chacha", b"sign", b"derive",
     b"token", b"sha", b"ed25519", b"curve", b"nonce", b"crypto", b"seal")))
print(f"\ninteresting strings: {len(interesting)}")
for s in interesting[:40]:
    print(f"  {s.decode('utf-8', 'ignore')[:80]}")
