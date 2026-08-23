"""Print the imported DLLs of a PE file. Used to verify winmm.dll /
avicap32.dll are NOT in the agent's IAT after the dynamic-load refactor."""
import struct, sys

def imports(path):
    with open(path, 'rb') as f:
        b = f.read()
    e_lfanew = struct.unpack_from('<I', b, 0x3C)[0]
    nt = e_lfanew
    assert b[nt:nt+4] == b'PE\x00\x00', 'not a PE file'
    coff = nt + 4
    num_sections = struct.unpack_from('<H', b, coff+2)[0]
    opt_size = struct.unpack_from('<H', b, coff+16)[0]
    opt = coff + 20
    magic = b[opt]
    # Data directory 1 is imported DLLs
    # PE32: EDATA starts at opt+96, each dir is 8 bytes (RVA, size)
    # PE32+: starts at opt+112
    if magic == 0x0b:
        dir_base = opt + 96
    else:
        dir_base = opt + 112
    import_rva = struct.unpack_from('<I', b, dir_base + 1*8)[0]
    sec_off = opt + opt_size
    sections = []
    for i in range(num_sections):
        s = sec_off + i*40
        name = b[s:s+8].rstrip(b'\x00').decode('ascii', 'replace')
        vsize = struct.unpack_from('<I', b, s+8)[0]
        va = struct.unpack_from('<I', b, s+12)[0]
        rawsz = struct.unpack_from('<I', b, s+16)[0]
        rawoff = struct.unpack_from('<I', b, s+20)[0]
        sections.append((name, va, vsize, rawsz, rawoff))
    def rva_to_off(rva):
        for n, va, vs, ro, rs in sections:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None
    offs = rva_to_off(import_rva)
    if offs is None:
        return []
    iats = []
    while True:
        name_rva = struct.unpack_from('<I', b, offs + 12)[0]
        if name_rva == 0:
            # check the FirstThunk too, the OLT==0 sentinel is the proper
            # terminator, but namerva==0 happens on the same descriptor
            olt = struct.unpack_from('<I', b, offs)[0]
            if olt == 0:
                break
        no = rva_to_off(name_rva)
        if no is not None:
            nstr = b[no:no+32].split(b'\x00')[0].decode('ascii', 'replace')
            iats.append(nstr)
        offs += 20
        # crude stop after a descriptor with all-zero fields
        ft = struct.unpack_from('<I', b, offs)[0]
        if ft == 0:
            break
    return iats

if __name__ == '__main__':
    iats = imports(sys.argv[1])
    print('Imported DLLs:')
    for n in iats:
        print(' ', n)
    print()
    print('winmm in IAT:', any('winmm' in s.lower() for s in iats))
    print('avicap in IAT:', any('avicap' in s.lower() for s in iats))
