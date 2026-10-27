"""Read selected handlers from this lab's ELF relocation-backed PHP function table."""
import json
import struct
import sys
from pathlib import Path


def handlers(path):
    data = Path(path).read_bytes()
    if len(data) > 64 * 1024 * 1024 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected bounded ELF64 little-endian module')
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
    loads = []
    for i in range(phnum):
        kind, flags, offset, address, physical, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        if kind == 1:
            loads.append((offset, address, filesz, flags))
    relocations = {}
    for i in range(shnum):
        entry = struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
        if entry[1] != 4:
            continue
        for pos in range(entry[4], entry[4] + entry[5], entry[9]):
            address, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                relocations[address] = addend
    found = {}
    for name in ('system',):
        needle = name.encode() + b'\0'
        positions = []
        cursor = 0
        while True:
            cursor = data.find(needle, cursor)
            if cursor == -1:
                break
            positions.append(cursor)
            cursor += len(needle)
        pointers = set()
        for pos in positions:
            for offset, address, size, flags in loads:
                if offset <= pos < offset + size:
                    pointers.add(address + pos - offset)
        matches = []
        for location, pointer in relocations.items():
            if pointer in pointers and location + 8 in relocations:
                handler = relocations[location + 8]
                if any(address <= handler < address + size and flags & 1 for offset, address, size, flags in loads):
                    matches.append(handler)
        if len(set(matches)) != 1:
            raise ValueError(f'nonunique {name} handler: {matches}')
        found[name] = matches[0]
    return found


if __name__ == '__main__':
    print(json.dumps({name: hex(value) for name, value in handlers(sys.argv[1]).items()}, indent=2))
