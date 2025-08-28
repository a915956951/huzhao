import sys
from pathlib import Path


def read_len(data: bytes, idx: int):
    first = data[idx]
    if first < 0x80:
        return first, 1
    num_bytes = first & 0x7F
    val = 0
    for k in range(num_bytes):
        val = (val << 8) | data[idx + 1 + k]
    return val, 1 + num_bytes


def find_tag(data: bytes, tag_bytes: bytes) -> int:
    try:
        return data.index(tag_bytes)
    except ValueError:
        return -1


def analyze(label: str, raw: bytes):
    print(f"\n=== {label} ===")
    # 75 (DG2)
    i75 = find_tag(raw, b"\x75")
    if i75 < 0:
        print("Tag 75 not found")
        return
    l75, s75 = read_len(raw, i75 + 1)
    off75 = i75 + 1 + s75
    print(f"75: pos={i75} len={l75} hdr={1+s75}")

    # 7F61
    i61 = find_tag(raw, b"\x7F\x61")
    if i61 >= 0:
        l61, s61 = read_len(raw, i61 + 2)
        off61 = i61 + 2 + s61
        print(f"7F61: pos={i61} len={l61} hdr={2+s61}")
    else:
        print("7F61 not found")
        return

    # Expect first child: 0x02 0x01 0x01 (instance count)
    if raw[off61] == 0x02:
        count_len, count_len_size = read_len(raw, off61 + 1)
        count_val = raw[off61 + 1 + count_len_size : off61 + 1 + count_len_size + count_len]
        a_off = off61 + 1 + count_len_size + count_len
        print(f"Count field: len={count_len} val={count_val.hex()} next={a_off}")
    else:
        a_off = off61
        print("No count field at 7F61 start")

    # 7F60
    if raw[a_off:a_off+2] == b"\x7F\x60":
        i60 = a_off
    else:
        i60 = find_tag(raw, b"\x7F\x60")
    if i60 >= 0:
        l60, s60 = read_len(raw, i60 + 2)
        off60 = i60 + 2 + s60
        print(f"7F60: pos={i60} len={l60} hdr={2+s60}")
    else:
        print("7F60 not found")
        return

    # children of 7F60: A1 ... and 5F2E ...
    ia1 = find_tag(raw, b"\xA1")
    if ia1 >= 0:
        la1, sa1 = read_len(raw, ia1 + 1)
        print(f"A1: pos={ia1} len={la1} hdr={1+sa1}")
    else:
        la1 = 0
        sa1 = 0
        print("A1 not found")

    i2e = find_tag(raw, b"\x5F\x2E")
    if i2e >= 0:
        l2e, s2e = read_len(raw, i2e + 2)
        print(f"5F2E: pos={i2e} len={l2e} hdr={2+s2e}")
    else:
        print("5F2E not found")
        return

    # computed child totals
    ct60 = (1 + sa1) + la1 + (2 + s2e) + l2e
    print(f"7F60 child_total={ct60} declared={l60} delta={l60 - ct60}")

    ct61 = 0
    # include count field if present
    if raw[off61] == 0x02:
        count_len, count_len_size = read_len(raw, off61 + 1)
        ct61 += 1 + count_len_size + count_len
    ct61 += (2 + s60) + l60
    print(f"7F61 child_total={ct61} declared={l61} delta={l61 - ct61}")

    # CBEFF header inside 5F2E
    bio_off = i2e + 2 + s2e
    bio = raw[bio_off : bio_off + l2e]
    if len(bio) >= 50:
        head = bio[:50]
        h14 = (head[14] << 8) | head[15]
        h18 = (head[18] << 8) | head[19]
        print(
            f"CBEFF: total={len(bio)} h14={h14} diff_total={len(bio)-h14} h18={h18} diff_rec={(len(bio)-14)-h18}"
        )
    else:
        print(f"CBEFF too short: {len(bio)} bytes")


def main():
    new_path = Path('generated_data/0102.bin')
    if not new_path.exists():
        print('generated_data/0102.bin not found')
        return
    raw_new = new_path.read_bytes()
    analyze('NEW', raw_new)

    # try to find a backup old template
    from glob import glob

    for pat in ['old_backup*', 'old*', 'old_*']:
        for d in sorted(glob(pat)):
            p = Path(d) / '0102.bin'
            if p.exists():
                raw_old = p.read_bytes()
                analyze(f'OLD {p}', raw_old)
                return


if __name__ == '__main__':
    main()

