import sys
import os
import zlib
import pickle

# Extracts RenPy archives
# Usage: python extract_rpa.py <archive.rpa> <output_dir>
# Malware sample: 3c086e76942fb9fd3d1e4384e9c1228c227c00c78dc29fca512ed95ee919ee5e
# It contains the rpa in data/archive.rpa
# Decompile resulting .rpyc with https://github.com/CensoredUsername/unrpyc

def read_exact(f, size):
    data = f.read(size)
    if len(data) != size:
        raise EOFError("Unexpected EOF")
    return data


def detect_version(f):
    header = f.read(40)
    f.seek(0)

    if header.startswith(b"RPA-3.0 "):
        return 3
    if header.startswith(b"RPA-2.0 "):
        return 2
    if header.startswith(b"\x78\x9c"):
        return 1

    raise ValueError("Unknown or unsupported RPA format")


def read_index_v3(f):
    header = read_exact(f, 40)
    offset = int(header[8:24], 16)
    key = int(header[25:33], 16)

    f.seek(offset)
    index = pickle.loads(zlib.decompress(f.read()))

    out = {}

    for name, entries in index.items():
        decoded = []
        for entry in entries:
            if len(entry) == 2:
                off, size = entry
                decoded.append((off ^ key, size ^ key, b""))
            else:
                off, size, start = entry
                if not isinstance(start, bytes):
                    start = start.encode("latin-1")
                decoded.append((off ^ key, size ^ key, start))
        out[name] = decoded

    return out


def read_index_v2(f):
    header = read_exact(f, 24)
    offset = int(header[8:], 16)
    f.seek(offset)
    return pickle.loads(zlib.decompress(f.read()))


def read_index_v1(f):
    return pickle.loads(zlib.decompress(f.read()))


def extract_rpa(path, outdir):
    os.makedirs(outdir, exist_ok=True)

    with open(path, "rb") as f:
        version = detect_version(f)

        if version == 3:
            index = read_index_v3(f)
        elif version == 2:
            index = read_index_v2(f)
        elif version == 1:
            index = read_index_v1(f)
        else:
            raise RuntimeError("Unsupported RPA version")

        for name, entries in index.items():
            out_path = os.path.join(outdir, name.replace("/", os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            data = b""

            for entry in entries:
                if len(entry) == 2:
                    off, size = entry
                    start = b""
                else:
                    off, size, start = entry

                f.seek(off)
                chunk = f.read(size)
                data += start + chunk

            with open(out_path, "wb") as out:
                out.write(data)

            print("Extracted:", name)


def main():
    if len(sys.argv) != 3:
        print("Usage: python extract_rpa.py <archive.rpa> <output_dir>")
        sys.exit(1)

    extract_rpa(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
