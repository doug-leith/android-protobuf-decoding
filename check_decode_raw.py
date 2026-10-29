# Compares decode_raw.decode_raw() with `protoc --decode_raw` byte for byte, on the payloads in the
# given files/folders, on random mutations of them, and on randomly generated messages.
# Usage: python3 check_decode_raw.py [--protoc PATH] [--fuzz N] [--seed S] FILE_OR_DIR...
import argparse, os, random, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from decode_raw import decode_raw, DecodeRawError

def varint(n):
    out = b""
    while True:
        b, n = n & 0x7f, n >> 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])

def odd_varint(rng, n):
    # usually the plain encoding; sometimes padded with redundant bytes (up to 11), or with bits
    # set above 32, which protoc treats differently at the top level and inside a nested field
    r = rng.random()
    if r < 0.85:
        return varint(n)
    if r < 0.93:
        n += rng.choice([1, 2, 255, 2**31]) << 32
    e = varint(n)
    pad = rng.randint(0, 11-len(e)) if len(e) < 11 else 0
    if pad:
        e = bytes(c | 0x80 for c in e) + b"\x80"*(pad-1) + b"\x00"
    return e

def random_message(rng, depth):
    # nested messages, groups, overlong varints and edge values, to exercise the parse and print rules
    out = b""
    for _ in range(rng.randint(0, 4)):
        field = rng.choice([1, 2, 15, 16, 2047, 2**29-1, rng.randint(1, 2**29-1)])
        kind = rng.choice("vvfdllmmg" if depth > 0 else "vvfdll")
        if kind == "v":
            out += odd_varint(rng, field << 3) + varint(rng.choice([0, 1, 127, 128, 2**31, 2**63, 2**64-1, rng.getrandbits(64)]))
        elif kind == "f":
            out += odd_varint(rng, field << 3 | 5) + rng.randbytes(4)
        elif kind == "d":
            out += odd_varint(rng, field << 3 | 1) + rng.randbytes(8)
        elif kind == "l":
            body = rng.choice([b"", rng.randbytes(rng.randint(1, 20)), "héllo 'x' \"y\" \\ ?".encode()])
            out += odd_varint(rng, field << 3 | 2) + odd_varint(rng, len(body)) + body
        elif kind == "m":
            body = random_message(rng, depth-1)
            out += odd_varint(rng, field << 3 | 2) + odd_varint(rng, len(body)) + body
        else:
            out += odd_varint(rng, field << 3 | 3) + random_message(rng, depth-1) + odd_varint(rng, field << 3 | 4)
    return out

def nested(rng):
    # chains of messages and groups around the depth limits (10 for printing, 100 for groups)
    body = varint(8) + varint(1)
    for _ in range(rng.randint(0, 105)):
        f = rng.randint(1, 3)
        if rng.random() < 0.5:
            body = varint(f << 3 | 2) + varint(len(body)) + body
        else:
            body = varint(f << 3 | 3) + body + varint(f << 3 | 4)
    return body

def mutate(rng, b):
    b = bytearray(b)
    for _ in range(rng.randint(1, 3)):
        op = rng.randrange(4)
        if op == 0 and b:
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        elif op == 1 and b:
            del b[rng.randrange(len(b)):]
        elif op == 2:
            b[rng.randint(0, len(b)):rng.randint(0, len(b))] = rng.randbytes(rng.randint(0, 3))
        elif b:
            i, j = sorted(rng.randrange(len(b)+1) for _ in range(2))
            b[i:i] = b[i:j]
    return bytes(b)

def with_protoc(protoc, b):
    p = subprocess.run([protoc, "--decode_raw"], input=b, capture_output=True)
    return p.stdout.decode("latin-1") if p.returncode == 0 else None

def in_process(b):
    try:
        return decode_raw(b)
    except DecodeRawError:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protoc", default="protoc")
    ap.add_argument("--fuzz", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("paths", nargs="*")
    args = ap.parse_args()
    corpus = []
    for p in args.paths:
        files = [os.path.join(p, f) for f in sorted(os.listdir(p))] if os.path.isdir(p) else [p]
        corpus += [("file " + f, open(f, "rb").read()) for f in files]
    rng = random.Random(args.seed)
    cases = list(corpus)
    for i in range(args.fuzz):
        kind = rng.randrange(3) if corpus else rng.randrange(1, 3)
        if kind == 0:
            cases.append(("mutation %d" % i, mutate(rng, rng.choice(corpus)[1])))
        elif kind == 1:
            cases.append(("generated %d" % i, random_message(rng, rng.randint(0, 12))))
        else:
            cases.append(("nested %d" % i, nested(rng)))
    with ThreadPoolExecutor(16) as pool:
        expected = list(pool.map(lambda c: with_protoc(args.protoc, c[1]), cases))
    bad = 0
    for (name, b), want in zip(cases, expected):
        # protoc's stdout is decoded as latin-1, and decode_raw's output is ASCII, so equal text is equal bytes
        got = in_process(b)
        if got != want:
            bad += 1
            if bad <= 10:
                print("MISMATCH", name, "protoc failed" if want is None else "", "decode_raw failed" if got is None else "")
    fails = sum(w is None for w in expected)
    print("%d cases (%d corpus, %d fuzz; protoc failed on %d): %d mismatches" % (len(cases), len(corpus), len(cases)-len(corpus), fails, bad))
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
