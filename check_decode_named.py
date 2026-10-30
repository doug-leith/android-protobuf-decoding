# Compares decode_named.decode_named() with `protoc --decode=MSG -I=DIR FILE` (stderr merged into stdout, as the
# addon ran it) byte for byte, on random messages of every type in the protos the addon decodes, on saved
# payloads, and on mutations of both.
# Usage: python3 check_decode_named.py [--protoc PATH] [--per-type N] [--mutations N] [--seed S] [--corpus DIR] [--proto FILE ...]
# --proto checks only the named protos (repeatable), e.g. --proto chime_named.proto or --proto federatedcompute/aggregations.proto;
# the default is every proto in PROTOS.
# A corpus folder holds NAME.bin payloads, each with a NAME.json {"msg": ..., "proto": ..., "inc": ...}.
import argparse, glob, json, os, random, struct, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from google.protobuf import descriptor, message_factory
import decode_raw
from decode_named import decode_named, DecodeNamedError, _pool
from check_decode_raw import mutate as mutate_bytes

mypath = os.path.dirname(os.path.realpath(__file__))
PROTOS = ["app_measurement.proto3", "firebase_logbatch.proto", "finsky_protobuf/response.proto", "checkin.proto",
          "devicekeyrequest.proto", "locm.proto", "spatula.proto", "intermediatetoken.proto",
          "exptsandconfigs_response.proto", "exptsandconfigs_request.proto", "federated_learning_protos/federated_api.proto",
          "android_messaging.proto3", "android_dialer.proto3", "gboard_named.proto", "icing_named.proto",
          "consentinfo.proto", "stats_log.proto", "lockbox.proto", "activity_recognition.proto", "netstats.proto",
          "scoobyevents.proto", "scoobymessageevents.proto", "playstore.proto", "client_logging_named.proto",
          "primes_named.proto", "chime_named.proto", "autofill_named.proto", "on_device_abuse_named.proto",
          "agsa_named.proto", "ondevicesafety_named.proto", "westworld_counters_named.proto", "kollektomat_named.proto", "voilatile_named.proto", "voice_search_named.proto",
          "wallet_client_token_named.proto",
          ("federated_learning_protos", "federatedcompute/eligibility_eval_tasks.proto"),
          ("federated_learning_protos", "federatedcompute/task_assignments.proto"),
          ("federated_learning_protos", "federatedcompute/aggregations.proto"),
          ("federated_learning_protos", "federatedcompute/secure_aggregations.proto"),
          ("federated_learning_protos", "population_eligibility_spec.proto")]
F = descriptor.FieldDescriptor

def split(path):
    # (include dir, proto) for a PROTOS entry: a path, or (include dir, proto path within it) for a proto whose
    # imports are relative to a parent folder
    if isinstance(path, tuple):
        return os.path.join(mypath, path[0]), path[1]
    return os.path.join(mypath, os.path.dirname(path)), os.path.basename(path)

def message_types(pool, proto, map_entries):
    out = []
    def walk(d):
        if d.full_name not in map_entries:
            out.append(d)
        for n in d.nested_types:
            walk(n)
    for d in pool.FindFileByName(proto).message_types_by_name.values():
        walk(d)
    return out

def scalar(rng, fd):
    t = fd.type
    if t in (F.TYPE_INT32, F.TYPE_SINT32, F.TYPE_SFIXED32):
        return rng.choice([0, 1, -1, 2**31-1, -2**31, rng.randint(-2**31, 2**31-1)])
    if t in (F.TYPE_INT64, F.TYPE_SINT64, F.TYPE_SFIXED64):
        return rng.choice([0, -1, 2**63-1, -2**63, rng.randint(-2**63, 2**63-1)])
    if t in (F.TYPE_UINT32, F.TYPE_FIXED32):
        return rng.choice([0, 1, 2**32-1, rng.getrandbits(32)])
    if t in (F.TYPE_UINT64, F.TYPE_FIXED64):
        return rng.choice([0, 2**64-1, rng.getrandbits(64)])
    if t == F.TYPE_BOOL:
        return rng.random() < 0.5
    if t == F.TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", rng.getrandbits(32)))[0]
    if t == F.TYPE_DOUBLE:
        return struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
    if t == F.TYPE_STRING:
        return rng.choice(["", "abc", "héllo €", "tab\there \"q\" 'a' \\", "😀\x00\x7f"])
    if t == F.TYPE_BYTES:
        return rng.randbytes(rng.randint(0, 12))
    if t == F.TYPE_ENUM:
        values = [v.number for v in fd.enum_type.values]
        if fd.enum_type.is_closed or rng.random() < 0.7:
            return rng.choice(values)
        return rng.randint(-2**31, 2**31-1)

def random_message(rng, pool, d, depth, types):
    m = message_factory.GetMessageClass(d)()
    fields = list(d.fields) + list(pool.FindAllExtensions(d))
    for fd in fields:
        if rng.random() < 0.4:
            continue
        target = m.Extensions[fd] if fd.is_extension else getattr(m, fd.name)
        n = rng.randint(0, 3) if fd.label == F.LABEL_REPEATED else 1
        for _ in range(n):
            try:
                if fd.message_type is not None and fd.message_type.GetOptions().map_entry:
                    kf, vf = fd.message_type.fields_by_name["key"], fd.message_type.fields_by_name["value"]
                    k = scalar(rng, kf)
                    if vf.message_type is not None:
                        if depth > 0:
                            target[k].CopyFrom(random_message(rng, pool, vf.message_type, depth-1, types))
                    else:
                        target[k] = scalar(rng, vf)
                elif fd.message_type is not None:
                    if depth <= 0:
                        break
                    if fd.message_type.full_name == "google.protobuf.Any":
                        sub = message_factory.GetMessageClass(fd.message_type)()
                        if rng.random() < 0.7:
                            sub.Pack(random_message(rng, pool, rng.choice(types), depth-1, types))
                        else:
                            sub.type_url = rng.choice(["", "noslash", "type.googleapis.com/no.such.Type"])
                            sub.value = rng.randbytes(rng.randint(0, 8))
                    else:
                        sub = random_message(rng, pool, fd.message_type, depth-1, types)
                    if fd.label == F.LABEL_REPEATED:
                        target.add().CopyFrom(sub)
                    elif fd.is_extension:
                        m.Extensions[fd].CopyFrom(sub)
                    else:
                        target.CopyFrom(sub)
                elif fd.label == F.LABEL_REPEATED:
                    target.append(scalar(rng, fd))
                elif fd.is_extension:
                    m.Extensions[fd] = scalar(rng, fd)
                else:
                    setattr(m, fd.name, scalar(rng, fd))
            except (ValueError, TypeError):
                pass  # value the python API refuses (e.g. an out-of-range closed enum): the mutations cover those
    return m

def varint(n):
    out = b""
    while True:
        b, n = n & 0x7f, n >> 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])

def encode(fields):
    out = b""
    for f, w, v in fields:
        out += varint(f << 3 | w)
        if w == 0:
            out += varint(v)
        elif w == 1:
            out += v.to_bytes(8, "little")
        elif w == 5:
            out += v.to_bytes(4, "little")
        elif w == 2:
            out += varint(len(v)) + v
        else:
            out += encode(v) + varint(f << 3 | 4)
    return out

def mutate_fields(rng, b):
    # well-formed changes: a field's value or wire type, a duplicate, an unknown field number, a deletion
    try:
        fields = [list(x) for x in decode_raw._parse(b, 0, 100)[0]]
    except decode_raw.DecodeRawError:
        return b
    if not fields:
        return b
    for _ in range(rng.randint(1, 3)):
        i = rng.randrange(len(fields))
        op = rng.randrange(7)
        if op == 0:
            fields[i][1:] = [0, rng.choice([2, 99, 2**31, 2**32-1, 2**63, 2**64-1, rng.getrandbits(64)])]
        elif op == 1:
            fields[i][1:] = [2, rng.choice([b"\xff\xfe", b"\xc3", b"ok\xed\xa0\x80", "é€😀".encode(), b""])]
        elif op == 2:
            fields[i][1:] = [5, rng.getrandbits(32)]
        elif op == 3:
            fields[i][1:] = [1, rng.getrandbits(64)]
        elif op == 4:
            fields.append(list(fields[i]))
        elif op == 5:
            fields[i][0] = rng.choice([999, 19000, 2**29-1])
        elif len(fields) > 1:
            fields.pop(i)
    return encode(fields)

def with_protoc(protoc, case):
    msg, proto, inc, b = case
    p = subprocess.run([protoc, "--decode=" + msg, "-I=" + inc, proto], input=b, cwd=inc,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.decode("utf-8", "surrogateescape") if p.returncode == 0 else None

def in_process(case):
    msg, proto, inc, b = case
    try:
        return decode_named(msg, proto, b, inc)
    except DecodeNamedError:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protoc", default="protoc")
    ap.add_argument("--per-type", type=int, default=3)
    ap.add_argument("--mutations", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--corpus")
    ap.add_argument("--save", help="folder to write mismatching inputs to, in the --corpus format")
    ap.add_argument("--proto", action="append", help="check only this proto (as listed in PROTOS); repeatable")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    cases = []
    protos = PROTOS
    if args.proto:
        names = lambda p: {split(p)[1], os.path.basename(split(p)[1]), p if isinstance(p, str) else split(p)[1]}
        unknown = [a for a in args.proto if not any(a in names(p) for p in PROTOS)]
        if unknown:
            sys.exit("not in PROTOS: " + ", ".join(unknown))
        protos = [p for p in PROTOS if names(p) & set(args.proto)]
    for path in protos:
        inc, proto = split(path)
        pool, map_entries = _pool(inc, proto)
        types = message_types(pool, proto, map_entries)
        for d in types:
            for _ in range(args.per_type):
                b = random_message(rng, pool, d, 3, types).SerializePartialToString()
                cases.append((d.full_name, proto, inc, b))
    if args.corpus:
        for j in sorted(glob.glob(os.path.join(args.corpus, "*.json"))):
            if args.proto and json.load(open(j))["proto"] not in [split(p)[1] for p in protos]:
                continue
            meta = json.load(open(j))
            cases.append((meta["msg"], meta["proto"], meta["inc"], open(j[:-5] + ".bin", "rb").read()))
    base = list(cases)
    for msg, proto, inc, b in base:
        for _ in range(args.mutations):
            m = mutate_fields(rng, b) if rng.random() < 0.8 else mutate_bytes(rng, b)
            cases.append((msg, proto, inc, m))
    with ThreadPoolExecutor(16) as pool:
        expected = list(pool.map(lambda c: with_protoc(args.protoc, c), cases))
    bad = 0
    for case, want in zip(cases, expected):
        got = in_process(case)
        if got != want:
            bad += 1
            if args.save:
                os.makedirs(args.save, exist_ok=True)
                name = os.path.join(args.save, "mismatch%d" % bad)
                json.dump({"msg": case[0], "proto": case[1], "inc": case[2]}, open(name + ".json", "w"))
                open(name + ".bin", "wb").write(case[3])
            if bad <= 10:
                if want is None or got is None:
                    print("MISMATCH", case[0], "protoc failed" if want is None else "decode_named failed")
                else:
                    w, g = want.splitlines(), got.splitlines()
                    d = next(((a, c) for a, c in zip(w, g) if a != c), ("%d lines" % len(w), "%d lines" % len(g)))
                    print("MISMATCH", case[0], "protoc:", repr(d[0])[:150], "| decode_named:", repr(d[1])[:150])
    print("%d cases (%d generated or saved, %d mutated; protoc failed on %d): %d mismatches"
          % (len(cases), len(base), len(cases)-len(base), sum(w is None for w in expected), bad))
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
