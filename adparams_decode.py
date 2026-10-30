# Decoders for advert URL parameters:
#   ms, dc_ms  AdShield click/impression signal (Play store app and the Google Mobile Ads SDK)
#   attok      event attestation token added by the Google Mobile Ads SDK (see attok.proto)
#   gref       opaque protobuf in the Play store intent:// link returned by www.google.com/aclk
# decode_url_params(url) returns the text to print, "" when the url carries none of these.  It never
# raises: a value that is encrypted, or in a format we do not know, is reported as such.
import base64, hashlib, os, re, struct, urllib.parse
from decode_raw import decode_raw, DecodeRawError
from decode_named import decode_named, DecodeNamedError

mypath = os.path.dirname(os.path.realpath(__file__))

AD_HOSTS = (".doubleclick.net", ".googleadservices.com", ".googlesyndication.com")
AD_PATHS = ("/aclk", "/pagead/", "/pcs/click", "/dbm/clk")

def _is_ad_url(parts):
    host = (parts.hostname or "").lower()
    return host.endswith(AD_HOSTS) or any(p in parts.path for p in AD_PATHS)

def _b64(s):
    # base64, standard or url-safe, padded or not; None when s is not base64
    s = urllib.parse.unquote(s).strip()
    if not s or not re.fullmatch(r"[A-Za-z0-9+/_\-]+=*", s):
        return None
    try:
        return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_").rstrip("=") + "=" * (-len(s.rstrip("=")) % 4))
    except (ValueError, base64.binascii.Error):
        return None

def _fields(buf):
    # top-level protobuf fields as [(number, wiretype, value)]; None when buf is not a protobuf
    out = []; i = 0
    try:
        while i < len(buf):
            key = 0; shift = 0
            while True:
                c = buf[i]; i += 1; key |= (c & 0x7f) << shift; shift += 7
                if c < 0x80: break
            f, t = key >> 3, key & 7
            if f == 0: return None
            if t == 0:
                v = 0; shift = 0
                while True:
                    c = buf[i]; i += 1; v |= (c & 0x7f) << shift; shift += 7
                    if c < 0x80: break
            elif t == 2:
                n = 0; shift = 0
                while True:
                    c = buf[i]; i += 1; n |= (c & 0x7f) << shift; shift += 7
                    if c < 0x80: break
                if i + n > len(buf): return None
                v = buf[i:i + n]; i += n
            elif t == 1: v = buf[i:i + 8]; i += 8
            elif t == 5: v = buf[i:i + 4]; i += 4
            else: return None
            if i > len(buf): return None
            out.append((f, t, v))
    except IndexError:
        return None
    return out

def _raw(buf):
    try:
        return decode_raw(buf)
    except DecodeRawError as e:
        return "(not a protobuf: %s)\n" % e

def _uuid(b):
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:]) if len(b) == 16 else h

# ---------------------------------------------------------------- AdShield ms / dc_ms

# Play store class ecw: the signal protobuf is split into 255-byte chunks, each made a 256-byte block
# (length byte, chunk, random padding), passed through the fixed transform in afma_circuit.py, then
# XORed with RC4 keyed by the click's ai value (first 32 characters).  The blocks and the MD5 of the
# signal are sent as {1: block (repeated), 2: md5}.  Envelope field 3 marks the other producers:
# 2 = native AdShield code, 4 = DroidGuard VM output (Google Mobile Ads SDK, flow msa-r).
ERROR_CODES = {"3": "invalid request data", "5": "no signal available", "7": "signal encoding failed"}

_gates = None

def _build_gates():
    # afma_circuit.F as a gate list in SSA form: wires 0-63 are the input words
    import ast
    fn = ast.parse(open(os.path.join(mypath, "afma_circuit.py")).read()).body[0]
    gates = []; cur = {}; out = [None] * 64; n = [64]
    def name(t):
        if isinstance(t, ast.Name): return t.id
        return "S." + t.slice.value
    def gate(op, x, y=None):
        z = n[0]; n[0] += 1; gates.append((op, z, x, y)); return z
    def binop(op, a, b):
        if isinstance(a, tuple): a, b = b, a
        if isinstance(b, tuple):          # the only constant in the circuit is -1
            if b != ("c", -1): raise ValueError("unexpected constant %r" % (b,))
            if op is ast.BitXor: return gate("not", a)
            if op is ast.BitAnd: return a
            raise ValueError("unexpected | -1")
        return gate({ast.BitAnd: "and", ast.BitOr: "or", ast.BitXor: "xor"}[op], a, b)
    def ev(e):
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.USub): return ("c", -e.operand.value)
        if isinstance(e, ast.Constant): return ("c", e.value)
        if isinstance(e, ast.Subscript) and e.value.id == "W": return e.slice.value
        if isinstance(e, (ast.Name, ast.Subscript)): return cur[name(e)]
        return binop(type(e.op), ev(e.left), ev(e.right))
    for st in fn.body:
        if isinstance(st, ast.Assign):
            t = st.targets[0]
            if isinstance(t, ast.Name) and t.id in ("S", "OUT"): continue
            if isinstance(t, ast.Subscript) and t.value.id == "OUT": out[t.slice.value] = ev(st.value); continue
            cur[name(t)] = ev(st.value)
        elif isinstance(st, ast.AugAssign):
            cur[name(st.target)] = binop(type(st.op), cur[name(st.target)], ev(st.value))
    return gates, out, n[0]

def _invert_block(block):
    # input block of the transform for this 256-byte output.  The transform is a bitsliced Feistel
    # cipher with the key folded in, so propagating known bits back from the outputs (32 blocks at a
    # time, one per bit position) recovers every input bit.  None if it does not.
    global _gates
    if _gates is None:
        _gates = _build_gates()
    gates, out, nwires = _gates
    M = 0xffffffff
    K = [0] * nwires; V = [0] * nwires
    touch = [[] for _ in range(nwires)]
    for gi, (op, z, x, y) in enumerate(gates):
        touch[z].append(gi); touch[x].append(gi)
        if y is not None: touch[y].append(gi)
    queue = []; queued = bytearray(len(gates))
    def learn(w, k, v):
        new = k & ~K[w]
        if new:
            K[w] |= new; V[w] = (V[w] & ~new) | (v & new)
            for gi in touch[w]:
                if not queued[gi]: queued[gi] = 1; queue.append(gi)
    for i, w in enumerate(struct.unpack("<64I", block)):
        learn(out[i], M, w)
    while queue:
        gi = queue.pop(); queued[gi] = 0
        op, z, x, y = gates[gi]
        kz, vz, kx, vx = K[z], V[z], K[x], V[x]
        if op == "not":
            learn(z, kx, ~vx & M); learn(x, kz, ~vz & M); continue
        ky, vy = K[y], V[y]
        if op == "xor":
            learn(z, kx & ky, vx ^ vy); learn(x, kz & ky, vz ^ vy); learn(y, kz & kx, vz ^ vx)
        elif op == "and":
            learn(z, (kx & ky) | (kx & ~vx) | (ky & ~vy), vx & vy)
            one = kz & vz; learn(x, one, M); learn(y, one, M)
            zero = kz & ~vz; learn(y, zero & kx & vx, 0); learn(x, zero & ky & vy, 0)
        else:
            learn(z, (kx & ky) | (kx & vx) | (ky & vy), vx | vy)
            zero = kz & ~vz; learn(x, zero, 0); learn(y, zero, 0)
            one = kz & vz; learn(y, one & kx & ~vx, M); learn(x, one & ky & ~vy, M)
    if any(K[i] != M for i in range(64)):
        return None
    x = [V[i] for i in range(64)]
    from afma_circuit import F
    if struct.pack("<64I", *F(x, M)) != block:
        return None
    return struct.pack("<64I", *x)

def _rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(data)
    for n in range(len(out)):
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        out[n] ^= S[(S[i] + S[j]) & 255]
    return bytes(out)

def _decrypt_blocks(blocks, key):
    # plaintext from the 256-byte blocks, or None
    plain = b""
    for c in blocks:
        if len(c) != 256: return None
        b = _invert_block(_rc4(key, c) if key else c)
        if b is None or b[0] > 255: return None
        plain += b[1:1 + b[0]]
    return plain

MS_FIELDS = """  1 signal version   2 client version string   5/6/59 battery status/level %/temperature (0.1 C)
  14/15 touch x/y (pixels)   23 session start time (s)   25 time of signal (s)   45 call stack depth
  50 touch event details   51/52 time since boot with/without sleep (ms)   24 Google Advertising Id
  (ad request signals only)"""

def decode_ms(value, ai):
    if value.isdigit() and len(value) <= 3:
        return "AdShield error code %s (%s), no signal\n" % (value, ERROR_CODES.get(value, "unknown code"))
    buf = _b64(value)
    if buf is None:
        return "not base64, not an AdShield signal\n"
    keys = [ai[:32].encode("utf-8")] if ai else []
    keys.append(None)              # dc_ms on ad.doubleclick.net has no ai, and then no RC4 layer
    env = _fields(buf)
    if env is not None and all(t == 2 and f in (1, 2) or t == 0 and f == 3 for f, t, v in env):
        kind = [v for f, t, v in env if f == 3]
        blocks = [v for f, t, v in env if f == 1]
        md5 = [v for f, t, v in env if f == 2]
        if kind == [4]:
            return "encrypted: DroidGuard VM output (AdShield msa-r), %d bytes, cannot be decoded offline\n" % sum(map(len, blocks))
        if kind == [2]:
            return "encrypted: native AdShield output, %d bytes, cannot be decoded offline\n" % sum(map(len, blocks))
        if kind:
            return "encrypted: unknown AdShield envelope type %d\n" % kind[0]
        if blocks and len(md5) == 1:
            for key in keys:
                plain = _decrypt_blocks(blocks, key)
                if plain is not None and hashlib.md5(plain).digest() == md5[0]:
                    return ("decrypted Play store AdShield signal (%d bytes, MD5 matches, RC4 key %s):\n%s\nfields:\n%s\n"
                            % (len(plain), "ai" if key else "none", _raw(plain), MS_FIELDS))
            return ("encrypted: Play store AdShield format (%d blocks) but decryption failed the MD5 check; "
                    "probably an encoder build with a different key\n" % len(blocks))
    if len(buf) == 256:
        # a single block holding MD5(rest) + length byte + signal: what ecw sends when the signal is empty
        for key in keys:
            b = _invert_block(_rc4(key, buf) if key else buf)
            if b is not None and hashlib.md5(b[16:]).digest() == b[:16] and b[16] <= 239:
                plain = b[17:17 + b[16]]
                return "decrypted Play store AdShield fallback signal (%d bytes):\n%s" % (len(plain), _raw(plain))
        return "encrypted: 256 bytes, not a Play store AdShield block we can decrypt\n"
    return "encrypted or unknown format: %d bytes, not an AdShield envelope\n" % len(buf)

# ---------------------------------------------------------------- attok

def _named(message, buf):
    try:
        return decode_named(message, "attok.proto", buf)
    except DecodeNamedError as e:
        return "(could not decode as %s: %s)\n%s" % (message, e, _raw(buf))

def decode_attok(value):
    if value == "failure_click_attok":
        return "no token: the SDK could not get a click attestation token\n"
    buf = _b64(value)
    if buf is None:
        return "not base64: %r\n" % value[:80]
    outer = _fields(buf)
    if outer and {f for f, t, v in outer} <= {1, 2} and all(t == 2 for f, t, v in outer):
        content = dict((f, v) for f, t, v in outer).get(1, b"")
        ev = _fields(content)
        if ev and any(f == 2 and t == 0 for f, t, v in ev) and any(f in (3, 9, 10, 11, 12) for f, t, v in ev):
            out = "signed event attestation token (not encrypted), signature %d bytes:\n" % len(dict((f, v) for f, t, v in outer).get(2, b""))
            out += _named("EventAttestation", content)
            evd = dict((f, v) for f, t, v in ev)
            if 8 in evd:
                out += "Google Advertising Id: %s\n" % _uuid(evd[8])
            token = _fields(evd.get(4, b"")) or []
            tok_content = dict((f, v) for f, t, v in token).get(1)
            if tok_content:
                out += "integrity_token content (signed by Google):\n" + _named("IntegrityTokenContent", tok_content)
                adid = dict((f, v) for f, t, v in (_fields(tok_content) or [])).get(5)
                if adid:
                    out += "integrity_token Google Advertising Id: %s\n" % _uuid(adid)
            return out
    if len(buf) > 5 and buf[0] in (0, 1):
        return ("encrypted: Tink %s ciphertext, key id 0x%s, %d bytes; the destination's key is needed to decrypt\n"
                % ("TINK" if buf[0] == 1 else "LEGACY", buf[1:5].hex(), len(buf)))
    return "encrypted or unknown format: %d bytes\n" % len(buf)

# ---------------------------------------------------------------- gref

def decode_gref(value):
    buf = _b64(value)
    if buf is None:
        return "not base64: %r\n" % value[:80]
    if _fields(buf) is None:
        return "not a protobuf: %d bytes\n" % len(buf)
    return _raw(buf)

# ---------------------------------------------------------------- url

def _params(url):
    # query parameters and ;name=value path parameters (ad.doubleclick.net style), first value of each
    parts = urllib.parse.urlsplit(url)
    params = {}
    for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(k, v)
    for k, v in re.findall(r";([A-Za-z_]+)=([^;?#]*)", parts.path):
        params.setdefault(k, v)
    return parts, params

def decode_url_params(url, where="url parameter"):
    try:
        parts, params = _params(url)
        out = ""
        if "ms" in params and _is_ad_url(parts):     # elsewhere ms is unrelated (e.g. googlevideo ms=au,rdu)
            out += "Decoded ms %s: %s" % (where, decode_ms(params["ms"], params.get("ai")))
        if "dc_ms" in params:
            out += "Decoded dc_ms %s: %s" % (where, decode_ms(params["dc_ms"], params.get("ai")))
        if "attok" in params:
            out += "Decoded attok %s: %s" % (where, decode_attok(params["attok"]))
        if "gref" in params:
            out += "Decoded gref %s:\n%s" % (where, decode_gref(params["gref"]))
            gref, gclid = _b64(params["gref"]), _b64(params.get("gclid", ""))
            if gref and gclid and gclid in gref:
                out += "(gref contains the gclid of the same link)\n"
        return out
    except Exception as e:
        return "***ERROR decoding advert url parameters: %s: %s\n" % (type(e).__name__, e)
