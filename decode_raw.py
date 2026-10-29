# In-process equivalent of `protoc --decode_raw`: the same parse rules and the same text output,
# without starting a protoc process per message.  check_decode_raw.py compares the two byte for byte.
#
# protoc's rules, as measured against libprotoc 33.1:
# - top level: groups may nest 100 deep; any malformed input fails the whole decode
# - a length-delimited field is printed as a nested message when it is non-empty, the recursion
#   budget (10 at the top level, one less per printed level) is positive, and it parses with
#   groups nested no deeper than that budget; otherwise it is printed as a C-escaped string
# - groups are always printed as nested messages, and also use up one level of budget
# - tags and lengths are varints of at most 5 bytes (bits of a tag past 32 are dropped);
#   values are varints of at most 10 bytes (bits past 64 are dropped)

class DecodeRawError(Exception):
    pass

def _varint(buf, pos, maxlen):
    result = 0
    for i in range(maxlen):
        if pos >= len(buf):
            raise DecodeRawError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7f) << (7*i)
        if not b & 0x80:
            return result & 0xffffffffffffffff, pos
    raise DecodeRawError("varint too long")

def _parse(buf, pos, depth, group=None):
    # returns ([(field number, wire type, value)], position after the message or group)
    fields = []
    while pos < len(buf):
        tag, pos = _varint(buf, pos, 5)
        tag &= 0xffffffff
        field, wiretype = tag >> 3, tag & 7
        if field == 0:
            raise DecodeRawError("field number 0")
        if wiretype == 0:
            value, pos = _varint(buf, pos, 10)
        elif wiretype == 1 or wiretype == 5:
            n = 8 if wiretype == 1 else 4
            if pos+n > len(buf):
                raise DecodeRawError("truncated fixed%d" % (8*n))
            value = int.from_bytes(buf[pos:pos+n], "little")
            pos += n
        elif wiretype == 2:
            n, pos = _varint(buf, pos, 5)
            if n > len(buf)-pos:
                raise DecodeRawError("length past end of input")
            value = buf[pos:pos+n]
            pos += n
        elif wiretype == 3:
            if depth <= 0:
                raise DecodeRawError("groups nested too deep")
            value, pos = _parse(buf, pos, depth-1, field)
        elif wiretype == 4:
            if group != field:
                raise DecodeRawError("unmatched end group")
            return fields, pos
        else:
            raise DecodeRawError("wire type %d" % wiretype)
        fields.append((field, wiretype, value))
    if group is not None:
        raise DecodeRawError("unterminated group")
    return fields, pos

# C escaping as protoc prints bytes: \n \r \t \" \' \\, printable ASCII as is, everything else 3-digit octal
_ESCAPE = ["\\%03o" % c if c < 0x20 or c >= 0x7f else chr(c) for c in range(256)]
for c, e in ((0x0a, "\\n"), (0x0d, "\\r"), (0x09, "\\t"), (0x22, '\\"'), (0x27, "\\'"), (0x5c, "\\\\")):
    _ESCAPE[c] = e

def _print(fields, budget, indent, out):
    pad = "  "*indent
    for field, wiretype, value in fields:
        if wiretype == 0:
            out.append("%s%d: %d\n" % (pad, field, value))
        elif wiretype == 5:
            out.append("%s%d: 0x%08x\n" % (pad, field, value))
        elif wiretype == 1:
            out.append("%s%d: 0x%016x\n" % (pad, field, value))
        else:
            if wiretype == 2:
                sub = None
                if value and budget > 0:
                    try:
                        sub = _parse(value, 0, budget)[0]
                    except DecodeRawError:
                        pass
                if sub is None:
                    out.append('%s%d: "%s"\n' % (pad, field, "".join([_ESCAPE[c] for c in value])))
                    continue
            else:
                sub = value
            out.append("%s%d {\n" % (pad, field))
            _print(sub, budget-1, indent+1, out)
            out.append("%s}\n" % pad)

def decode_raw(bb):
    # text that `protoc --decode_raw` prints for bb; raises DecodeRawError where protoc fails
    out = []
    _print(_parse(bytes(bb), 0, 100)[0], 10, 0, out)
    return "".join(out)
