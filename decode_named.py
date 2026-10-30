# In-process equivalent of `protoc --decode=MESSAGE -I=DIR FILE.proto` with stderr merged into stdout, as the
# addon ran it: the .proto is compiled once per process to a descriptor set, messages are parsed with the
# python protobuf library and printed the way protoc prints them.  check_decode_named.py compares the two.
#
# Where python's text format differs from protoc's, protoc's is reproduced:
# - unknown fields are printed with decode_raw.py's rules
# - floats are printed with %.6g, or %.9g when that does not read back with strtof as the same float or
#   strtof reports a range error (as it does for every subnormal); doubles with %.15g, or %.17g
# - an out-of-range value of a closed enum is kept as an unknown int32, sign-extended to 64 bits
#   (python's upb keeps the low 32 bits unsigned)
# - an Any is never expanded: protoc prints its type_url and value even when it knows the type
# - every entry of a map is kept, duplicate keys included, and printed stable-sorted by key with its key
#   and value always shown (defaults when missing) and nothing else; for this the map entry types are
#   compiled as ordinary messages, so a map parses as a repeated field
# - a group field that arrives length-delimited is kept as an unknown field (python's parser rejects the
#   message): it is renumbered to an unused field number before parsing and printed under its own number
# - missing required fields give protoc's warning line before the message, an extension in a field path written
#   as protoc writes it, "(full name)" (python's FindInitializationErrors leaves out the parentheses)
import ctypes, io, os, subprocess, tempfile
from google.protobuf import descriptor, descriptor_pb2, descriptor_pool, message_factory, text_format
from google.protobuf import unknown_fields
import decode_raw

class DecodeNamedError(Exception):
    pass

_pools = {}

def _pool(include, proto):
    # (descriptor pool, full names of the map entry types) for proto
    key = (include, proto)
    if key not in _pools:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "set.desc")
            p = subprocess.run(["protoc", "--include_imports", "--descriptor_set_out=" + out, "-I=" + include, proto],
                               cwd=include, capture_output=True, text=True)
            if p.returncode != 0:
                raise DecodeNamedError("protoc could not compile %s: %s" % (proto, p.stderr.strip()))
            files = descriptor_pb2.FileDescriptorSet.FromString(open(out, "rb").read()).file
        map_entries = set()
        def unmap(prefix, messages):
            for m in messages:
                if m.options.map_entry:
                    map_entries.add(prefix + m.name)
                    m.options.ClearField("map_entry")
                unmap(prefix + m.name + ".", m.nested_type)
        pool = descriptor_pool.DescriptorPool()
        for f in files:
            unmap(f.package + "." if f.package else "", f.message_type)
            pool.Add(f)
        _pools[key] = (pool, map_entries)
    return _pools[key]

_libc = ctypes.CDLL(None, use_errno=True)
_libc.strtof.restype = ctypes.c_float
_libc.strtof.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

def _float(value):
    s = "%.6g" % value
    if value == value:
        ctypes.set_errno(0)
        if _libc.strtof(s.encode(), None) != value or ctypes.get_errno() != 0:
            s = "%.9g" % value
    return s

def _double(value):
    s = "%.15g" % value
    if value == value and float(s) != value:
        s = "%.17g" % value
    return s

def _unknown(field_set):
    return [(f.field_number, f.wire_type, _unknown(f.data) if f.wire_type == 3 else f.data) for f in field_set]

def _enum_value(value):
    value &= 0xffffffff
    return value | 0xffffffff00000000 if value & 0x80000000 else value

def _has_groups(desc, seen=None):
    # whether desc or a message it reaches has a group (delimited) field
    seen = set() if seen is None else seen
    if desc.full_name in seen:
        return False
    seen.add(desc.full_name)
    for fd in desc.fields:
        if fd.type == descriptor.FieldDescriptor.TYPE_GROUP:
            return True
        if fd.message_type is not None and _has_groups(fd.message_type, seen):
            return True
    return False

def _encode_varint(n):
    out = b""
    while True:
        b, n = n & 0x7f, n >> 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])

def _scan(buf, pos, end, group=None):
    # the fields in buf[pos:end] (or up to group's end tag) as (field, wire type, tag end, value start, value end,
    # field end) with byte offsets, and the position after them; None if malformed
    out = []
    while pos < end:
        tag, tag_end = decode_raw._varint(buf, pos, 10)
        field, wiretype = (tag & 0xffffffff) >> 3, tag & 7
        if wiretype == 0:
            _v, pos = decode_raw._varint(buf, tag_end, 10)
            vstart, vend = tag_end, pos
        elif wiretype in (1, 5):
            vstart, vend = tag_end, tag_end + (8 if wiretype == 1 else 4)
            pos = vend
        elif wiretype == 2:
            n, vstart = decode_raw._varint(buf, tag_end, 10)
            vend = pos = vstart + n
        elif wiretype == 3:
            inner = _scan(buf, tag_end, end, field)
            if inner is None:
                return None
            vstart, vend, pos = tag_end, inner[2], inner[1]
        elif wiretype == 4:
            return (out, tag_end, pos) if field == group else None
        else:
            return None
        if pos > end:
            return None
        out.append((field, wiretype, tag_end, vstart, vend, pos))
    return None if group is not None else (out, pos)

def _field_numbers(buf, out, depth=0):
    # every field number in buf, including inside length-delimited fields that parse as messages
    try:
        fields = decode_raw._parse(buf, 0, 100, nested=depth > 0)[0]
    except decode_raw.DecodeRawError:
        return out
    def walk(fs):
        for f, w, v in fs:
            out.add(f)
            if w == 2 and v and depth < 64:
                _field_numbers(v, out, depth + 1)
            elif w == 3:
                walk(v)
    walk(fields)
    return out

def _renumber_delimited(buf, desc, placeholders, used):
    # protoc keeps a group field that arrives length-delimited as an unknown field; python's parser rejects the
    # message. Renumber each such field (here and in nested messages and groups) to an unused field number, so it
    # parses as unknown too; placeholders maps the new numbers back for printing. Returns buf itself if unchanged.
    try:
        scanned = _scan(buf, 0, len(buf))
    except decode_raw.DecodeRawError:
        return buf
    if scanned is None:
        return buf
    fields, parts, last = scanned[0], [], 0
    pos = 0
    for field, wiretype, tag_end, vstart, vend, end in fields:
        start, pos = pos, end
        fd = desc.fields_by_number.get(field)
        if fd is None or fd.message_type is None:
            continue
        if fd.type == descriptor.FieldDescriptor.TYPE_GROUP and wiretype == 2:
            number = next(n for n, orig in placeholders.items() if orig == field) if field in placeholders.values() else \
                next(n for n in range(0x1fffffff, 0, -1) if n not in used and n not in placeholders)
            placeholders[number] = field
            parts += [buf[last:start], _encode_varint(number << 3 | 2)]   # same length prefix and value
            last = tag_end
        elif wiretype in (2, 3) and _has_groups(fd.message_type):
            inner = buf[vstart:vend]
            new = _renumber_delimited(inner, fd.message_type, placeholders, used)
            if new is not inner:
                if wiretype == 2:
                    parts += [buf[last:tag_end], _encode_varint(len(new)), new]
                else:
                    parts += [buf[last:vstart], new, buf[vend:end]]   # the group's own end tag
                last = end
    if not parts:
        return buf
    return b"".join(parts) + buf[last:]

class _Printer(text_format._Printer):
    def __init__(self, out, map_entries, placeholders=None):
        super().__init__(out, as_utf8=False)
        self.map_entries = map_entries
        self.placeholders = placeholders or {}

    def PrintMessage(self, message):
        # fields in field-number order, then unknown fields; no Any expansion
        for field, value in message.ListFields():
            if field.message_type is not None and field.message_type.full_name in self.map_entries:
                key, val = field.message_type.fields_by_name["key"], field.message_type.fields_by_name["value"]
                # by key, as protoc sorts them: a string key compared as its UTF-8 bytes, since one that is not valid UTF-8
                # comes back as bytes
                for entry in sorted(value, key=lambda e: e.key.encode() if isinstance(e.key, str) else e.key):
                    self.out.write(" " * self.indent + field.name + " {\n")
                    self.indent += 2
                    self.PrintField(key, entry.key)
                    self.PrintField(val, getattr(entry, "value"))
                    self.indent -= 2
                    self.out.write(" " * self.indent + "}\n")
            elif field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
                for element in value:
                    self.PrintField(field, element)
            else:
                self.PrintField(field, value)
        known = message.DESCRIPTOR.fields_by_number
        fields = [(self.placeholders.get(f, f), w, _enum_value(v) if w == 0 and f in known and known[f].enum_type is not None else v)
                  for f, w, v in _unknown(unknown_fields.UnknownFieldSet(message))]
        out = []
        decode_raw._print(fields, 10, self.indent // 2, out)
        self.out.write("".join(out))

    def PrintFieldValue(self, field, value):
        if field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_FLOAT:
            self.out.write(_float(value))
        elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_DOUBLE:
            self.out.write(_double(value))
        else:
            super().PrintFieldValue(field, value)

def _init_errors(m, prefix=""):
    # paths of m's missing required fields, as protoc's ReflectionOps::FindInitializationErrors gives them
    out = [prefix + fd.name for fd in m.DESCRIPTOR.fields
           if fd.label == descriptor.FieldDescriptor.LABEL_REQUIRED and not m.HasField(fd.name)]
    for fd, value in m.ListFields():
        if fd.message_type is None:
            continue
        name = prefix + ("(%s)" % fd.full_name if fd.is_extension else fd.name)
        if fd.label == descriptor.FieldDescriptor.LABEL_REPEATED:
            for i, sub in enumerate(value):
                out += _init_errors(sub, "%s[%d]." % (name, i))
        else:
            out += _init_errors(value, name + ".")
    return out

def message_class(message, proto, include=os.path.dirname(os.path.realpath(__file__))):
    # python class for message in proto (maps parse as repeated entries, see above)
    pool, _map_entries = _pool(include, proto)
    try:
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(message))
    except KeyError:
        raise DecodeNamedError("type not defined in %s: %s" % (proto, message))

def decode_named(message, proto, data, include=os.path.dirname(os.path.realpath(__file__))):
    # text that `protoc --decode=message -I=include proto` prints for data; raises DecodeNamedError where protoc fails
    pool, map_entries = _pool(include, proto)
    try:
        m = message_factory.GetMessageClass(pool.FindMessageTypeByName(message))()
    except KeyError:
        raise DecodeNamedError("type not defined in %s: %s" % (proto, message))
    data, placeholders = bytes(data), {}
    if _has_groups(m.DESCRIPTOR):
        data = _renumber_delimited(data, m.DESCRIPTOR, placeholders, _field_numbers(data, set()))
    try:
        m.MergeFromString(data)
    except Exception as e:
        raise DecodeNamedError("Failed to parse input (%s --decode=%s): %s" % (proto, message, e))
    missing = _init_errors(m)
    out = io.StringIO()
    if missing:
        out.write("warning:  Input message is missing required fields:  %s\n" % ", ".join(missing))
    _Printer(out, map_entries, placeholders).PrintMessage(m)
    return out.getvalue()
