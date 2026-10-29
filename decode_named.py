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
# - missing required fields give protoc's warning line before the message
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

class _Printer(text_format._Printer):
    def __init__(self, out, map_entries):
        super().__init__(out, as_utf8=False)
        self.map_entries = map_entries

    def PrintMessage(self, message):
        # fields in field-number order, then unknown fields; no Any expansion
        for field, value in message.ListFields():
            if field.message_type is not None and field.message_type.full_name in self.map_entries:
                key, val = field.message_type.fields_by_name["key"], field.message_type.fields_by_name["value"]
                for entry in sorted(value, key=lambda e: e.key):
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
        fields = [(f, w, _enum_value(v) if w == 0 and f in known and known[f].enum_type is not None else v)
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

def decode_named(message, proto, data, include=os.path.dirname(os.path.realpath(__file__))):
    # text that `protoc --decode=message -I=include proto` prints for data; raises DecodeNamedError where protoc fails
    pool, map_entries = _pool(include, proto)
    try:
        m = message_factory.GetMessageClass(pool.FindMessageTypeByName(message))()
    except KeyError:
        raise DecodeNamedError("type not defined in %s: %s" % (proto, message))
    try:
        m.MergeFromString(bytes(data))
    except Exception as e:
        raise DecodeNamedError("Failed to parse input (%s --decode=%s): %s" % (proto, message, e))
    missing = m.FindInitializationErrors()
    out = io.StringIO()
    if missing:
        out.write("warning:  Input message is missing required fields:  %s\n" % ", ".join(missing))
    _Printer(out, map_entries).PrintMessage(m)
    return out.getvalue()
