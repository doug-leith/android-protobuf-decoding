"""LATIN_IME (Gboard) message classes from gboard_named.proto.

Built at import from the compiled descriptor gboard/gboard_named.desc rather
than from protoc's generated _pb2 code: _pb2 files from a newer protoc
refuse to load under an older protobuf runtime (the venv has 5.29), while a
descriptor loads under any runtime that supports edition 2023.

After changing gboard_named.proto, rebuild the descriptor with:
  protoc --proto_path=. --descriptor_set_out=gboard/gboard_named.desc gboard_named.proto
"""

import os

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.internal import enum_type_wrapper

_desc = os.path.join(os.path.dirname(os.path.realpath(__file__)), "gboard", "gboard_named.desc")
with open(_desc, "rb") as _f:
    _fds = descriptor_pb2.FileDescriptorSet.FromString(_f.read())
_pool = descriptor_pool.DescriptorPool()
for _file in _fds.file:
    _pool.Add(_file)

LatinIME_LogEntry = message_factory.GetMessageClass(_pool.FindMessageTypeByName("LatinIME_LogEntry"))
KeyboardEvent = enum_type_wrapper.EnumTypeWrapper(_pool.FindEnumTypeByName("KeyboardEvent"))
