"""ICING (GMS on-device search and the libraries that log under it) message
classes from icing_named.proto.

Built at import from the compiled descriptor icing/icing_named.desc, like
gboard_named_pb.py, so it loads under the venv's protobuf runtime.

After changing icing_named.proto, rebuild the descriptor with:
  protoc --proto_path=. --descriptor_set_out=icing/icing_named.desc icing_named.proto
"""

import os

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

_desc = os.path.join(os.path.dirname(os.path.realpath(__file__)), "icing", "icing_named.desc")
with open(_desc, "rb") as _f:
    _fds = descriptor_pb2.FileDescriptorSet.FromString(_f.read())
_pool = descriptor_pool.DescriptorPool()
for _file in _fds.file:
    _pool.Add(_file)

Icing_LogEntry = message_factory.GetMessageClass(_pool.FindMessageTypeByName("Icing_LogEntry"))
