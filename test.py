import test_pb2
import test_smaller_pb2
from google.protobuf import text_format
from google.protobuf.unknown_fields import UnknownFieldSet

def protoUnknownFieldsToString(pb, verbose=True):
    out = text_format.TextWriter(as_utf8=False)
    printer = text_format._Printer(out)
    try:
        # try to use newer unknown fields API
        printer._PrintUnknownFields(UnknownFieldSet(pb))
    except Exception as e:
        if verbose:
            print("In protoUnknownFieldsToString couldn't get UnknownFieldSet: ",e)
    #old API
    #printer._PrintUnknownFields(pb.UnknownFields())
    result = out.getvalue()
    out.close()
    return result


test = test_pb2.Test()
test.one=1
test.two="test"
buf = test.SerializeToString()

test_smaller = test_smaller_pb2.TestSmall()
test_smaller.ParseFromString(buf)
print(test_smaller)
print(protoUnknownFieldsToString(test_smaller))

