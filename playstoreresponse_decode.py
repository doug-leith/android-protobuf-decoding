import subprocess
import textwrap
import sys
import os
import base64
import tempfile
import traceback

mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
from decoding_helpers import decode_pb, decode_pb_array, protoUnknownFieldsToString, protoToString

sys.path.append(mypath+"/finsky_protobuf")
import response_pb2


#f = open('/tmp/playstore_bytes', 'rb')
if len(sys.argv)>1:
    fname=sys.argv[1]
else:
    fname='/tmp/playstore_bytes'
f = open(fname, 'rb')
data = f.read()
f.close()
#print(decode_pb(data))

try:
    #decoded = subprocess.check_output("protoc --decode=\"Response.ResponseWrapper\" -I='"+mypath+"/finsky_protobuf' response.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
    # print out untidily ...
    #print(decoded)

    playstore = response_pb2.ResponseWrapper()
    playstore.ParseFromString(data)
    print(playstore)
    if playstore.serverLogsCookie is not None:
        print('Decoded serverLogsCookie:')
        print(decode_pb(playstore.serverLogsCookie))
    try:
        # print out any other fields we might have missed
        unknown = protoUnknownFieldsToString(playstore)
        if len(unknown) > 0:
            print(unknown)
    except:
        pass

except Exception as e:
    print(repr(e))
    traceback.print_exc(file=sys.stdout)

