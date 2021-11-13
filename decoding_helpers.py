from google.protobuf.internal.decoder import _DecodeVarint32
import subprocess
import textwrap
import sys
import os

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)


def decode_pb(bb, verbose=False):
    # try to decode a protobuf without knowing the schema, usually works fine
    # but there can be ambiguity in encoding and so result may not be quite what we'd
    # like e.g. an embedded protobuf might be parsed as a bytes field.
    f = open('/tmp/bytes', 'wb')
    f.write(bb)
    f.close()
    try:
        return subprocess.check_output("cat /tmp/bytes | protoc --decode_raw", 
                                       shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:  
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def try_decode_pb_array(name, buf, decoder, verbose=True):
    # tries to decode as protobuf array, if that fails then print out the binary data
    res = decoder(buf, False)  # just a canary, likely will fail so silence error reporting
    # print("first try: "+res)
    if res == "Failed":
        decode_pb_array(name, buf, decoder, verbose)
    elif name is not None:
        print(name+":{\n"+textwrap.indent(res, '   ')+"}")


def decode_pb_array(name, buf, decoder, verbose=False):
    # decodes a protobuf array
    # a protobuf array is a sequence of <varint/length><protobuf> entries.
    pos = 0
    while (pos < len(buf)):
        msg_len, new_pos = _DecodeVarint32(buf[pos:len(buf)], 0)
        #if msg_len <= 0:  # shouldn't happen
        #    raise Exception("decode_pb_array(): msg_len <= 0 ("+str(msg_len)+")")
        #if new_pos <= 0:  # shouldn't happen
        #    raise Exception("decode_pb_array(): new_pos <= 0 ("+str(new_pos)+")")
        #if pos+new_pos > len(buf):  # shouldn't happen
        #    raise Exception("decode_pb_array(): pos+new_pos > buflen")
        #if pos+new_pos+msg_len > len(buf):  # shouldn't happen
        #    raise Exception("decode_pb_array(): pos+new_pos+msg_len > buflen")
        pos = pos+new_pos
        # print("Decoding message of length "+str(msg_len)+" ("+str(pos)+","+str(len(buf))+")")
        bytes = buf[pos:(pos+msg_len)]
        # keep a copy, helps when debugging
        f = open('/tmp/event_bytes', 'wb')
        f.write(bytes)
        f.close()
        res = decoder(bytes, verbose)
        # print(res)
        if (res == "Failed"): 
            # protobuf decoding failed, fall back to printing binary
            print("Problem decoding protobuf, trying raw decode:")
            print("***decode_pb_array: ", pos, pos+new_pos, pos+new_pos+msg_len, len(buf))
            res = decode_pb(bytes, verbose)  # try raw decoding of protobuf, maybe schema mismatch
            if (res == "Failed"):
                print("Dumping binary data:")
                res = str(bytes)  # dump out raw data
            # keep a copy, helps when debugging
            f = open('/tmp/event_debug_bytes', 'wb')
            f.write(bytes)
            f.close()
            # break
        if name is not None:
            print(name+":{\n"+textwrap.indent(res, '   ')+"}")
        pos = pos+msg_len
    #if pos != len(buf):  # shouldn't happen
    #    raise Exception("decode_pb_array(): pos!=buflen ("+str(pos)+"/"+str(len(buf))+")")


def decode_firebase_analytics(bytes, verbose=True):
    # partially decodes POST payload from https://app-measurement.com/a endpoint
    try:
        # print(bytes)
        f = open('/tmp/bytes', 'wb')
        f.write(bytes)
        f.close()
        return subprocess.check_output("python3 '"+mypath+"/app_measurement_decode.py'", 
                                       shell=True, stderr=subprocess.STDOUT, text=True)
        # pb = app_measurement_pb2.POST_body()
        # pb.ParseFromString(bytes)
        # return str(pb)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed: "


def decode_log_batch(bytes, verbose=True):
    # partially decodes POST payload from https://play.googleapis.com/log/batch endpoint
    try:
        f = open('/tmp/batch_bytes', 'wb')
        f.write(bytes)
        f.close()
        str = subprocess.check_output("python3 '"+mypath+"/logbatch_decode.py'", 
                                      shell=True, stderr=subprocess.STDOUT, text=True)
        # print(str)
        return(str)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_checkin(bytes, verbose=False):
    try:
        f = open('/tmp/checkin_bytes', 'wb')
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"CheckinRequest\" -I='"+mypath+"' checkin.proto  </tmp/checkin_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_wbxml(buf, verbose=True):
    # decode binary XML format https://en.wikipedia.org/wiki/WBXML
    # using libwbxml https://github.com/libwbxml/libwbxml
    unzipped = buf  # zlib.decompress(buf,32 + zlib.MAX_WBITS)
    f = open('/tmp/wbxml', 'wb')
    f.write(unzipped)
    f.close()
    try:
        subprocess.check_output("wbxml2xml -o /tmp/xml /tmp/wbxml", 
                                shell=True, stderr=subprocess.STDOUT, text=True)
        f = open('/tmp/xml', 'r')
        xml = f.read()
        f.close()
        return xml
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"
