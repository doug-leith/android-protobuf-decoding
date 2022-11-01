from google.protobuf.internal.decoder import _DecodeVarint32
from google.protobuf import text_format
import subprocess
import textwrap
import sys
import os
#import brotli
import urllib.parse
import zlib
import base64
import json
import tempfile
from mitmproxy import http, io
import struct


# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
import firebase_logbatch_pb2


def printBinaryString(string):
    for c in string:
        if c >= 32 and c <= 127:
            print('%c' % c, end='')
        else:
            print('\%X' % c, end='')
    print()


def findGzipMagicHeader(buf):
    found = -1
    for i in range(len(buf)):  # find gzip magic bytes 0x1f8b (easier than parsing header!)
        if buf[i] == 31 and buf[i+1] == 139:
            found = i
            break
    return found


def fieldIsSet(f):
    if f is None:
        return False
    elif len(str(f))==0:
        return False
    return True


def makeIter(tt):
    try:
        iterator = iter(tt)
    except TypeError:
        # not iterable
        tt=[tt]
    return tt

def GetHumanReadable(size, precision=2):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB']
    suffixIndex = 0
    while size > 1024:
        suffixIndex += 1  # increment the index of the suffix
        size = size/1024.0  # apply the division
    return "%.*f%s"%(precision, size, suffixes[suffixIndex])

def printPostBody(url, mimeType, postData, responseData="", responseCookies=""):

    # decode known google formats
    if url == 'https://www.google.com/loc/m/api':
        decode_gRPC(postData,decode_locm)
    elif url == "https://android-context-data.googleapis.com/google.internal.android.location.kollektomat.v1.KollektomatService/Offer":
        decode_gRPC(postData,decode_kollektomat)
    elif 'app-measurement.com/a' in url:
        print(decode_firebase_analytics(postData))
    elif url in ['https://android.clients.google.com/checkin', 'https://android.googleapis.com/checkin']:
        print(decode_checkin(postData))
    elif url in ['https://play.googleapis.com/log/batch', 'https://play.googleapis.com/vn/log/batch']:
        print(decode_log_batch(postData))
    elif "experimentsandconfigs/v1/getExperimentsAndConfigs" in url:
        decodeHeterodyneRequest(postData)
    elif "android.googleapis.com/auth/devicekey" in url:
        print(decode_deviceKeyRequest(postData))
    elif "play.googleapis.com/play/log" in url:
        if len(postData) > 0:
            print(decode_playstore(postData))
            #print("<skipping data>")
    elif "firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog" in url:
        print(postData)
        try:
            data = json.loads(postData)
            print("\nLOGEVENTS FROM JSON (decoded):")
            count = 1
            for log in data['logRequest']:
                tag=""
                if log['logSourceName']:
                    tag=log['logSourceName']
                for e in log['logEvent']:
                    buf = base64.b64decode(e['sourceExtension'])
                    try:
                        if tag == "FIREPERF":
                            print(tag+" log event "+str(count)+":")
                            print(decode_firebase_logbatch(buf))
                        else:
                            try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)
                    except Exception as ee:
                        print("Firelog decoding failed:")
                        print(repr(ee))
                        try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)
                print()
                count = count+1
        except Exception as e:
            print("JSON decoding failed:")
            print(repr())
    ### decode using MIMO headers
    elif mimeType in ['application/x-protobuf', 'application/x-protobuffer', 'application/x-brotli', 'application/octet-stream','application/x-gzip','application/protobuf']:
        try_decode_pb_array("POST Body", postData, decode_pb)
    elif mimeType == 'application/grpc':
        decode_gRPC(postData, decode_pb)
    elif mimeType == 'application/json':
        print(postData.decode('utf8'))
    elif mimeType == 'application/x-www-form-urlencoded':
        try:
            print(urllib.parse.unquote(postData.decode('utf8')))
        except:
            print(postData)
    #elif mimeType == 'application/x-brotli':
    #    print(brotli.decompress(postData).decode('utf8'))
    elif len(postData) > 0:
        #print(entry['request']['postData'])
        printBinaryString(postData)

    ############################
    # take a look at the content of the response ...
    if len(responseCookies) > 0:
        print("Response cookies:")
        print(responseCookies)
    if 'android.googleapis.com/auth' in url:
        print("Response data from android.googleapis.com/auth:")
        try:
            for line in responseData.splitlines():
                printBinaryString(line)
        except:
            printBinaryString(responseData)
    elif 'mail.google.com/mail/ads/main' in url:
        try_decode_pb_array("Response data from mail.google.com/mail/ads/main", responseData, decode_pb)
    elif "experimentsandconfigs/v1/getExperimentsAndConfigs" in url:
        if len(responseData) > 0:
            decodeHeterodyneResponse(responseData)
    elif url in ['https://android.clients.google.com/checkin','https://android.googleapis.com/checkin']:
        res = decode_checkin_response(responseData)
        if res == "Failed":
            try_decode_pb_array("Response data from android.clients.google.com/checkin", responseData, decode_pb)
        else:
            print("Response data from android.clients.google.com/checkin:")
            print(res)
    elif "firebase" in url or "firebase" in url:
        #f responseData and len(responseData)>0:
        #   try_decode_pb_array("Response data from "+url, responseData, decode_pb) 
        print("Response from "+url+":")
        print(responseData)  
    elif "app-measurement.com/config/app/" in url: 
        print("Response from "+url+":")
        try:
            print(decode_pb(responseData))
        except:
            print(responseData)
    elif "app-measurement" in url: 
        print("Response from "+url+":")
        print(responseData)  
    elif "play-fe.googleapis.com" in url: 
        res = decode_playstore_response(responseData)
        if res == "Failed":
            try_decode_pb_array("Response from "+url, responseData, decode_pb)
        else:
            print("Response data from "+url+":")
            print(res)
    

def decode_pb(bb, verbose=False, debug=False):
    # try to decode a protobuf without knowing the schema, usually works fine
    # but there can be ambiguity in encoding and so result may not be quite what we'd
    # like e.g. an embedded protobuf might be parsed as a bytes field.
    if debug:
        fname='/tmp/bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(bb)
    f.close()
    try:
        res = subprocess.check_output("cat "+fname+" | protoc --decode_raw", 
                                       shell=True, stderr=subprocess.STDOUT, text=True)
        return res
    except subprocess.CalledProcessError as e:  
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def try_decode_pb_array(name, buf, decoder, verbose=True, debug=False):
    # tries to decode as protobuf array, if that fails then print out the binary data
    if buf is None:
        return
    res = decoder(buf, verbose=False, debug=debug)  # just a canary, likely will fail so silence error reporting
    #print("first try: "+res)
    if res == "Failed" or res is None:
        decode_pb_array(name, buf, decoder, verbose=verbose, debug=debug)
    elif name is not None:
        print(name+":{\n"+textwrap.indent(res, '   ')+"}")


def decode_pb_array(name, buf, decoder, verbose=False, debug=False):
    # decodes a protobuf array
    # a protobuf array is a sequence of <varint/length><protobuf> entries.
    orig = buf
    pos = 0
    count = 1
    while (pos < len(buf)):
        try:
            msg_len, new_pos = _DecodeVarint32(buf[pos:len(buf)], 0)
        except:
            # pretty bad if this happens, just dump out the binary and exit
            print("Problem decoding Varint32 in protobuf array.  Raw POST data is:")
            printBinaryString(orig)
            return
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
        next_bytes=buf[pos:(pos+msg_len)]
        if debug:
            # keep a copy, helps when debugging
            f = open('/tmp/event_debug_bytes', 'wb')
            f.write(next_bytes)
            f.close()
        res = decoder(next_bytes, verbose=False, debug=debug)
        #print(res)
        if (res == "Failed" or res is None): 
            # protobuf decoding failed, fall back to printing binary
            print("Problem decoding protobuf, trying raw decode:", pos, pos+msg_len, len(buf))
            res = decode_pb(next_bytes, verbose=verbose, debug=debug)  # try raw decoding of protobuf, maybe schema mismatch
            if (res == "Failed"):
                print("Dumping binary data:")
                print(str(orig))  # dump out raw data
                # keep a copy, helps when debugging
                f = open('/tmp/event_debug_bytes2', 'wb')
                f.write(orig)
                f.close()
                return
        if name is not None:
            print(name+" "+str(count)+": {\n"+textwrap.indent(res, '   ')+"}")
        pos = pos+msg_len
        count = count+1
    #if pos != len(buf):  # shouldn't happen
    #    raise Exception("decode_pb_array(): pos!=buflen ("+str(pos)+"/"+str(len(buf))+")")


# see https://github.com/protocolbuffers/protobuf/blob/cac9765af0ace57ce00b6ea07b8829339a622b1d/python/google/protobuf/text_format.py#L56
def protoUnknownFieldsToString(pb):
    out = text_format.TextWriter(as_utf8=False)
    printer = text_format._Printer(out)
    printer._PrintUnknownFields(pb.UnknownFields())
    result = out.getvalue()
    out.close()
    return result


def protoToString(name, pb):
    #for field, value in pb.ListFields():
    #    print(field.full_name, value)
    #    if field.message_type:
    #        for f in field.UnknownFields():
    #          print(str(f.field_number)+": "+str(f.data))
    #for f in pb.UnknownFields():
    #    print(str(f.field_number)+": "+str(f.data))
    #exit()
    decoded = name+" {\n"
    decoded = decoded+textwrap.indent(text_format.MessageToString(pb, print_unknown_fields=True), '   ')+"}"
    return decoded


def decode_gRPC(data, decoder):
    while data:
        try:
            compressed, length = struct.unpack('!?i', data[:5])
            message = struct.unpack('!%is'%length, data[5:5+length])[0]
            if compressed:
                # assume gzip, actual compression has to be parsed from 'grpc-encoding' header
                # see also: https://www.oreilly.com/library/view/grpc-up-and/9781492058328/ch04.html
                message = zlib.decompress(message, 32+zlib.MAX_WBITS)
        except Exception as e: 
            print(repr(e))
            print("Invalid gRPC message: ",(data,))
            return
        try_decode_pb_array("POST Body", message, decoder)
        data = data[5+length:]


#def decode_gRPC(postData, decoder):
#    found = findGzipMagicHeader(postData)
#    if found > 0:
#        protobuf = postData[found:]
#        try: 
#            postData = zlib.decompress(protobuf, 32+zlib.MAX_WBITS)
#        except:
#            print("problem unzipped POST data, raw payload:")
#            printBinaryString(postData)
#            return
#        try_decode_pb_array("POST Body", postData, decoder)
#    else:
#        # remove 5 byte gRPC header 
#        try_decode_pb_array("POST Body", postData[5:], decoder)


def decode_firebase_analytics(bytes, verbose=True, debug=False):
    # partially decodes POST payload from https://app-measurement.com/a endpoint
    try:
        # print(bytes)
        #f = open('/tmp/appmeas_bytes', 'wb')
        if debug:
            fname='/tmp/appmeas_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        return subprocess.check_output("python3 '"+mypath+"/app_measurement_decode.py' '"+fname+"'", 
                                       shell=True, stderr=subprocess.STDOUT, text=True)
        # pb = app_measurement_pb2.POST_body()
        # pb.ParseFromString(bytes)
        # return str(pb)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed: "


def decode_firebase_logbatch(bytes, verbose=False, grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/firebaselogbatch_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"FirelogEvent\" -I='"+mypath+"' firebase_logbatch.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        if grep:
            try:
                firebase = firebase_logbatch_pb2.FirelogEvent()
                firebase.ParseFromString(bytes)
                if fieldIsSet(firebase.traceMetric) and firebase.traceMetric.name:
                    print('+++FIREBASE_BATCH',firebase.traceMetric.clientStartTimeis,firebase.applicationInfo.androidAppInfo.packageName, firebase.applicationInfo.appInstanceId, firebase.traceMetric.name)
            except Exception as e:
                print("firebase grep failed:")
                print(repr(e))
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_log_batch(bytes, verbose=True, debug=False):
    # partially decodes POST payload from https://play.googleapis.com/log/batch endpoint
    try:
        #f = open('/tmp/batch_bytes', 'wb')
        if debug:
            fname='/tmp/batch_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        str = subprocess.check_output("python3 '"+mypath+"/logbatch_decode.py' '"+fname+"'", 
                                      shell=True, stderr=subprocess.STDOUT, text=True)
        # print(str)
        return(str)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_playstore(bytes, verbose=True, debug=False):
    # partially decodes POST payload from https://play.googleapis.com/play/log?format=raw&proto_v2=true endpoint
    try:
        #f = open('/tmp/playstore_bytes', 'wb')
        if debug:
            fname='/tmp/playstore_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        str = subprocess.check_output("python3 '"+mypath+"/playstore_decode.py' '"+fname+"'", 
                                      shell=True, stderr=subprocess.STDOUT, text=True)
        # print(str)
        return(str)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_playstore_response(bytes, verbose=True, debug=False):
    # partially decodes response from https://play-fe.googleapis.com/fdfe
    try:
        if debug:
            fname='/tmp/playstore_response_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"Response.ResponseWrapper\" -I='"+mypath+"/finsky_protobuf' response.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        # print(str)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_checkin(bytes, verbose=False, debug=False):
    try:
        #f = open('/tmp/checkin_bytes', 'wb')
        if debug:
            fname='/tmp/checkin_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"CheckinRequest\" -I='"+mypath+"' checkin.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #decoded = subprocess.check_output("protoc --decode=\"AndroidCheckinRequest\" -I='"+mypath+"' checkin_chrome.proto  </tmp/checkin_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_checkin_response(bytes, verbose=False, debug=False):
    try:
        #f = open('/tmp/checkin_resp_bytes', 'wb')
        if debug:
            fname='/tmp/checkin_resp_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"CheckinResponse\" -I='"+mypath+"' checkin.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #decoded = subprocess.check_output("protoc --decode=\"AndroidCheckinResponse\" -I='"+mypath+"' checkin_chrome.proto  </tmp/checkin_resp_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_deviceKeyRequest(bytes, verbose=False, debug=False):
    try:
        #f = open('/tmp/devicekey_bytes', 'wb')
        if debug:
            fname='/tmp/devicekey_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"DeviceKeyRequest\" -I='"+mypath+"' devicekeyrequest.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_locm(bytes, verbose=False, debug=False):
    try:
        #f = open('/tmp/locm_bytes', 'wb')
        if debug:
            fname='/tmp/locm_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"LocRequest\" -I='"+mypath+"' locm.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"
 
def decode_kollektomat(bytes, verbose=False,debug=False):
    try:
        #f = open('/tmp/locm_bytes', 'wb')
        if debug:
            fname='/tmp/kollektomat_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"KollektomatRequest\" -I='"+mypath+"' locm.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def base64padding(header):
    if len(header) % 4 == 2:
        extras="=="
    elif len(header) % 4 == 3:
        extras="="
    else:
        extras=""
    return extras
  

def decodeBase64ZippedProto(header):
    try:
        buf = base64.b64decode(header + base64padding(header))
        unzipped = zlib.decompress(buf, 32 + zlib.MAX_WBITS)
        return decode_pb(unzipped)
    except Exception as e:
        print(e)
        return "Failed"


def decodeXGoogXSpatula(header, debug=False):
    buf = base64.b64decode(header+base64padding(header))
    #try_decode_pb_array("Decoded x-goog-spatula header", buf, decode_pb)
    #f = open('/tmp/spatula_bytes', 'wb')
    if debug:
        fname='/tmp/spatula_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(buf)
    f.close()
    decoded = subprocess.check_output("protoc --decode=\"GoogleSpatulaHeader\" -I='"+mypath+"' spatula.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
    print("Decoded x-goog-spatula header:\n", decoded)
    #return(decoded)


def decodeHeterodyneResponse(buf, verbose=True, debug=False):
    #f = open('/tmp/heterodyneresponse_bytes', 'wb')
    if debug:
        fname='/tmp/heterodyneresponse_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(buf)
    f.close()
    try:
        decoded = subprocess.check_output("protoc --decode=\"HeterodyneResponse\" -I='"+mypath+"' exptsandconfigs_response.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        print("Decoded heterodyne response:\n", decoded)
    except subprocess.CalledProcessError as e:  
        if verbose:
            print(e.output)
            print(e)
        print("Failed to decode heterodyne response, raw response:")
        printBinaryString(buf)


def decodeHeterodyneRequest(buf, verbose=True, debug=False):
    #f = open('/tmp/heterodynereq_bytes', 'wb')
    if debug:
        fname='/tmp/heterodynereq_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(buf)
    f.close()
    try:
        decoded = subprocess.check_output("protoc --decode=\"HeterodyneRequest\" -I='"+mypath+"' exptsandconfigs_request.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        print("Decoded heterodyne request:\n", decoded)
    except subprocess.CalledProcessError as e:  
        if verbose:
            print(e.output)
            print(e)
        print("Failed to decode heterodyne request, raw request:")
        printBinaryString(buf)


def decode_wbxml(buf, verbose=True, debug=False):
    # decode binary XML format https://en.wikipedia.org/wiki/WBXML
    # using libwbxml https://github.com/libwbxml/libwbxml
    unzipped = buf  # zlib.decompress(buf,32 + zlib.MAX_WBITS)
    #f = open('/tmp/wbxml', 'wb')
    if debug:
        fname='/tmp/wbxml'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(unzipped)
    f.close()
    try:
        subprocess.check_output("wbxml2xml -o /tmp/xml "+fname, 
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


def decode_bond(buf):
    # this uses OneDrive telemetry schema from Samsung handset, not portable
    # and needs decoder executable "onedrive" to be in directory
    unzipped = buf  # zlib.decompress(buf,32 + zlib.MAX_WBITS)
    f = open('/tmp/bond', 'wb')
    f.write(unzipped)
    f.close()
    try:
        return subprocess.check_output("./onedrive", shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        print(e)
        return "Failed"


class PrintTrace:

    response_content_sum = 0
    request_content_sum = 0
    request_dict_sum = {}
    start_timestamp = -1

    # def __init__(self):
    #    self.f = open("tmp.mitm", "wb")
    #    self.w = io.FlowWriter(self.f)

    # def done(self):
    #    self.f.close()

    def response(self, flow:http.HTTPFlow):
        print("\ntimestamp %s"%(flow.request.timestamp_start))
        print("%s %s" % (flow.request.method, flow.request.pretty_url))
        req = flow.request.path.split("?")
        req = req[0]
        if req not in self.request_dict_sum:
            self.request_dict_sum[req] = 0
        for q in flow.request.query:
            self.request_content_sum += len(flow.request.query[q])
            self.request_dict_sum[req] += len(flow.request.query[q])
        headers=[]
        for hh in flow.request.headers:
            h={'name':hh, 'value':flow.request.headers[hh]}
            headers.append(h)
            print(h['name'], ':', h['value'])
            if h['name'].lower() == "x-goog-spatula":
                decodeXGoogXSpatula(h['value'])
            elif h['name'].lower() in ["x-dfe-phenotype", "x-ps-rh"]:
                # TO DO: sometimes the unzipped here fails, which seems odd.
                res = decodeBase64ZippedProto(h['value'])
                if res != "Failed":
                    print("Decoded "+h['name']+" header:\n", res)
            elif h['name'].lower() == "x-dfe-encoded-targets":
                val = h['value'] + '=='
                try:
                    buf = base64.b64decode(val+base64padding(val))
                    print("Decoded x-dfe-encoded-targets header:\n", decode_pb(buf))
                except:
                    pass
            elif h['name'].lower() == "x-firebase-client":
                val = h['value']
                try:
                    buf = base64.urlsafe_b64decode(val+base64padding(val))
                    unzipped = zlib.decompress(buf, 32 + zlib.MAX_WBITS)
                    print("Decoded x-firebase-client header:\n", unzipped)
                except Exception as e:
                    print(e)

        postData = ""
        mimeType = ""
        if flow.request.method == "POST":
            postData = flow.request.content
            if flow.response.headers['Content-Type']:
                mimeType = flow.response.headers['Content-Type'] 
 
        responseCookies = ""
        for hh in flow.response.headers:
            h={'name':hh, 'value':flow.response.headers[hh]}
            if h['name'] == 'cookie':
                responseCookies = responseCookies+h['name']+": " + h['value']+"\n"
        for hh in flow.request.headers:
            if 'set-cookie' in h['name']:
                h={'name':hh, 'value':flow.request.headers[hh]}
                responseCookies = responseCookies+h['name']+": " + h['value']+"\n"
        if len(flow.response.content) > 0:
            responseData = flow.response.content
        else:
            responseData = None

        printPostBody(flow.request.pretty_url, mimeType, postData, responseData=responseData, responseCookies=responseCookies) 
 

#tell mitmproxy to use PrintTrace() class as an addon, this way we can use "-s decoding_helpers.py" as mitmdump option and things just work
addons = [PrintTrace()]


