from google.protobuf.internal.decoder import _DecodeVarint32
from google.protobuf import text_format
#from google.protobuf import unknown_fields
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
from mitmproxy import http, tcp
import struct
import re
import h2
import warnings
import firebase_logbatch_pb2
import locm_pb2
import datetime
from mitmproxy.utils import strutils
from mitmproxy import ctx
# suppress protobuf deprecation warnings, at least for now
warnings.filterwarnings("ignore")

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)

#print(sys.version)
#print(text_format.__file__)


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

def printPostBody(url, mimeType, postData, responseData="", responseCookies="", responseHeaders="", verboseResponse=True):

    # decode known google formats
    if url == 'https://www.google.com/loc/m/api':
        decode_gRPC(postData,decode_locm)
    elif url == "https://android-context-data.googleapis.com/google.internal.android.location.kollektomat.v1.KollektomatService/Offer":
        #print("calling decode_gRPC(postData,decode_kollektomat)")
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
        #print("calling decode_gRPC(postData, decode_pb)")
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
    if len(responseHeaders) > 0:
        print("Response headers:")
        print(responseHeaders)        
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
    elif url in ['https://play.googleapis.com/log/batch', 'https://play.googleapis.com/vn/log/batch']:
        if len(responseData) > 0:
            print("Response from "+url+":")
            print(decode_pb(responseData)) 
    elif verboseResponse:
        # print out all responses
        if (responseData is not None) and (len(responseData) > 0):
            print("Response from "+url+":")
            print(responseData) 
 
    

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
    #printer._PrintUnknownFields(unknown_fields.UnknownFieldSet(pb))
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
        try_decode_pb_array("POST Body (gRPC)", message, decoder)
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
        # finsky_protobuf's are from // and https://github.com/mmcloughlin/finsky/tree/master/protobuf
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

kollektomat_count=0
def decode_kollektomat(bytes, verbose=True, debug=True):
    #print("decode_kollektomat")
    try:
        #f = open('/tmp/locm_bytes', 'wb')
        if True:
            global kollektomat_count
            fname='/tmp/kollektomat_bytes_'+str(kollektomat_count)
            kollektomat_count = kollektomat_count + 1
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        #print(fname)
        decoded = subprocess.check_output("protoc --decode=\"KollektomatRequest\" -I='"+mypath+"' locm.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        if True:
            # save location data
            kollektomat = locm_pb2.KollektomatRequest()
            kollektomat.ParseFromString(bytes)
            for request in kollektomat.request:
                if not fieldIsSet(request.locRequest):
                    continue
                if not request.locRequest.signals:
                    continue
                for signals in request.locRequest.signals:
                    if fieldIsSet(signals.gpsInfo) and signals.gpsInfo.latLong:
                        fname='/tmp/kollektomat_gpslocs'
                        f = open(fname, 'a')
                        print("lat: ",float(signals.gpsInfo.latLong.lat)/1.0e7, " long: ", float(signals.gpsInfo.latLong.long)/1.0e7, "gpsTime: ", signals.gpsInfo.gpsTime, ' ', end='', file=f)
                        if fieldIsSet(signals.gpsInfo.speed):
                            print("speed: ",signals.gpsInfo.speed, end='', file=f)
                        print(file=f)
                        f.close()
                    elif fieldIsSet(signals.wifiSignals) and signals.wifiSignals.wifiSignal:
                        fname='/tmp/kollektomat_wifilocs'
                        f = open(fname, 'a')
                        print(int(signals.wifiSignals.timestamp),' ', end='', file=f)
                        for wifi in signals.wifiSignals.wifiSignal:
                            print(int(wifi.macAddress),int(wifi.rssi),' ', end='', file=f)
                        print(file=f)
                        f.close()
        return(decoded)
    except subprocess.CalledProcessError as e:
        if True:
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

def decodeFLRequestRequest(buf, verbose=True, debug=False):
    if debug:
        fname='/tmp/fl_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    #fname='/tmp/fl_bytes'
    #f = open(fname, 'wb')
    f.write(buf)
    f.close()
    try:
        decoded = subprocess.check_output("protoc --decode=\"google.internal.federatedml.v2.ClientStreamMessage\" -I='"+mypath+"/federated_learning_protos' federated_api.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print("Decoded FL request:\n", decoded)
        return decoded
    except subprocess.CalledProcessError as e:  
        if verbose:
            print(e.output)
            print(e)
            #print("Failed to decode FLRequest, raw request:")
            #printBinaryString(buf)
        return "Failed"

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

def bytes_to_escaped_str(
    data: bytes, keep_spacing: bool = False, escape_single_quotes: bool = False
) -> str:
    """
    Take bytes and return a safe string that can be displayed to the user.
    Single quotes are always escaped, double quotes are never escaped:
        "'" + bytes_to_escaped_str(...) + "'"
    gives a valid Python string.
    Args:
        keep_spacing: If True, tabs and newlines will not be escaped.
    """

    if not isinstance(data, bytes):
        raise ValueError(f"data must be bytes, but is {data.__class__.__name__}")
    # We always insert a double-quote here so that we get a single-quoted string back
    # https://stackoverflow.com/questions/29019340/why-does-python-use-different-quotes-for-representing-strings-depending-on-their
    ret = repr(b'"' + data).lstrip("b")[2:-1]
    if not escape_single_quotes:
        ret = re.sub(r"(?<!\\)(\\\\)*\\'", lambda m: (m.group(1) or "") + "'", ret)
    if keep_spacing:
        ret = re.sub(
            r"(?<!\\)(\\\\)*\\([nrt])",
            lambda m: (m.group(1) or "") + dict(n="\n", r="\r", t="\t")[m.group(2)],
            ret,
        )
    return ret


class PrintTrace:

    start_timestamp = -1

    # federated learning uses http2 with prior info, which is not supported by mitmproxy, so we need to handle
    # http2 stream processing ourselves.
    client_conns={} # we use h2 package to keep track of http2 client state per connection, and allow us to decode stream
    server_conns={} # ditto server side of connection
    def handle_fl(self, flow: tcp.TCPFlow):
    #def tcp_message(self, flow: tcp.TCPFlow):
        message=flow.messages[-1]
        if message.from_client:
            arrow=" -> "
        else:
            arrow=" <- "
        #print(flow.client_conn.peername, flow.server_conn.peername, flow.messages[-1].from_client)
        print(flow.client_conn.peername[0]+":"+str(flow.client_conn.peername[1])+arrow+flow.server_conn.peername[0]+":"+str(flow.server_conn.peername[1]))
        #print(flow.messages[-1].content)
        if flow.client_conn.peername not in self.client_conns.keys():
            client_config=h2.config.H2Configuration(validate_inbound_headers=False)
            self.client_conns[flow.client_conn.peername] = h2.connection.H2Connection(client_config)
            server_config=h2.config.H2Configuration(client_side=False)
            self.server_conns[flow.client_conn.peername] = h2.connection.H2Connection(server_config)
            #print(self.client_conns)
        client_conn=self.client_conns[flow.client_conn.peername]
        server_conn=self.server_conns[flow.client_conn.peername]
        if not message.from_client:
            print("Server sent:")
            res=client_conn.receive_data(message.content)
            for r in res:
                if isinstance(r,h2.events.RequestReceived) or isinstance(r,h2.events.TrailersReceived):
                    print("Headers:")
                    #print(r.headers)
                    for h in r.headers:
                        print(h[0].decode()+": "+h[1].decode())
                elif isinstance(r,h2.events.DataReceived):
                    #print("<Data>")
                    decode_gRPC(r.data,decode_pb)
                else:
                    print(r)
        else:
            print("Client sent:")
            res=server_conn.receive_data(message.content)
            for r in res:
                if isinstance(r,h2.events.RequestReceived) or isinstance(r,h2.events.TrailersReceived):
                    print("Headers:")
                    #print(r.headers)
                    for h in r.headers:
                        print(h[0].decode()+": "+h[1].decode())
                elif isinstance(r,h2.events.DataReceived):
                    #print("<Data>")
                    decode_gRPC(r.data,decodeFLRequestRequest)
                else:
                    print(r)
        print('----------------')

    def tcp_message(self, flow: tcp.TCPFlow):
        assumeFL = True
        if assumeFL:
            # assume a raw tcp connection is a federated learning exchange
            # TO DO: add some checking so that fall back to something reasonable if in fact its something else
            # i.e. add check that its http2 and that :path header is federatedml-pa
            self.handle_fl(flow)
        else:
            # just dump the raw data
            message = flow.messages[-1]
            if message.from_client:
                arrow=" -> "
            else:
                arrow=" <- "
            print(flow.client_conn.peername[0]+":"+str(flow.client_conn.peername[1])+arrow+flow.server_conn.peername[0]+":"+str(flow.server_conn.peername[1]))
            print("content=",strutils.bytes_to_escaped_str(message.content))

    def load(self, loader):
        # add new command line options for start and end time of dump
        loader.add_option(
            name="expt_starttime",
            typespec=int,
            default=-1,
            help="Add a start timestamp, ignore earlier connections")
        loader.add_option(
            name="expt_endtime",
            typespec=int,
            default=-1,
            help="Add a end timestamp, ignore later connections")

    def response(self, flow:http.HTTPFlow):
        
        # check command line options for start and end time of dump
        if ctx.options.expt_starttime and ctx.options.expt_starttime>0:
            #print("start",flow.request.timestamp_start,ctx.options.expt_starttime)
            if flow.request.timestamp_start < ctx.options.expt_starttime:
                return
        if ctx.options.expt_endtime and ctx.options.expt_endtime>0:
            #print("end",flow.request.timestamp_start,ctx.options.expt_endtime)
            if flow.request.timestamp_start > ctx.options.expt_endtime:
                return

        print("\ntimestamp %s (%s UTC)"%(flow.request.timestamp_start, datetime.datetime.fromtimestamp(flow.request.timestamp_start,datetime.timezone.utc)))
        print("%s %s" % (flow.request.method, flow.request.pretty_url))
        googleOnly = True
        if googleOnly:
            # bail if not a google related connection
            url = flow.request.pretty_url
            if not('goog' in url or 'doubleclick' in url or 'app-measurement' in url or 'firebase' in url or 'appspot' in url):
                return
        req = flow.request.path.split("?")
        req = req[0]
        request_content_sum = 0
        for q in flow.request.query:
            request_content_sum += len(flow.request.query[q])
        headers=[]
        for hh in flow.request.headers:
            h={'name':hh, 'value':flow.request.headers[hh]}
            headers.append(h)
            print(h['name'], ':', h['value'])
            request_content_sum += len(h['value'])
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
            request_content_sum += len(postData)
            if 'Content-Type' in flow.response.headers:
                mimeType = flow.response.headers['Content-Type'] 
            elif 'content-type' in flow.response.headers:
                mimeType = flow.response.headers['content-type']
 
        responseCookies = ""
        for hh in flow.response.headers:
            h={'name':hh, 'value':flow.response.headers[hh]}
            if 'cookie' in h['name'] or 'Cookie' in h['name']:
                responseCookies = responseCookies+h['name']+": " + h['value']+"\n"
        for hh in flow.request.headers:
            # shouldn't happen
            if 'set-cookie' in h['name'] or 'Set-Cookie' in h['name']:
                h={'name':hh, 'value':flow.request.headers[hh]}
                responseCookies = responseCookies+h['name']+"(request!): " + h['value']+"\n"
        if flow.response.content is not None and len(flow.response.content) > 0:
            responseData = flow.response.content
        else:
            responseData = None

        printPostBody(flow.request.pretty_url, mimeType, postData, responseData=responseData, responseCookies=responseCookies, responseHeaders=flow.response.headers) 
        print('+++REQUEST ', flow.request.pretty_url, request_content_sum, flow.request.timestamp_start)
 

#tell mitmproxy to use PrintTrace() class as an addon, this way we can use "-s decoding_helpers.py" as mitmdump option and things just work
addons = [PrintTrace()]


