from google.protobuf.internal.decoder import _DecodeVarint32
from google.protobuf import text_format
from google.protobuf.unknown_fields import UnknownFieldSet
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
import cbor2 

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
            print('%X' % c, end='')
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

def stringContains(string, snippets):
    for s in snippets:
        if s in string:
            return True
    return False

def printUsingMimeType(payload,mimeType,tag="POST Body"):
    #print("mimetype:",mimeType)
    if len(payload)==0 or payload==None:
        return
    if mimeType in ['application/x-protobuf', 'application/x-protobuffer', 'application/x-brotli', 
                    'application/octet-stream','application/x-gzip','application/protobuf',
                     'application/vnd.google.octet-stream-compressible'
                    ]:
        res = try_decode_pb_array(tag+" ("+mimeType+" decoded)", payload, decode_pb)
        if "Dumping binary data" in res:
            # didn't decode as a protobuf, try gRPC
            res2 = decode_gRPC(payload, decode_pb, tag+" ("+mimeType+" decoded as gRPC)")
            if "Invalid gRPC message" in res2:
                print(payload)
            else:
                print(res2)
        else:
            print(res)
    elif mimeType == 'application/grpc':
        print(decode_gRPC(payload, decode_pb, tag+" ("+mimeType+" decoded)"))
    elif 'application/json' in mimeType: 
        print(tag+" ("+mimeType+"):")
        print(payload.decode('utf8'))
    elif mimeType == 'application/cbor':
        print(tag+" ("+mimeType+" decoded):")
        print(cbor2.loads(payload))
    elif mimeType == 'text/plain; charset=utf-8':
        print(tag+" ("+mimeType+"):")
        try:
            print(payload.decode('utf8'))
        except:
            print(payload)
    elif mimeType == 'application/x-www-form-urlencoded':
        try:
            print(tag+" ("+mimeType+" decoded):")
            print(urllib.parse.unquote(payload.decode('utf8')))
        except:
            print(tag+":")
            print(payload)
    elif mimeType == 'application/x-brotli':
        # Microsoft schema only
        print(tag+" ("+mimeType+" decoded):")
        print(brotli.decompress(postData).decode('utf8'))
    else:
        print(tag+" ("+mimeType+"):")
        print(payload)

def printHeaders(flowheaders, type=""):
    cookies = ""
    for hh in flowheaders:
        h={'name':hh, 'value':flowheaders[hh]}
        if 'cookie' in h['name'] or 'Cookie' in h['name'] or 'set-cookie' in h['name'] or 'Set-Cookie' in h['name']:
            cookies = cookies+h['name']+": " + h['value']+"\n"
    if len(cookies)>0:
        print(type+" cookies:")
        print(cookies)

    request_content_sum =0 
    print(type+" headers:")
    for hh in flowheaders:
        h={'name':hh, 'value':flowheaders[hh]}
        print(h['name'], ':', h['value'])
        request_content_sum += len(h['value'])
        if h['name'].lower() == "x-goog-spatula":
            print(decodeXGoogXSpatula(h['value']))
        elif h['name'].lower() in ["x-dfe-phenotype", "x-ps-rh",]:
            # TO DO: sometimes the unzipped here fails, which seems odd.
            res = decodeBase64ZippedProto(h['value'])
            if res != "Failed":
                print("Decoded "+h['name']+" header:\n", res)
        elif h['name'].lower() in ["x-dfe-encoded-targets", "x-gmm-client-bin", "x-geo-bin"]:
            val = h['value'] + '=='
            try:
                buf = decodeBase64(val)
                print("Decoded "+h['name']+" header:\n", decode_pb(buf))
            except:
                pass
        elif h['name'].lower() == "x-firebase-client":
            val = h['value']
            try:
                buf = base64.urlsafe_b64decode(val+base64padding(val))
                unzipped = zlib.decompress(buf, 32 + zlib.MAX_WBITS)
                print("Decoded x-firebase-client header:\n", unzipped)
            except Exception as e:
                pass
                #print(e)
        elif h['name'].lower() == "authorization":
            val = h['value']
            parts=val.split(' ')
            if len(parts)==2 and parts[0] == "Bearer" and parts[1][0:7]=="ya29.m.":
                print(decodeAuthBearerHeader(parts[1]))

    return request_content_sum

def printRequest(url, request):

    request_content_sum=0
    if len(request.headers) > 0:
        # print headers
        request_content_sum += printHeaders(request.headers, "Request")   

    req = request.path.split("?")
    req = req[0]
    for q in request.query:
        request_content_sum += len(request.query[q])
        # decode query parameters
        if q == "bpb" and "/maps/vt/proto" in url:
            #google maps
            try:
                val=request.query[q]
                # need to use urlsafe of base64 variant here
                buf = base64.urlsafe_b64decode(val)
                print("Decoded "+q+" query parameter:\n", decode_pb(buf,verbose=True,debug=False))
            except Exception as e:
                print(e)

    # handlers for known google post data formats
    request_decoders={
    '/loc/m/api': decode_locm,
    'KollektomatService/Offer': decode_kollektomat,
    'app-measurement.com/a': decode_firebase_analytics,
    'android.clients.google.com/checkin': decode_checkin,
    'android.googleapis.com/checkin': decode_checkin,
    '/log/batch': decode_log_batch,
    'experimentsandconfigs/v1/getExperimentsAndConfigs': decodeHeterodyneRequest,
    'android.googleapis.com/auth/devicekey': decode_deviceKeyRequest,
    'play.googleapis.com/play/log':decode_playstore,
    'firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog':decode_firebase_logbatch,
    'remoteprovisioning.googleapis.com/v1/:fetchEekChain' : decode_cbor,
    'remoteprovisioning.googleapis.com/v1/:signCertificates' : decode_cbor,
    }

    postData = ""
    requestMimeType = ""
    if request.method == "POST":
        postData = request.content
        request_content_sum += len(postData)
        if 'Content-Type' in request.headers:
            requestMimeType = request.headers['Content-Type'] 
        elif 'content-type' in request.headers:
            requestMimeType = request.headers['content-type']

    if (postData is not None) and (len(postData) > 0):
        # decode known google formats
        decoded=False
        for snippet in request_decoders:
            if snippet in url:
                print("POST Body (decoded):")
                print(request_decoders[snippet](postData))
                decoded=True
                break
        if not decoded:
            printUsingMimeType(postData,requestMimeType)

    return request_content_sum

def printResponse(url, response, verboseResponse=False):

    # take a look at the content of the response ...

    if len(response. headers) > 0:
        # print headers
        printHeaders(response.headers, "Response")   

    # handlers for known google formats
    response_decoders={
    'experimentsandconfigs/v1/getExperimentsAndConfigs': decodeHeterodyneResponse,
    'android.clients.google.com/checkin': decode_checkin_response,
    'android.googleapis.com/checkin': decode_checkin_response,
    'play-fe.googleapis.com/fdfe': decode_playstore_response,
    #'android.clients.google.com/fdfe': decode_playstore_response,
    '/log/batch':decode_pb,
    'remoteprovisioning.googleapis.com/v1/:fetchEekChain': decode_eek,
    'remoteprovisioning.googleapis.com/v1/:signCertificates' : decode_signedcerts,
    'android.googleapis.com/auth/devicekey': decode_deviceKeyResponse,
    }

    responseMimeType=None
    if ('Content-Type' in response.headers):
        responseMimeType=response.headers['Content-Type']
    elif ('content-type' in response.headers):
        responseMimeType=response.headers['content-type'] 

    if response.content is not None and len(response.content) > 0:
        responseData = response.content
    else:
        responseData = None

    if (responseData is not None) and (len(responseData) > 0):
        # decode known google formats
        decoded=False
        for snippet in response_decoders:
            if snippet in url:
                print("Response data (decoded):")
                print(response_decoders[snippet](responseData))
                decoded=True
                break
        if not decoded:
            if verboseResponse or stringContains(url,["android.googleapis.com/auth/devicekey",'android.googleapis.com/auth',
                'androidantiabuse/v1/x/create','devicecertificates','remoteprovisioning','mail.google.com/mail/ads/main',
                "firebase",'app-measurement.com/config/app/','/log/batch', '/loc/m/api', 'KollektomatService/Offer',
                'android.clients.google.com/fdfe','accounts.google.com']):
                    printUsingMimeType(responseData,responseMimeType,"Response data")
            elif len(responseData) <= 1000:
                printUsingMimeType(responseData,responseMimeType,"Response data")
            else:
                print("Response data (truncated):")
                print(responseData[:1000])

    

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
        res=""
        if verbose:
            res=str(e.output)+"\n"
            res=res+str(e)+"\n"
            return "Failed to parse input\n"+res
        return "Failed"

def try_decode_pb_array(name, buf, decoder, verbose=True, debug=False):
    # tries to decode as protobuf array, if that fails then print out the binary data
    if buf is None:
        return
    res = decoder(buf, verbose=False, debug=debug)  # just a canary, likely will fail so silence error reporting
    #print("first try: "+res)
    if res is None or res == "Failed" or "Failed to parse input" in res:
        res = decode_pb_array(name, buf, decoder, verbose=verbose, debug=debug)
    elif name is not None:
        res = name+":{\n"+textwrap.indent(res, '   ')+"}"
    return(res)


def decode_pb_array(name, buf, decoder, verbose=False, debug=False):
    # decodes a protobuf array
    # a protobuf array is a sequence of <varint/length><protobuf> entries.
    orig = buf
    pos = 0
    count = 1
    res=""
    while (pos < len(buf)):
        try:
            msg_len, new_pos = _DecodeVarint32(buf[pos:len(buf)], 0)
        except:
            # pretty bad if this happens, just dump out the binary and exit
            #print()"Problem decoding Varint32 in protobuf array.  Raw POST data is:")
            #printBinaryString(orig)
            return("Problem decoding Varint32 in protobuf array.  Raw POST data is:\n"+str(orig))
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
        temp_res = decoder(next_bytes, verbose=False, debug=debug)
        #print(res)
        if ((temp_res == "Failed") or ("Failed to parse input" in temp_res) or (temp_res is None)): 
            # protobuf decoding failed, fall back to printing binary
            res = res+"Problem decoding protobuf, trying raw decode: %d %d %d\n"%(pos, pos+msg_len, len(buf))
            temp_res = decode_pb(next_bytes, verbose=verbose, debug=debug)  # try raw decoding of protobuf, maybe schema mismatch
            if (temp_res == "Failed" or ("Failed to parse input" in temp_res)):
                #print("Dumping binary data:")
                #print(str(orig))  # dump out raw data
                # keep a copy, helps when debugging
                f = open('/tmp/event_debug_bytes2', 'wb')
                f.write(orig)
                f.close()
                return(res+"Dumping binary data:\n"+str(orig))
        if name is not None:
            res=res+ name+" "+str(count)+": {\n"+textwrap.indent(temp_res, '   ')+"}\n"
        pos = pos+msg_len
        count = count+1
    #if pos != len(buf):  # shouldn't happen
    #    raise Exception("decode_pb_array(): pos!=buflen ("+str(pos)+"/"+str(len(buf))+")")
    return(res)


# see https://github.com/protocolbuffers/protobuf/blob/cac9765af0ace57ce00b6ea07b8829339a622b1d/python/google/protobuf/text_format.py#L56
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

def decodeCerts(certchain):
    # x509 cert starts with b'0x82' then two bytes giving length, so use this to parse out cert chain
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    res=""
    temp = certchain
    while len(temp)>0:
        #print(temp[2:4])
        length=struct.unpack('!H',temp[2:4])
        #print(length)
        #print(temp[0:length[0]+4])
        cert = x509.load_der_x509_certificate(temp[0:length[0]+4])
        res=res+"X509 certificate:\n"
        for property in ['issuer','subject','not_valid_before_utc','not_valid_after_utc','serial_number',
            'signature_algorithm_oid']: #,'extensions']:
            res=res+"\t"+property+":"+str(getattr(cert,property))+"\n"
        try:
            res=res+"\t"+"public key:"+str(cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))+"\n"
        except:
            pass
        temp=temp[length[0]+4:]
    return res  

def decode_signedcerts(payload):
    # decode https://remoteprovisioning.googleapis.com/v1/:signCertificates response
    response = cbor2.loads(payload)
    try:
        certchain = response[0]
        res="Cert chain:\n"
        res = res +decodeCerts(certchain)
        certs = response[1]
        res = res+"Individual certs:\n"
        for cert in certs:
            res = res +decodeCerts(cert)
        return res
    except:
        return str(response)

def decode_eek(payload):
    geek = cbor2.loads(payload)
    res=""
    for eek in geek[0]:
        res=res+"Elliptic Curve Index: "+str(eek[0])+" EekChain (ECDH key and cert chain, used in later cert signing request): "+str(eek[1])+"\n"
        res = res+"Challenge: "+base64.b64encode(geek[1]).decode('utf8')+"\n"
        if (len(geek)>2):
            res=res+"DeviceConfig: "+str(geek[2])+"\n"
    return res

def decode_cbor(payload):
    try:
        return str(cbor2.loads(payload))
    except:
        return str(payload)

def decode_gRPC(data,decoder,tag="POST Body (gRPC decoded)"):
    res=""
    orig_data = data
    while data:
        try:
            compressed, length = struct.unpack('!?I', data[:5])
            message = struct.unpack('!%is'%length, data[5:5+length])[0]
            if compressed:
                # assume gzip, actual compression has to be parsed from 'grpc-encoding' header
                # see also: https://www.oreilly.com/library/view/grpc-up-and/9781492058328/ch04.html
                message = zlib.decompress(message, 32+zlib.MAX_WBITS)
        except Exception as e: 
            #print(repr(e))
            #print("compressed ",compressed, "length", length, "data len ",len(orig_data),len(data))
            #print("Invalid gRPC message: ",(orig_data,))
            return "Invalid gRPC message: "+str(orig_data)
        res=res+try_decode_pb_array(tag, message, decoder)+"\n"
        data = data[5+length:]
    return(res)

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


def decode_firebase_logbatch_event(bytes, verbose=False, grep=True, debug=False):
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
                    decoded =decoded +'+++FIREBASE_BATCH %s %s %s %s',(firebase.traceMetric.clientStartTimeis,firebase.applicationInfo.androidAppInfo.packageName, firebase.applicationInfo.appInstanceId, firebase.traceMetric.name)
            except Exception as e:
                print("firebase grep failed:\n")
                print(repr(e))
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"

def decode_firebase_logbatch(postData, verbose=True):
    res=str(postData)
    try:
        data = json.loads(postData)
        res=res+"\nLOGEVENTS FROM JSON (decoded):\n"
        count = 1
        for log in data['logRequest']:
            tag=""
            if log['logSourceName']:
                tag=log['logSourceName']
            for e in log['logEvent']:
                if 'sourceExtension' in e:
                    buf = decodeBase64(e['sourceExtension'])
                    try:
                        if tag == "FIREPERF":
                            res=res+tag+" log event "+str(count)+":\n"
                            res=res+decode_firebase_logbatch_event(buf)+"\n"
                        else:
                            res=res+try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)+"\n"
                    except Exception as ee:
                        res=res+"Firelog decoding failed:\n"
                        res=res+repr(ee)
                        res=res+try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)+"\n"
                res=res+"\n"
            count = count+1
    except Exception as e:
        if verbose:
            print("JSON decoding failed:")
            print(repr(e))

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
        str = subprocess.check_output("protoc --decode=\"Response.ResponseWrapper\" -I='"+mypath+"/finsky_protobuf' response.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(str)
        str = subprocess.check_output("python3 '"+mypath+"/playstoreresponse_decode.py' '"+fname+"'", 
                                      shell=True, stderr=subprocess.STDOUT, text=True)
        #print(str)
        return(str)
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

def decode_deviceKeyResponse(bytes, verbose=False, debug=False):
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
        decoded = subprocess.check_output("protoc --decode=\"DeviceKeyResponse\" -I='"+mypath+"' devicekeyrequest.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"

def decode_locm(data, verbose=True, debug=False):
    try:
        #f = open('/tmp/locm_bytes', 'wb')
        if debug:
            fname='/tmp/locm_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        # read header.  
        # writeShort(2), writeByte(0), <length><string1>, writeLong(0L), <length><string2>
        # string1="location,2023,android,gms,en_US", string2="g" 
        posn=3 # writeShort(2), writeByte(0) \x00\x02\x00
        length = struct.unpack('!h', data[posn:posn+2])[0] # string length \x00\x1f
        posn=posn+2+length # string "location,2023,android,gms,en_US"
        posn=posn+8+3 # writeLong(0L), \x00\x00\x00\x00\x00\x00\x00\x00\x00\x01g
        posn=posn+4 # writeInt(message length)
        posn=posn+3 # byte(0), short(257)  x00x01\x01
        # message header
        posn=posn+2 # writeShort(message id)
        posn=posn+10 # string "g:loc/ul" x00\x08g:loc/ul
        posn=posn+2 # writeShort(0)
        posn=posn+6 # string "POST" \x00\x04POST
        posn=posn+2 # writeShort
        posn=posn+2 # string "" \x00\x00
        posn=posn+6 # string "ROOT" \x00\x04ROOT  
        posn=posn+1 # writeByte(0)
        posn=posn+4 # writeInt(message length)
        posn=posn+3 # string "g" \x00\x01g
        # what follows is a gzipped protobuf
        message = zlib.decompress(data[posn:], 32+zlib.MAX_WBITS)
        f.write(message)
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
def decode_kollektomatproto(bytes, verbose=False, debug=False, saveData=True):
    #print("decode_kollektomat")
    try:
        #f = open('/tmp/locm_bytes', 'wb')
        if debug:
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
        if saveData:
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
        if verbose:
            print(e.output)
            print(e)
        return "Failed"

def decode_kollektomat(postData, verbose=False, debug=False):
    #print("raw: ",postData)
    return(decode_gRPC(postData,decode_kollektomatproto))

def base64padding(header):
    if len(header) % 4 == 2:
        extras="=="
    elif len(header) % 4 == 3:
        extras="="
    else:
        extras=""
    return extras

def decodeBase64(header):
    return base64.b64decode(header + base64padding(header))

def urlsafe_decodeBase64(header):
    return base64.urlsafe_b64decode(header + base64padding(header))


def decodeBase64ZippedProto(header):
    try:
        buf = urlsafe_decodeBase64(header)
        unzipped = zlib.decompress(buf, 32 + zlib.MAX_WBITS)
        return decode_pb(unzipped)
    except Exception as e:
        print(e)
        return "Failed"


def decodeXGoogXSpatula(header, debug=False):
    buf = urlsafe_decodeBase64(header)
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
    return("Decoded x-goog-spatula header:\n"+decoded)
    #return(decoded)

def decodeAuthBearerHeader(header, debug=False):
    # example: ya29.m.CqkEASf-AWiMjE32vF2w15AemCtG9oEVKMmZb0nTui52upWAWK5BdGGWTH56eclQbzl7z_3WJQo-B7a8MvQUpKT3mFenAl_P8Sj87WZG74IA6D7VHv77c2D998XR3h3GusC_Z1r87prVJPvZYcknxec8BsJZteObEGtb3zoUu-7_3w87SyynzLFM852uVKkOi5EO60Xtqg9ti6Cdo1hyHOECiDk6j6_dgTkZzhnzHPsMJsd9F9Db-oLuk2ffF6Y4Q924wzLA_6ZTqiGbJZrIt7FOVMCOwwzVsRfsqclRAx-ICGqAl-GvUbVP5TxQdiLdVzwI5-HIk00G_Ap4MgD7X-XbTFjTL5eaWtbbR9YJ4HX6xchgraf1fEqDOYVzHC3kHLXWdttPh1pvMrCGHs9n7wYCzVjR_jr5KeoP2RK066lqDcdCSg-RfT08qxWDLmFeNJur8gBC6HiqqzrDgdU01TxwI9xUAiK5Lm2zS-eCFUISo4NK421xUHdNe_eFY4WrDij6-TXkyzZN4LZ0mvz91ec9b0vL19frdJq9pl2riuxrixlb2ZxMv0WuE9jL0vj3aiVLRvuQxtScmn8XN0O8EYZVTPjIbu9cnghV4UEqMunY5fHpmhfMUDSfURG_mvR8AWMuqP5IC9BeWmDrgTbEuOnIsQGvGhB53XLO3mKN2tanptCj2BWuj6oN0k7wSUus9hLrhC6vFuyHMnYdf4nxwjmuuN4f6pJhCY460xIMCAESBgoBMxDRHBgFGiBAuva1FdbuSY0ohuHtc0CktKXibIqksqQO1SGn9r24eiICCAEqK2FDZ1lLQVlrU0FSSVNGUUhHWDJNaVl6X3ZTdDVKTmdINURHY0FfYm8tdlE
    buf = urlsafe_decodeBase64(header[7:])
    if debug:
        fname='/tmp/intermediatetoken_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(buf)
    f.close()
    decoded = subprocess.check_output("protoc --decode=\"IntermediateToken\" -I='"+mypath+"' intermediatetoken.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
    return("Decoded Auth Bearer header:\n"+decoded)

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
        return("Decoded heterodyne response:\n"+decoded)
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
        return("Decoded heterodyne request:\n"+decoded)
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
    connection_count = 0

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
        assumeFL = False #True
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
        # add command line option to only process google connections, e.g. use as "--set google_only=false"
        loader.add_option(
            name="google_only",
            typespec=bool,
            default=True,
            help="Only process Google connections")
        # add command line option to only process a specified number of connections"
        loader.add_option(
            name="num_connections",
            typespec=int,
            default=-1,
            help="Number of connections to process")

    def request(self, flow:http.HTTPFlow):
        if ctx.options.num_connections and ctx.options.num_connections>0:
            if self.connection_count >= ctx.options.num_connections:
                ctx.master.shutdown() # quit mitmdump, doesn't seem to work?
                quit() # force quit, works but generates error trace
        self.connection_count = self.connection_count+1

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
        url = flow.request.pretty_url
        if ctx.options.google_only:
            # bail if not a google related connection
            if not('goog' in url or 'doubleclick' in url or 'app-measurement' in url or 'firebase' in url or 'appspot' in url or "youtube" in url):
                return

        request_content_sum = printRequest(url,flow.request) 
        printResponse(url,flow.response) 
        print('+++REQUEST ', flow.request.pretty_url, request_content_sum, flow.request.timestamp_start)
 

#tell mitmproxy to use PrintTrace() class as an addon, this way we can use "-s decoding_helpers.py" as mitmdump option and things just work
addons = [PrintTrace()]


