from google.protobuf.internal.decoder import _DecodeVarint32
from google.protobuf import text_format
from google.protobuf import message as protobuf_message
from google.protobuf.unknown_fields import UnknownFieldSet # only present in recent versions of google module
import subprocess
import textwrap
import sys
import os
import brotli  # a dependency of mitmproxy
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
from decode_raw import decode_raw, DecodeRawError  # in-process `protoc --decode_raw`
from decode_named import decode_named, DecodeNamedError, message_class  # in-process `protoc --decode`
import adparams_decode  # advert url parameters ms, dc_ms, attok, gref
import s2cell  # S2 cell id -> lat/lng, for the VoilaTile location tiles
import federatedcompute_decode  # federatedcompute-pa: federated learning and analytics
import contextlib, importlib, io
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

class ScriptDecodeError(Exception):
    pass

def run_decoder_script(module, data):
    # what `python3 module.py FILE` printed, stdout and stderr together with newlines as check_output(text=True)
    # returned them, but run in this process: the script's decode(data) with its output captured
    out = io.StringIO(newline=None)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            importlib.import_module(module).decode(data)
    except Exception as e:
        raise ScriptDecodeError("%s: %s: %s" % (module, type(e).__name__, e)) from e
    return out.getvalue()

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
    if mimeType is None:
        print(payload)
        return
    if mimeType in ['application/x-protobuf', 'application/x-protobuffer',
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
        try:
            print(payload.decode('utf8'))
        except UnicodeDecodeError:
            print(payload)
    elif mimeType == 'application/cbor':
        try:
            decoded = cbor2.loads(payload)
            print(tag+" ("+mimeType+" decoded):")
            print(decoded)
        except cbor2.CBORDecodeError as e:
            print("***ERROR: cbor: ",e)
            print(tag+" ("+mimeType+"):")
            print(payload)
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
        try:
            text = brotli.decompress(payload).decode('utf8')
            print(tag+" ("+mimeType+" decoded):")
            print(text)
        except (brotli.error, UnicodeDecodeError) as e:
            print("***ERROR: brotli: ",e)
            print(tag+" ("+mimeType+"):")
            print(payload)
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
            if h['name'].lower() == "x-ps-rh":
                print(adparams_decode.decode_ps_rh_po_token(h['value']), end='')
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
        elif h['name'].lower() == "location":
            # e.g. the intent:// Play store link returned by www.google.com/aclk, with gref
            res = adparams_decode.decode_url_params(h['value'], "location header parameter")
            if res:
                print(res, end='')

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
                print("***ERROR: ",e)
    # advert parameters ms, dc_ms, attok, gref (query or ;name=value path parameters)
    res = adparams_decode.decode_url_params(url)
    if res:
        print(res, end='')

    # handlers for known google post data formats
    request_decoders={
    '/loc/m/api': decode_locm,
    'KollektomatService/Offer': decode_kollektomat,
    'ProgramBlobService/DownloadBlob': decode_downloadblob_request,
    'VoilaTileService/FindTiles': decode_voilatile_request,
    'federatedcompute-pa.googleapis.com/v1/': lambda b: federatedcompute_decode.decode_request(url, b) or decode_pb(b),
    'app-measurement.com/a': decode_firebase_analytics,
    'android.clients.google.com/checkin': decode_checkin,
    'android.googleapis.com/checkin': decode_checkin,
    'play.googleapis.com/log/batch': decode_log_batch,
    'experimentsandconfigs/v1/getExperimentsAndConfigs': decodeHeterodyneRequest,
    'android.googleapis.com/auth/devicekey': decode_deviceKeyRequest,
    'deviceintegritytokens-pa.googleapis.com/v1/getAdEventToken': adparams_decode.decode_get_ad_event_token_request,
    'deviceintegritytokens-pa.googleapis.com/v1/getPoIntegrityToken': adparams_decode.decode_get_po_integrity_token_request,
    'play.googleapis.com/play/log':decode_playstore,
    'firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog':decode_firebase_logbatch,
    'firebaselogging.googleapis.com/v0cc/log/batch':decode_firebase_logbatch,
    'remoteprovisioning.googleapis.com/v1/:fetchEekChain' : decode_cbor,
    'remoteprovisioning.googleapis.com/v1:fetchEekChain' : decode_cbor,
    'remoteprovisioning.googleapis.com/v1/:signCertificates' : decode_cbor,
    'remoteprovisioning.googleapis.com/v1:signCertificates' : decode_cbor,
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
        # DroidGuard results (checkin, adAttest, fdfe/sync, ...); the getAdEventToken and getPoIntegrityToken
        # decoders print their own
        if 'getAdEventToken' not in url and 'getPoIntegrityToken' not in url:
            res = adparams_decode.decode_droidguard_results_in(postData)
            if res:
                print(res, end='')

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
    'play.googleapis.com/log/batch':decode_pb,
    'remoteprovisioning.googleapis.com/v1/:fetchEekChain': decode_eek,
    'remoteprovisioning.googleapis.com/v1/:signCertificates' : decode_signedcerts,
    'remoteprovisioning.googleapis.com/v1:signCertificates' : decode_signedcerts,
    'android.googleapis.com/auth/devicekey': decode_deviceKeyResponse,
    'deviceintegritytokens-pa.googleapis.com/v1/getAdEventToken': adparams_decode.decode_get_ad_event_token_response,
    'deviceintegritytokens-pa.googleapis.com/v1/getPoIntegrityToken': adparams_decode.decode_get_po_integrity_token_response,
    'ProgramBlobService/DownloadBlob': decode_downloadblob_response,
    'VoilaTileService/FindTiles': decode_voilatile_response,
    'federatedcompute-pa.googleapis.com/v1/': lambda b: federatedcompute_decode.decode_response(url, b, response.status_code) or decode_pb(b),
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
                print(responseData[:1000],"<truncated>")

    
#from mitm_protobuf import format_pbuf
#import difflib
def decode_pb(bb, verbose=True, debug=False):
    # try to decode a protobuf without knowing the schema, usually works fine
    # but there can be ambiguity in encoding and so result may not be quite what we'd
    # like e.g. an embedded protobuf might be parsed as a bytes field.
    if debug:
        fname='/tmp/bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        # same output as `protoc --decode_raw`, without a protoc process per message (see check_decode_raw.py)
        res = decode_raw(bb)

        '''
        # test of alternative raw decoding approach, but it makes different choices/guesses from protoc
        mitm_res = format_pbuf(bb)        
        diff="".join(difflib.ndiff(res.splitlines(keepends=True),mitm_res.splitlines(keepends=True)))
        if len(diff)>0:
            print("+++mitm")
            print(diff)
            print("---mitm")
        '''
        return res
    except DecodeRawError as e:
        res=""
        if verbose:
            res="***ERROR: Failed to parse input.\n"
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
        except Exception as e:
            # pretty bad if this happens, just dump out the binary and exit
            #print()"Problem decoding Varint32 in protobuf array.  Raw POST data is:")
            #printBinaryString(orig)
            print("***ERROR decoding Varint32: ",e)
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
            print("***ERROR In protoUnknownFieldsToString couldn't get UnknownFieldSet: ",e)
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
            try:
                res=res+"\t"+property+":"+str(getattr(cert,property))+"\n"
            except Exception as e:
                print("***ERROR: ",e)
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
    except Exception as e:
        print("***ERROR: ",e)
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
            #print("***ERROR: ",e)
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
            f.write(bytes)
            f.close()
        return run_decoder_script("app_measurement_decode", bytes)
        # pb = app_measurement_pb2.POST_body()
        # pb.ParseFromString(bytes)
        # return str(pb)
    except ScriptDecodeError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed: "


def decode_firebase_logbatch_event(bytes, verbose=True, grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/firebaselogbatch_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("FirelogEvent", "firebase_logbatch.proto", bytes)
        if grep:
            try:
                firebase = firebase_logbatch_pb2.FirelogEvent()
                firebase.ParseFromString(bytes)
                if fieldIsSet(firebase.traceMetric) and firebase.traceMetric.name:
                    decoded =decoded +'+++FIREBASE_BATCH '+str(firebase.traceMetric.clientStartTimeis)+" "+str(firebase.applicationInfo.androidAppInfo.packageName)+" "+str(firebase.applicationInfo.appInstanceId)+" "+str(firebase.traceMetric.name)+"\n"
            except Exception as e:
                print("***ERROR firebase grep: ",e)
        return decoded
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
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
                            decoded=decode_firebase_logbatch_event(buf,verbose=verbose)
                            if decoded == "Failed":
                                # try raw decode
                                decoded=try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)
                                res=res+decoded
                            else:
                                res=res+str(decoded)
                        else:
                            res=res+try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)+"\n"
                    except Exception as ee:
                        res=res+"Firelog decoding failed:\n"
                        res=res+repr(ee)+"\nTrying raw decode:\n"
                        res=res+try_decode_pb_array(tag+" log event "+str(count), buf, decode_pb)
                res=res+"\n"
            count = count+1
        return res
    except Exception as e:
        print("***ERROR JSON decoding: ",e)
        return res

def decode_log_batch(bytes, verbose=True, debug=False):
    # partially decodes POST payload from https://play.googleapis.com/log/batch endpoint
    try:
        if debug:
            fname='/tmp/batch_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        str = run_decoder_script("logbatch_decode", bytes)
        # print(str)
        return(str)
    except ScriptDecodeError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_playstore(bytes, verbose=True, debug=False):
    # partially decodes POST payload from https://play.googleapis.com/play/log?format=raw&proto_v2=true endpoint
    try:
        if debug:
            fname='/tmp/playstore_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        str = run_decoder_script("playstore_decode", bytes)
        # print(str)
        return(str)
    except ScriptDecodeError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_playstore_response(bytes, verbose=True, debug=False):
    # partially decodes response from https://play-fe.googleapis.com/fdfe
    try:
        if debug:
            fname='/tmp/playstore_response_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        # finsky_protobuf's are from // and https://github.com/mmcloughlin/finsky/tree/master/protobuf
        str = decode_named("Response.ResponseWrapper", "response.proto", bytes, mypath+"/finsky_protobuf")
        #print(str)
        str = run_decoder_script("playstoreresponse_decode", bytes)
        #print(str)
        return(str)
    except (ScriptDecodeError, DecodeNamedError) as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_checkin(bytes, verbose=True, debug=False):
    try:
        #f = open('/tmp/checkin_bytes', 'wb')
        if debug:
            fname='/tmp/checkin_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("CheckinRequest", "checkin.proto", bytes)
        #decoded = subprocess.check_output("protoc --decode=\"AndroidCheckinRequest\" -I='"+mypath+"' checkin_chrome.proto  </tmp/checkin_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except DecodeNamedError as e:       
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_checkin_response(bytes, verbose=True, debug=False):
    try:
        #f = open('/tmp/checkin_resp_bytes', 'wb')
        if debug:
            fname='/tmp/checkin_resp_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("CheckinResponse", "checkin.proto", bytes)
        #decoded = subprocess.check_output("protoc --decode=\"AndroidCheckinResponse\" -I='"+mypath+"' checkin_chrome.proto  </tmp/checkin_resp_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_deviceKeyRequest(bytes, verbose=True, debug=False):
    try:
        #f = open('/tmp/devicekey_bytes', 'wb')
        if debug:
            fname='/tmp/devicekey_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("DeviceKeyRequest", "devicekeyrequest.proto", bytes)
        #print(decoded)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_deviceKeyResponse(bytes, verbose=True, debug=False):
    try:
        #f = open('/tmp/devicekey_bytes', 'wb')
        if debug:
            fname='/tmp/devicekey_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("DeviceKeyResponse", "devicekeyrequest.proto", bytes)
        #print(decoded)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_locm(data, verbose=True, debug=False):
    try:
        #f = open('/tmp/locm_bytes', 'wb')
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
        if debug:
            fname='/tmp/locm_bytes'
            f = open(fname, 'wb')
            f.write(message)
            f.close()
        decoded = decode_named("LocRequest", "locm.proto", message)
        #print(decoded)
        return(decoded)
    except (DecodeNamedError, zlib.error, struct.error) as e:  # zlib, struct: a truncated or corrupted body
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def get_expt_name():
    if ctx.options.expt_name:
        # allows to run on multiple files without creating clashes
        expt_name = ctx.options.expt_name
    else:
        expt_name=""
    return str(expt_name)

GNSS_CONSTELLATIONS = {0: "UNKNOWN", 1: "GPS", 2: "SBAS", 3: "GLONASS", 4: "QZSS", 5: "BEIDOU", 6: "GALILEO", 7: "IRNSS"}  # GnssStatus.CONSTELLATION_*

def kollektomat_utc(ms):
    return datetime.datetime.fromtimestamp(ms/1000, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

def decode_glocrequest(req, decoded, Grep=True, saveData=True):
    # the newer Offer payload, an lbs.GLocRequest (kollektomat_named.proto): Google Play services' sensor collector
    # uploads a collection in chunks, all times in it are ms after the collection started
    info = req.payload.value.upload_info
    start = info.collection_start_time_ms
    if saveData:
        for signals in req.payload.value.signals:
            trace = signals.sensor_trace
            for loc in list(trace.location) + ([signals.location] if signals.HasField("location") else []):
                if loc.HasField("lat_lng"):
                    with open('/tmp/kollektomat_gpslocs'+get_expt_name(), 'a') as f:
                        print("lat: ", loc.lat_lng.lat_e7/1.0e7, " long: ", loc.lat_lng.lng_e7/1.0e7, "gpsTime: ", start + loc.time_ms, ' ', end='', file=f)
                        if loc.HasField("speed_mps"):
                            print("speed: ", loc.speed_mps, end='', file=f)
                        print(file=f)
            for scan in list(trace.wifi_scan) + ([signals.wifi_scan] if signals.HasField("wifi_scan") else []):
                with open('/tmp/kollektomat_wifilocs'+get_expt_name(), 'a') as f:
                    print(start + scan.time_ms, ' ', end='', file=f)
                    for ap in scan.access_point:
                        print(ap.bssid, ap.rssi_dbm, ' ', end='', file=f)
                    print(file=f)
    if not Grep:
        return decoded
    counts, bssids, sats, used, locs = {}, set(), {}, 0, []
    for signals in req.payload.value.signals:
        trace = signals.sensor_trace
        chunk_start = start + trace.start_offset_ns // 1000000
        for fd, value in trace.ListFields():
            if fd.label == fd.LABEL_REPEATED:
                counts[fd.name] = counts.get(fd.name, 0) + len(value)
        for scan in trace.wifi_scan:
            counts["wifi_aps"] = counts.get("wifi_aps", 0) + len(scan.access_point)
            bssids.update(ap.bssid for ap in scan.access_point)
        for scan in trace.cell_scan:
            counts["cells"] = counts.get("cells", 0) + 1 + len(scan.neighbor_cells)
        for status in trace.gnss_status:
            for sat in status.satellite:
                c = GNSS_CONSTELLATIONS.get(sat.constellation_type, str(sat.constellation_type))
                sats.setdefault(c, set()).add(sat.svid)
                used += sat.used_in_fix
        for rec in trace.gnss_measurements:
            counts["gnss_raw_measurements"] = counts.get("gnss_raw_measurements", 0) + len(rec.event.measurement)
        for loc in list(trace.location) + ([signals.location] if signals.HasField("location") else []):
            locs.append("%.5f,%.5f(%dm)" % (loc.lat_lng.lat_e7/1.0e7, loc.lat_lng.lng_e7/1.0e7, loc.accuracy_m))
        if trace.HasField("geomagnetic_field_model"):
            locs.append("geomagnetic_field_model")
    grep = "+++KOLLEKTOMAT %s session=%s chunk=%d collection_start=%s chunk_window=%s..%s" % (
        ",".join(req.collector), info.session_id, info.chunk_number, kollektomat_utc(start), kollektomat_utc(chunk_start),
        kollektomat_utc(info.request_time_ms))
    triggers = [str(s.collection_info.trigger) for s in req.payload.value.signals if s.collection_info.HasField("trigger")]
    if triggers:
        grep += " trigger=" + ",".join(triggers)  # 14: started because activity recognition saw ON_FOOT (eryt.1 in kollektomat_named.proto)
    grep += " " + " ".join("%s=%d" % kv for kv in counts.items())
    if bssids:
        grep += " unique_bssids=%d" % len(bssids)
    if sats:
        grep += " gnss_satellites=" + ",".join("%s:%d" % (c, len(s)) for c, s in sorted(sats.items())) + " used_in_fix=%d" % used
    grep += " location=" + (" ".join(locs) if locs else "none")
    return grep + "\n" + decoded

kollektomat_count=0
def decode_kollektomatproto(bytes, verbose=True, debug=False, Grep=True, saveData=True):
    try:
        if debug:
            global kollektomat_count
            fname='/tmp/kollektomat_bytes_'+str(kollektomat_count)
            kollektomat_count = kollektomat_count + 1
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        #print(fname)
        req = message_class("KollektomatOfferRequest", "kollektomat_named.proto")()
        try:
            req.ParseFromString(bytes)
        except protobuf_message.DecodeError:  # not this format: the locm.proto decode below reports it
            req = None
        if req is not None and req.payload.type_url == "type.googleapis.com/lbs.GLocRequest":
            decoded = decode_named("KollektomatOfferRequest", "kollektomat_named.proto", bytes)
            return decode_glocrequest(req, decoded, Grep, saveData)
        # older format (locm.proto)
        decoded = decode_named("KollektomatRequest", "locm.proto", bytes)
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
                        fname='/tmp/kollektomat_gpslocs'+get_expt_name()
                        f = open(fname, 'a')
                        print("lat: ",float(signals.gpsInfo.latLong.lat)/1.0e7, " long: ", float(signals.gpsInfo.latLong.long)/1.0e7, "gpsTime: ", signals.gpsInfo.gpsTime, ' ', end='', file=f)
                        if fieldIsSet(signals.gpsInfo.speed):
                            print("speed: ",signals.gpsInfo.speed, end='', file=f)
                        print(file=f)
                        f.close()
                    elif fieldIsSet(signals.wifiSignals) and signals.wifiSignals.wifiSignal:
                        fname='/tmp/kollektomat_wifilocs'+get_expt_name()
                        f = open(fname, 'a')
                        print(int(signals.wifiSignals.timestamp),' ', end='', file=f)
                        for wifi in signals.wifiSignals.wifiSignal:
                            print(int(wifi.macAddress),int(wifi.rssi),' ', end='', file=f)
                        print(file=f)
                        f.close()
        grep=""
        if Grep:
            res = decoded.split('\n')
            grep="+++KOLLEKTOMAT ";
            try:
                for s in res:
                    if re.search('cellSignals', s):
                        grep=grep+"cellSignals "
                    if re.search('cellId', s):
                        grep=grep+s.replace(" ", "")+" "
                    if re.search('wifiSignals', s):
                        grep=grep+"wifiSignals "
                    if re.search('macAddress', s):
                        grep=grep+s.replace(" ", "")+" "
                    if re.search('detectedActivities', s):
                        grep=grep+"detectedActivities "
                    if re.search('activity', s):
                        grep=grep+s.replace(" ", "")+" "
                grep=grep+"\n"
            except Exception as e:
                print("***ERROR KOLLEKTOMAT grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_kollektomat(postData, verbose=True, debug=False):
    #print("raw: ",postData)
    return(decode_gRPC(postData,decode_kollektomatproto))

def frewle_aps(blob):
    # FREWLE Wi-Fi AP tile (FrewleTile.frewle_blob in voilatile_named.proto), as GMS's esni/esnj read it: byte 0 version
    # (1), bytes 4-8 the tile's S2 cell id >> 24, bytes 9-10 the AP count, then 11 bytes per AP: MAC (6), position in
    # the tile cell (3, 12 more S2 levels), power output (1), path-loss exponent (1, (x + 128) * 0.01). An AP whose
    # bytes 6-10 are all 0 shares the previous AP's values. Returns (tile cell id, [(mac, ap cell id, power, ple)]).
    if not blob or blob[0] != 1:
        return None, []
    cell = int.from_bytes(blob[4:9], "big") << 24
    shift = 2 * (30 - s2cell.cell_level(cell)) - 24
    aps, last = [], None
    for k in range(int.from_bytes(blob[9:11], "big")):
        e = blob[11 + 11*k:22 + 11*k]
        if len(e) < 11:
            break
        if any(e[6:11]) or last is None:
            last = e
        ap_cell = (cell ^ (cell & -cell)) | (((int.from_bytes(last[6:9], "big") << 1) | 1) << shift)
        signed = lambda b: b - 256 if b > 127 else b
        aps.append((int.from_bytes(e[0:6], "big"), ap_cell, signed(last[9]), (signed(last[10]) + 128) * 0.01))
    return cell, aps

voilatile_bssids = set()  # the BSSIDs of the last FindTiles request, to find them in its response's tiles

def decode_voilatile_requestproto(bytes, verbose=True, debug=False, Grep=True):
    # voilatile-pa VoilaTileService/FindTiles request: Google Play services' network location asking for the location
    # tiles of the Wi-Fi APs and cell towers the phone sees
    global voilatile_bssids
    try:
        req = message_class("FindTilesRequest", "voilatile_named.proto")()
        req.ParseFromString(bytes)
        decoded = decode_named("FindTilesRequest", "voilatile_named.proto", bytes)
    except (protobuf_message.DecodeError, DecodeNamedError) as e:
        if verbose:
            print("***ERROR FindTiles request: ", e)
        return "Failed"
    bssids = [b for q in req.query for b in q.wifi_aps.bssid]
    cells = [c for q in req.query for c in q.cell_towers.cell_key]
    voilatile_bssids = set(bssids)
    grep = ""
    if Grep:
        grep = "+++VOILATILE_REQUEST wifi_aps=%d %s cells=%s tile_keys=%d device=%s\n" % (
            len(bssids), ",".join("%012x" % b for b in bssids) or "-", ",".join(cells) or "-", len(req.tile_key),
            req.client_context.device.model or req.client_context.device.manufacturer_model or "-")
    # BSSIDs are printed as integers by the decode; hex form here
    return grep + decoded + "".join("bssid %012x\n" % b for b in bssids)

def decode_voilatile_responseproto(bytes, verbose=True, debug=False, Grep=True):
    # FindTiles response: S2-cell tiles listing each known AP's MAC and position (FREWLE tiles) or cell towers.
    # The FREWLE blobs are elided from the decode and printed parsed, one AP per line.
    try:
        resp = message_class("FindTilesResponse", "voilatile_named.proto")()
        resp.ParseFromString(bytes)
    except protobuf_message.DecodeError as e:
        if verbose:
            print("***ERROR FindTiles response: ", e)
        return "Failed"
    tiles, aps_out, located = [], "", []
    for t in [t for r in resp.result for t in r.tile] + [b.tile for b in resp.bluesky]:
        if t.data.HasField("wifi"):
            cell, aps = frewle_aps(t.data.wifi.frewle.frewle_blob)
            if cell is None:
                continue
            lvl, lat, lng = s2cell.cell_to_latlng(cell)
            tiles.append("wifi:%.5f,%.5f(L%d,%d_aps)" % (lat, lng, lvl, len(aps)))
            aps_out += "FREWLE tile %016x level %d centre %.5f,%.5f, %d APs (%d bytes elided above):\n" % (
                cell, lvl, lat, lng, len(aps), len(t.data.wifi.frewle.frewle_blob))
            for mac, c, power, ple in aps:
                _, alat, alng = s2cell.cell_to_latlng(c)
                aps_out += "  AP %012x %.5f,%.5f power=%d path_loss_exponent=%.2f\n" % (mac, alat, alng, power, ple)
                if mac in voilatile_bssids:
                    located.append("%012x@%.5f,%.5f" % (mac, alat, alng))
            t.data.wifi.frewle.ClearField("frewle_blob")
        elif t.data.HasField("cell"):
            name = t.key.cell.name
            where = ""
            if "#" in name:
                try:
                    lvl, lat, lng = s2cell.cell_to_latlng(s2cell.token_to_id(name.split("#")[0]))
                    where = "@%.5f,%.5f(L%d)" % (lat, lng, lvl)
                except (ValueError, IndexError):
                    pass
            tiles.append("cell:%s%s(%d_cells)" % (name, where, len(t.data.cell.cell_id)))
    try:
        decoded = decode_named("FindTilesResponse", "voilatile_named.proto", resp.SerializeToString())
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR FindTiles response: ", e)
        return "Failed"
    grep = ""
    if Grep:
        grep = "+++VOILATILE_RESPONSE tiles=%d %s requested_aps_located=%d %s\n" % (
            len(tiles), " ".join(tiles) or "-", len(located), " ".join(located) or "-")
    return grep + decoded + aps_out

def decode_voilatile_request(postData, verbose=True, debug=False):
    return(decode_gRPC(postData, decode_voilatile_requestproto))

def decode_voilatile_response(data, verbose=True, debug=False):
    return(decode_gRPC(data, decode_voilatile_responseproto, "Response data (gRPC decoded)"))

def pb_enum_name(m, f):
    # the name of enum field f's value in message m, or the number when the value is not in the enum
    v = getattr(m, f)
    names = m.DESCRIPTOR.fields_by_name[f].enum_type.values_by_number
    return names[v].name if v in names else str(v)

def tink_summary(b):
    # size and Tink key ID of a Tink ciphertext (output prefix 0x01 + 4-byte key ID), for the large encrypted blobs
    if len(b) >= 5 and b[0] == 1:
        return "<%d bytes, Tink key %s>" % (len(b), b[1:5].hex())
    return "<%d bytes>" % len(b)

def decode_downloadblob_requestproto(bytes, verbose=True, debug=False, Grep=True):
    # ondevicesafety-pa ProgramBlobService/DownloadBlob request: Google's on-device abuse library (Moirai, in Google
    # Messages; also Play Protect's com.google.android.odad) asking for its rule/model package
    try:
        req = message_class("DownloadBlobRequest", "ondevicesafety_named.proto")()
        req.MergeFromString(bytes)
    except Exception:
        req = None
    if req is None or not req.HasField("blob_meta"):
        if verbose:
            print("***ERROR DownloadBlob request: no blob_meta")
        return "Failed"
    try:
        decoded = decode_named("DownloadBlobRequest", "ondevicesafety_named.proto", bytes)
        grep = ""
        if Grep:
            ci, c = req.blob_meta.client_info, req.blob_meta.counters
            att = req.attestation
            kind = "droidguard" if att.HasField("droidguard_token") else "key_attestation" if att.HasField("key_attestation") else "-"
            labels = ",".join("%s=%s" % (l.attribute, l.value) for l in ci.label) or "-"
            grep = "+++ONDEVICESAFETY_REQUEST %s %s tier=%s labels=%s downloads=%d classifications=%d attestation=%s mode=%s\n" % (
                ci.client_id or "-", pb_enum_name(ci.client_version, "client_type"), ci.device_tier or "-", labels,
                c.download_count, c.classification_count, kind, pb_enum_name(req, "download_mode"))
        return grep + decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR DownloadBlob request: ", e)
        return "Failed"

def decode_downloadblob_responseproto(bytes, verbose=True, debug=False, Grep=True):
    # ProgramBlobService/DownloadBlob response: the encrypted package (megabytes), its transparency-log proof and the
    # tokens. The package blobs are printed as size and Tink key ID only.
    try:
        resp = message_class("DownloadBlobResponse", "ondevicesafety_named.proto")()
        resp.MergeFromString(bytes)
    except Exception:
        if verbose:
            print("***ERROR DownloadBlob response: does not parse")
        return "Failed"
    blob = tink_summary(resp.blob) if resp.blob else "-"
    components = "|".join("%s/%d:%s" % (pb_enum_name(c, "type"), c.component_id, tink_summary(c.blob))
                          for c in resp.protection_components) or "-"
    resp.ClearField("blob")
    for c in resp.protection_components:
        c.ClearField("blob")
    try:
        decoded = decode_named("DownloadBlobResponse", "ondevicesafety_named.proto", resp.SerializeToString())
        grep = ""
        if Grep:
            checkpoint = resp.protection_proof_v2.signed_checkpoint.checkpoint.split("\n")
            grep = "+++ONDEVICESAFETY_RESPONSE %s blob=%s components=%s leaf_index=%d tree_size=%s protection_token=%s\n" % (
                pb_enum_name(resp, "status"), blob, components, resp.protection_proof_v2.leaf.leaf_index, checkpoint[1] if len(checkpoint) > 1 else "-",
                resp.protection_token[:8].hex() or "-")
        return grep + "(blob and protection_components.blob elided: %s; %s)\n" % (blob, components) + decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR DownloadBlob response: ", e)
        return "Failed"

def decode_downloadblob_request(postData, verbose=True, debug=False):
    return(decode_gRPC(postData, decode_downloadblob_requestproto))

def decode_downloadblob_response(data, verbose=True, debug=False):
    return(decode_gRPC(data, decode_downloadblob_responseproto, "Response data (gRPC decoded)"))

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
        print("***ERROR: ",e)
        return "Failed"

def decodeXGoogXSpatula(header, verbose=True, debug=False):
    try:
        buf = urlsafe_decodeBase64(header)
        #try_decode_pb_array("Decoded x-goog-spatula header", buf, decode_pb)
        #f = open('/tmp/spatula_bytes', 'wb')
        if debug:
            fname='/tmp/spatula_bytes'
            f = open(fname, 'wb')
            f.write(buf)
            f.close()
        decoded = decode_named("GoogleSpatulaHeader", "spatula.proto", buf)
        return("Decoded x-goog-spatula header:\n"+decoded)
    except (ValueError, DecodeNamedError) as e:  # ValueError: not base64
        if verbose:
            print("***ERROR: decoding x-goog-spatula header: ",e)
        return "Failed"
    #return(decoded)

def decodeAuthBearerHeader(header, verbose=True, debug=False):
    # example: ya29.m.CqkEASf-AWiMjE32vF2w15AemCtG9oEVKMmZb0nTui52upWAWK5BdGGWTH56eclQbzl7z_3WJQo-B7a8MvQUpKT3mFenAl_P8Sj87WZG74IA6D7VHv77c2D998XR3h3GusC_Z1r87prVJPvZYcknxec8BsJZteObEGtb3zoUu-7_3w87SyynzLFM852uVKkOi5EO60Xtqg9ti6Cdo1hyHOECiDk6j6_dgTkZzhnzHPsMJsd9F9Db-oLuk2ffF6Y4Q924wzLA_6ZTqiGbJZrIt7FOVMCOwwzVsRfsqclRAx-ICGqAl-GvUbVP5TxQdiLdVzwI5-HIk00G_Ap4MgD7X-XbTFjTL5eaWtbbR9YJ4HX6xchgraf1fEqDOYVzHC3kHLXWdttPh1pvMrCGHs9n7wYCzVjR_jr5KeoP2RK066lqDcdCSg-RfT08qxWDLmFeNJur8gBC6HiqqzrDgdU01TxwI9xUAiK5Lm2zS-eCFUISo4NK421xUHdNe_eFY4WrDij6-TXkyzZN4LZ0mvz91ec9b0vL19frdJq9pl2riuxrixlb2ZxMv0WuE9jL0vj3aiVLRvuQxtScmn8XN0O8EYZVTPjIbu9cnghV4UEqMunY5fHpmhfMUDSfURG_mvR8AWMuqP5IC9BeWmDrgTbEuOnIsQGvGhB53XLO3mKN2tanptCj2BWuj6oN0k7wSUus9hLrhC6vFuyHMnYdf4nxwjmuuN4f6pJhCY460xIMCAESBgoBMxDRHBgFGiBAuva1FdbuSY0ohuHtc0CktKXibIqksqQO1SGn9r24eiICCAEqK2FDZ1lLQVlrU0FSSVNGUUhHWDJNaVl6X3ZTdDVKTmdINURHY0FfYm8tdlE
    try:
        buf = urlsafe_decodeBase64(header[7:])
        if debug:
            fname='/tmp/intermediatetoken_bytes'
            f = open(fname, 'wb')
            f.write(buf)
            f.close()
        decoded = decode_named("IntermediateToken", "intermediatetoken.proto", buf)
        return("Decoded Auth Bearer header:\n"+decoded)
    except Exception as e:
        if verbose:
            print("***ERROR: decoding Auth Bearer header: ",e)
        return "Failed"

heterodyne_count=0
def decodeHeterodyneResponse(buf, verbose=True, debug=False):
    if debug:
        global heterodyne_count
        fname='/tmp/heterodyneresponse_bytes'+get_expt_name()+str(heterodyne_count)
        heterodyne_count=heterodyne_count+1
        f = open(fname, 'wb')
        f.write(buf)
        f.close()
    try:
        decoded = decode_named("HeterodyneResponse", "exptsandconfigs_response.proto", buf)
        return("Decoded heterodyne response:\n"+decoded)
    except DecodeNamedError as e:         
        if verbose:
            print("***ERROR: ",e) 
        print("Failed to decode heterodyne response, raw response:")
        printBinaryString(buf)
        return "Failed"


def decodeHeterodyneRequest(buf, verbose=True, debug=False):
    if debug:
        fname='/tmp/heterodynereq_bytes'
        f = open(fname, 'wb')
        f.write(buf)
        f.close()
    try:
        decoded = decode_named("HeterodyneRequest", "exptsandconfigs_request.proto", buf)
        return("Decoded heterodyne request:\n"+decoded)
    except DecodeNamedError as e:         
        if verbose:
            print("***ERROR: ",e) 
        print("Failed to decode heterodyne request, raw request:")
        printBinaryString(buf)
        return "Failed"

def decodeFLRequestRequest(buf, verbose=True, debug=False):
    #fname='/tmp/fl_bytes'
    #f = open(fname, 'wb')
    if debug:
        fname='/tmp/fl_bytes'
        f = open(fname, 'wb')
        f.write(buf)
        f.close()
    try:
        decoded = decode_named("google.internal.federatedml.v2.ClientStreamMessage", "federated_api.proto", buf, mypath+"/federated_learning_protos")
        #print("Decoded FL request:\n", decoded)
        return decoded
    except DecodeNamedError as e:
         
        if verbose:
            print("***ERROR FLRequest: ",e) 
            #print("Failed to decode FLRequest, raw request:")
            #printBinaryString(buf)
        return "Failed"

def decode_wbxml(buf, verbose=True, debug=False):
    # decode binary XML format https://en.wikipedia.org/wiki/WBXML
    # using libwbxml https://github.com/libwbxml/libwbxml
    unzipped = buf  # zlib.decompress(buf,32 + zlib.MAX_WBITS)
    if debug:
        fname='/tmp/wbxml'
        f = open(fname, 'wb')
        fname_xml = '/tmp/xml'
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
        f_xml = tempfile.NamedTemporaryFile(delete=False)
        fname_xml=f_xml.name
    f.write(unzipped)
    f.close()
    try:
        subprocess.check_output("wbxml2xml -o "+fname_xml+" "+fname, 
                                shell=True, stderr=subprocess.STDOUT, text=True)
        f = open(fname_xml, 'r')
        xml = f.read()
        f.close()
        return xml
    except subprocess.CalledProcessError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_bond(buf, debug=False):
    # this uses OneDrive telemetry schema from Samsung handset, not portable
    # and needs decoder executable "onedrive" to be in directory
    unzipped = buf  # zlib.decompress(buf,32 + zlib.MAX_WBITS)
    if debug:
        fname = '/tmp/bond'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(unzipped)
    f.close()
    try:
        return subprocess.check_output("./onedrive -i "+fname, shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        print("***ERROR: ",e)
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
        # add command line option to set an experiment name"
        loader.add_option(
            name="expt_name",
            typespec=str,
            default="",
            help="experiment name to use")

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


