import logbatch_pb2
#import android_dialer_pb2
import subprocess
import textwrap
import sys
import os
import re

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
from decoding_helpers import decode_pb, decode_wbxml, decode_log_batch, decode_firebase_analytics, try_decode_pb_array


def decode_messaging_pb(bb, verbose=False, terse=False):
    f = open('/tmp/message_bytes', 'wb')
    f.write(bb)
    f.close()
    try:
        str = subprocess.check_output("cat /tmp/message_bytes | protoc --decode=AndroidMessaging_LogEntry -I='"+mypath+"' android_messaging.proto3",shell=True,stderr=subprocess.STDOUT, text=True)
        if str is not None and terse:
            # just write out minimal event info, handy for getting an overview of a sequence of events
            str = str.split('\n')
            out = ""; ts = False
            for s in str:
                m = re.match('timestamp: ([0-9]+)', s)
                if m and not ts:
                    out = out+m.group(1)+" "
                    ts = True
                elif re.search('eventType', s):
                    out = out+s
                #elif re.search('messageProtocol', s):
                #    out = out+s
                #elif re.search('conversationType', s):
                #    out = out+s
                #elif re.search('conversationIdSHA1', s):
                #    out = out+s
                #elif re.search('configStatus', s):
                #    out = out+s
                elif re.search('bugleMessageStatus:', s):
                    out = out+s
                #elif re.search('sendAttempt', s):
                #    out = out+s
                elif re.search('suggestionEventType', s):
                    out = out+s
                elif re.search('appLaunch', s):
                    out = out+s
                elif re.search('sha256HashMsg', s):
                    out = out+s
                elif re.search('sha256HashPrevMsg', s):
                    out = out+s
            print(out)
            return ""
        return str
    except subprocess.CalledProcessError as e: 
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_dialer_pb(bb, verbose=False, terse=False):
    f = open('/tmp/dialer_bytes', 'wb')
    f.write(bb)
    f.close()
    try:
        str = subprocess.check_output("cat /tmp/dialer_bytes | protoc --decode=AndroidDialer_LogEntry -I='"+mypath+"' android_dialer.proto3",shell=True,stderr=subprocess.STDOUT, text=True)
        if str is not None and terse:
            # just write out minimal event info
            str = str.split('\n')
            out = ""; ts = False
            for s in str:
                m = re.match('timestamp: ([0-9]+)', s)
                if m and not ts:
                    #print(m.groups())
                    out = out+m.group(1)+" "
                    ts = True
                elif re.search('AOSPEventType:', s):
                    out = out+s
                elif re.search('queryLength:', s):
                    out = out+s
                elif re.search('callDuration:', s):
                    out = out+s
            print(out)
            return ""
        return str
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


f = open('/tmp/batch_bytes', 'rb')
data = f.read()
f.close()
#print(decode_pb(data))

try:
    logbatch = logbatch_pb2.LogBatchContainer()
    logbatch.ParseFromString(data)
    for i in range(len(logbatch.inner)):
        inner = logbatch.inner[i]
        # just output dialer events, ignore the rest
        #if inner.logSourceName == "ANDROID_DIALER":
        #    try_decode_pb_array(None, inner.logEntry, decode_dialer_pb, verbose=False)
        # just output messages events, ignore the rest
        #if inner.logSourceName == "ANDROID_MESSAGING":
        #    try_decode_pb_array(None, inner.logEntry, decode_messaging_pb, verbose=False)
        #continue
        print("logBatchInner "+str(i)+" {")
        print("header{\n"+textwrap.indent(str(inner.header),'   ')+"}")
        print("currentTimeMillis: "+str(inner.currentTimeMillis))
        print("pseudonymousIdToken: "+inner.pseudonymousIdToken)
        print("elapsedTime: "+str(inner.elapsedTime))
        print("qosTier: "+str(inner.qosTier))
        print("deviceStatus{\n"+textwrap.indent(str(inner.deviceStatus),'   ')+"}")
        print("logSourceName: "+inner.logSourceName) 
        #try_decode_pb_array("logEntry", inner.logEntry, decode_pb)   
        if inner.logSourceName == "ANDROID_MESSAGING":
            try_decode_pb_array("logEntry", inner.logEntry, decode_messaging_pb)   
        elif inner.logSourceName == "ANDROID_DIALER":
            try_decode_pb_array("logEntry", inner.logEntry, decode_dialer_pb, verbose=True)
        else:
            try_decode_pb_array("logEntry", inner.logEntry, decode_pb)
        print("}")
except Exception as e:
    print(e)
    print(subprocess.check_output("cat /tmp/dialer_bytes | protoc --decode=LogBatchContainer -I='"+mypath+"' logbatch.proto3",shell=True,stderr=subprocess.STDOUT, text=True))

