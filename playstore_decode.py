import playstore_pb2
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


def decode_playstoreevent(buf, verbose=False,debug=False):

    try:
        #f = open('/tmp/logevent_bytes', 'wb')
        if debug:
            fname='/tmp/logevent_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(buf)
        f.close()
        decoded_logevent = subprocess.check_output("protoc --decode=\"LogEvent\" -I='"+mypath+"' playstore.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded_logevent)
        logevent = playstore_pb2.LogEvent()
        logevent.ParseFromString(buf)
        #print(logevent)
        if logevent.source_extension is not None:
            #f = open('/tmp/ext_bytes', 'wb')
            if debug:
                fname='/tmp/ext_bytes'
                f = open(fname, 'wb')
            else:
                f = tempfile.NamedTemporaryFile(delete=False)
                fname=f.name
            f.write(logevent.source_extension)
            f.close()
            if (logSourceName is not None and logSourceName in ["MARKET","WESTINGHOUSE"]):
                try:
                    if (logSourceName == "MARKET"):  # "MARKET", decode as PlayStoreLogEvent
                        ext = subprocess.check_output("protoc --decode=\"PlayStoreLogEvent\" -I='"+mypath+"' playstore.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
                        try:
                            playstorelogevent = playstore_pb2.PlayStoreLogEvent()
                            playstorelogevent.ParseFromString(logevent.source_extension)
                            if playstorelogevent.serverLogsCookie is not None:
                                #print("serverLogsCookie (decoded):")
                                #print(playstorelogevent.serverLogsCookie)
                                ext=ext+"serverLogsCookie (decoded) {\n"+textwrap.indent(decode_pb(playstorelogevent.serverLogsCookie),'   ')+"}\n"
                                #print(base64.b64encode(playstorelogevent.serverLogsCookie))
                        except Exception as e:
                            print(e)
                    elif (logSourceName == "WESTINGHOUSE"):  
                        ext = subprocess.check_output("protoc --decode=\"WestinghouseEvent\" -I='"+mypath+"' playstore.proto  </tmp/ext_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
                except Exception as e:
                    print(e)
                    ext = decode_pb(logevent.source_extension)
            else:
                ext = decode_pb(logevent.source_extension)
            # print out untidily ...
            #print(decoded_logevent)
            #print(ext)
            #print("*************")
            # print out tidily ...
            decoded = "event_time_ms: "+str(logevent.event_time_ms)
            typeOfEvent = {1: "IMPRESSION", 3: "UI", 4: 'BACKGROUND', 6: "DEEPLINK", 9: 'COUNTER', 10: "SEQUENCE", 11: "VISUALELEMENTS"}
            #print(typeOfEvent.keys())
            #print(logevent.type_of_event, int(logevent.type_of_event) in typeOfEvent.keys())
            type_of_event = str(logevent.type_of_event)
            if len(logevent.type_of_event)>0:
                if int(logevent.type_of_event) in typeOfEvent.keys():
                    type_of_event = typeOfEvent[int(logevent.type_of_event)]
                
            decoded = decoded+"\ntype_of_event: "+type_of_event
            decoded = decoded+"\ntimezone_offset_seconds: "+str(logevent.timezone_offset_seconds)
            decoded = decoded+"\nClient Info {\n"+protoToString("client_ve",logevent.client_ve)
            #decoded = decoded+"\nplaystoreSettings {\n"+textwrap.indent(str(logevent.playstoreSettings),'   ')+"}"
            decoded = decoded+"\n"+protoToString("playstoreSettings", logevent.playstoreSettings)
            decoded = decoded+"\ncurrentServerTimeMillis: "+str(logevent.currentServerTimeMillis)
            # print out any other fields we might have missed
            unknown = protoUnknownFieldsToString(logevent)
            if len(unknown) > 0:
                decoded = decoded+"\n"+unknown
            decoded = decoded+"\nSOURCE_EXTENSION (decoded):\n"+textwrap.indent(ext,'   ')
        else:
            decoded = decoded_logevent
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


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
    decoded = subprocess.check_output("protoc --decode=\"LogRequest\" -I='"+mypath+"' playstore.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
    # print out untidily ...
    #print(decoded)

    playstore = playstore_pb2.LogRequest()
    playstore.ParseFromString(data)
    #print(playstore)

    # print out tidily ...
    #print("*************")
    #print("client_info {\n"+textwrap.indent(str(playstore.client_info),'   ')+"}")
    print(protoToString("client_info", playstore.client_info))
    logSourceName = str(playstore.LogSource.Name(playstore.log_source))
    print("log_source: "+logSourceName)
    print("request_time_ms: "+str(playstore.request_time_ms))
    #print("play_logger_metrics {"+textwrap.indent(str(playstore.play_logger_metrics),'   ')+"}")
    print(protoToString("play_logger_metrics", playstore.play_logger_metrics))
    print("serverTimestamp: "+str(playstore.serverTimestamp))
    print("google_ad_id: "+str(playstore.google_ad_id))
    print("limit_ad_tracking: "+str(playstore.limit_ad_tracking))
    try:
        # print out any other fields we might have missed
        unknown = protoUnknownFieldsToString(playstore)
        if len(unknown) > 0:
            print(unknown)
    except:
        pass

    if playstore.serialized_log_events is not None:
        print(decode_pb_array(logSourceName+" SERIALIZED LOG EVENT (decoded)", playstore.serialized_log_events, decode_playstoreevent))

except Exception as e:
    print(repr(e))
    traceback.print_exc(file=sys.stdout)

