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
from decoding_helpers import decode_pb, decode_pb_array, protoUnknownFieldsToString, protoToString, makeIter, fieldIsSet


def decode_playstoreevent(buf, verbose=False,debug=False):

    try:
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
        grep=""
        if fieldIsSet(logevent.source_extension):
            if debug:
                fname='/tmp/ext_bytes'
                f = open(fname, 'wb')
            else:
                f = tempfile.NamedTemporaryFile(delete=False)
                fname=f.name
            f.write(logevent.source_extension)
            f.close()
            if (fieldIsSet(logSourceName) and logSourceName in ["MARKET","WESTINGHOUSE"]):
                try:
                    if (logSourceName == "MARKET"):  # "MARKET", decode as PlayStoreLogEvent
                        ext = subprocess.check_output("protoc --decode=\"PlayStoreLogEvent\" -I='"+mypath+"' playstore.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
                        try:
                            playstorelogevent = playstore_pb2.PlayStoreLogEvent()
                            playstorelogevent.ParseFromString(logevent.source_extension)
                            #grep=grep+"+++TYPE OF EVENT(*)="+str(logevent.type_of_event)+"\n"
                            if fieldIsSet(playstorelogevent.serverLogsCookie):
                                #print("serverLogsCookie (decoded):")
                                #print(playstorelogevent.serverLogsCookie)
                                ext=ext+"serverLogsCookie (decoded) {\n"+textwrap.indent(decode_pb(playstorelogevent.serverLogsCookie),'   ')+"}\n"
                                #print(base64.b64encode(playstorelogevent.serverLogsCookie))
                            if fieldIsSet(playstorelogevent.background_action) and (str(logevent.type_of_event)=="4"):
                                if fieldIsSet(playstorelogevent.background_action.backgroundEvent):
                                    param=""
                                    if fieldIsSet(playstorelogevent.background_action.search_suggestion_report) and playstorelogevent.background_action.search_suggestion_report.query:
                                        param = str(playstorelogevent.background_action.search_suggestion_report.query)
                                    if fieldIsSet(playstorelogevent.background_action.document):
                                        param=str(playstorelogevent.background_action.document)
                                    bevent=playstore_pb2.PlayStoreBackgroundActionEvent.Type
                                    grep=grep+"+++PLAYSTORE backgroundEvent "+bevent.Name(playstorelogevent.background_action.backgroundEvent)+" "+param+"\n"                    
                            if fieldIsSet(playstorelogevent.impression) and (str(logevent.type_of_event)=="1"):
                                type=""
                                if fieldIsSet(playstorelogevent.impression.tree):
                                    if fieldIsSet(playstorelogevent.impression.tree.type):
                                        uiType = playstore_pb2.PlayStoreUiElement.Type
                                        type=uiType.Name(playstorelogevent.impression.tree.type)
                                grep=grep+"+++PLAYSTORE impression "+type+"\n"
                            if fieldIsSet(playstorelogevent.click) and (str(logevent.type_of_event)=="3"): 
                                type=""
                                for p in makeIter(playstorelogevent.click.element_path):
                                    if p.type:
                                        uiType = playstore_pb2.PlayStoreUiElement.Type
                                        type=type+uiType.Name(p.type)+" "
                                grep=grep+"+++PLAYSTORE click "+type+"\n"
                            if fieldIsSet(playstorelogevent.search):
                                if fieldIsSet(playstorelogevent.search.query):
                                    grep=grep+"+++PLAYSTORE search "+playstorelogevent.search.query+"\n"
                        except Exception as e:
                            print(e)
                    elif (logSourceName == "WESTINGHOUSE"): 
                        try: 
                            ext = subprocess.check_output("protoc --decode=\"WestinghouseEvent\" -I='"+mypath+"' playstore.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
                        except Exception as e:
                            print(e)
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
        return(grep+decoded)
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

