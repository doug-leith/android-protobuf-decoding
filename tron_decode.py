import tron_pb2
#import android_dialer_pb2
import subprocess
import textwrap
import sys
import os
import re
import warnings

mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
from decoding_helpers import decode_pb, try_decode_pb_array, protoUnknownFieldsToString, protoToString, fieldIsSet


# the meaning of fields changes depending on the event, sigh
# crappy mapping from tag ID to field label
tagToFieldMapping ={
   759: 6, # eventSubType g
   799: 21, # name v
   1000001: 18, # s
   1000002: 17, # r 
   1000003: 19, # t
   1000004: 20, # float u
   1000007: 7, # h
   1000008: 8, # i
   1000009: 9, # j
   1000010: 10, # k
   1000011: 11, # l
   1000012: 12, # m
   1000013: 14, # o
   1000014: 15, # p
   1000015: 16, # q
   1000017: 22, # w
   1000018: 24, # y
   1000019: 25 # z
   #1000020 A
   #1000021 B
   #1000022 C
   #1000023 D
   #1000024 E
   #1000025 F
   #1000026 G
   #1000028 H
   #1000029 I
   #1000030 f275J
   #1000031 K
# and more, but got fed up   
   }

eventToTagMapping = {
    826: 1000002,  
    827: 1000001,  
    825: 1000004, 
    319: 1000009, 
    325: 1000014, 
    871: 1000015, 
    320: 759, 
    904: 799, 
    905: 1000001, 
    321: 1000008, 
    322: 1000007, 
    901: 1000007, 
    902: 759, 
    793: 1000007, 
    794: 1000009, 
    795: 1000008, 
    796: 1000010, 
    797: 1000011, 
    798: 1000013, 
    825: 1000004, 
    909: 1000001, 
    911: 759, 
    914: 1000001, 
    915: 759, 
    917: 1000001, 
    833: 1000001, 
    865: 10000016, 
    903: 1000017, 
    857: 1000024, 
    946: 1000025, 
    860: 1000025, 
    832: 1000001, 
    1091: 1000022, 
    945: 1000021, 
    324: 1000001, 
    1083: 759, 
    842: 1000013, 
    1002: 1000001, 
    1001: 1000026, 
    1087: 1000013, 
    871: 1000015, 
    1086: 1000001, 
    854: 1000015, 
    994: 1000007, 
    1089: 1000001, 
    995: 1000004, 
    1117: 1000007, 
    1118: 1000008, 
    1120: 1000013, 
    1121: 1000015, 
    1122: 1000001, 
    1123: 1000002, 
    915: 759, 
    914: 1000001, 
    1099: 1000023, 
    943: 10000016, 
    1091: 1000022, 
    933: 1000010, 
    932: 1000001, 
    1095: 1000013, 
    1094: 1000001, 
    1125: 1000001, 
    1130: 759, 
    1234: 759, 
    858: 1000026, 
    1119: 1000028, 
    1254: 1000029, 
    1255: 1000030, 
    1262: 1000040, 
    1250: 1000031, 
    1251: 1000032, 
    1252: 1000033, 
    1253: 1000034, 
    1256: 1000035, 
    928: 1000001, 
    927: 1000013, 
    1140: 1000013, 
    1304: 1000007, 
    1303: 1000013, 
    1305: 1000031, 
    1306: 1000032, 
    1307: 1000033, 
    1308: 1000034, 
    1314: 1000007, 
    1315: 1000036, 
    1316: 1000037, 
    1317: 1000038, 
    1318: 1000029, 
    1319: 1000028, 
    1329: 1000013, 
    1326: 1000001, 
    1311: 1000043, 
    947: 1000042, 
    1271: 759, 
    1145: 1000007, 
    1274: 759, 
    949: 1000011, 
    908: 799, 
    1359: 1000007, 
    1366: 759, 
    1384: 1000041, 
    1321: 1000010, 
    1320: 1000013, 
    1395: 1000041, 
    1392: 759, 
    1394: 1000015, 
    1393: 1000001, 
    1421: 759, 
    1418: 1000031, 
    1419: 1000032, 
    1420: 1000007, 
    1414: 1000013, 
    1455: 1000001, 
    1452: 1000026, 
    1453: 1000031, 
    1454: 1000033, 
    1425: 1000010, 
    1428: 759, 
    1450: 1000010, 
    1429: 1000013, 
    1431: 759, 
    1432: 1000010, 
    1434: 759, 
    1435: 1000007, 
    1436: 1000008, 
    1449: 1000009, 
    1437: 1000010, 
    1448: 1000013, 
    1439: 1000011, 
    1443: 759, 
    1444: 1000041, 
    1446: 759, 
    1447: 1000010, 
    1515: 806, 
    1514: 759, 
    1553: 1000007, 
    1548: 1000009, 
    1516: 1000010, 
    1550: 1000011, 
    1517: 1000013, 
    1520: 1000014, 
    1549: 1000015, 
    1518: 1000002, 
    1519: 1000001, 
    1522: 799, 
    1537: 1000018, 
    1538: 1000019, 
    1539: 1000020, 
    1526: 1000023, 
    1528: 1000024, 
    1529: 1000025, 
    1521: 1000026, 
    1545: 1000029, 
    1525: 1000030, 
    1523: 1000031, 
    1524: 1000032, 
    1527: 1000033, 
    1530: 1000034, 
    1531: 1000036, 
    1532: 1000037, 
    1533: 1000038, 
    1541: 1000039, 
    1543: 1000040, 
    1534: 1000041, 
    1535: 1000042, 
    1536: 1000043, 
    1540: 1000044, 
    1542: 1000045, 
    1546: 1000046, 
    1547: 1000047, 
    1551: 1000048, 
    1552: 1000049
}


def decode_tron_pb(data, verbose=True, debug=False):  
    try:
        tron = tron_pb2.TronRequest()
        # ParseFromString fails with a warning rather than an exception, so we convert warning to an exception
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            tron.ParseFromString(data)
        #if not tron.IsInitialized() or tron.currentTimeMillis==0 or not fieldIsSet(tron.tronEvent):
        #    raise Exception('invalid data')

        #for k in eventToTagMapping:
        #    try: 
        #        print(k, tron.TronEvent.TronView.Name(k))
        #    except:
        #        print('unknown ',k)
        #sys.exit()

        res=""
        grepString = ""
        res=res+"currentTimeMillis: "+str(tron.currentTimeMillis)+"\n"
        for i in range(len(tron.tronEvent)):
            res=res+"tronEvent "+str(i)+" {\n"
            event = tron.tronEvent[i]
            #print(event)
            eventType = tron.TronEvent.TronEventType.Name(event.tronEventType)
            eventView = tron.TronEvent.TronView.Name(event.tronViewEnum)
            eventStr = "tronEventType: " + eventType
            eventStr = eventStr + "\ntronViewOrAction: " + eventView 
            eventStr = eventStr + "\ntimeMs: " + str(event.timeMs) 
            grepString = grepString + str(event.timeMs)+" "+eventType+" "+eventView
            if event.packageName:
                eventStr = eventStr + "\npackageName: " + str(event.packageName) 
                grepString = grepString +" "+str(event.packageName)
            # the data for each event is stored in a field that we need to calculate (the protobuf)
            # fields are reused and change meaning depending in the event)
            if eventView in eventToTagMapping.keys():
                tag = eventToTagMapping[eventView]
                if tag in tagToFieldMapping.keys():
                    fieldNumber = tagToFieldMapping[tag]
                    name = eventView.lower()
                    value = event.DESCRIPTOR.fields_by_number[fieldNumber]
                    eventStr = eventStr+"\n"+name+":" + str(value)
            elif event.tronEventSubType:
                name = "eventSubtype"
                value = event.tronEventSubType
                if eventView == "NOTIFICATION_PANEL":
                    if eventType == "TYPE_DISMISS":
                        value = tron.TronEvent.TronDismissReason.Name(value)  # NotificationManagerService.java
                        name = "dismissReason"
                elif eventView in ["LOCKSCREEN", "BOUNCER"]:
                    name = "secure"
                    if value == 0:
                        value = "UNSECURE"
                    else:
                        value = "SECURE"
                elif eventView == "SCREEN":
                    name = "userAction"
                elif eventView == "DISPLAY_POLICY":                   
                    value = tron.TronEvent.DisplayPolicy.Name(value)  #DisplayManagerInternal
                eventStr = eventStr+"\neventSubtype:" + str(value)
            if re.search("NOTIFICATION",tron.TronEvent.TronView.Name(event.tronViewEnum)):
                if event.notificationTag:
                    eventStr = eventStr+"\nnotificationTag: "+str(event.notificationTag)
                    grepString = grepString +" "+str(event.notificationTag)
                if event.notificationID:
                    eventStr = eventStr+"\nnotificationID: "+str(event.notificationID)
                eventStr = eventStr + "\nnotificationFreshnessMillis: "+str(event.notificationFreshnessMillis)
                eventStr = eventStr + "\nnotificationExposureMillis: "+str(event.notificationExposureMillis)
            if event.notificationChannelOrIntentAction:
                if re.search("INTENT",tron.TronEvent.TronView.Name(event.tronViewEnum)):
                    eventStr = eventStr+"\nintentAction: "+str(event.notificationChannelOrIntentAction)
                elif re.search("NOTIFICATION",tron.TronEvent.TronView.Name(event.tronViewEnum)):
                    eventStr = eventStr+"\nnotificationChannel: "+str(event.notificationChannelOrIntentAction)
                else:
                    eventStr = eventStr+"\nnotificationChannelOrIntentAction: "+str(event.notificationChannelOrIntentAction)
                grepString = grepString +" "+str(event.notificationChannelOrIntentAction)
            if event.fieldClassNameOrAutofillService:
                if re.search("AUTOFILL",tron.TronEvent.TronView.Name(event.tronViewEnum)):
                    eventStr = eventStr+"\nautofillService: "+str(event.fieldClassNameOrAutofillService)
                elif event.fieldClassNameOrAutofillService:
                    eventStr = eventStr+"\nactivity: "+str(event.fieldClassNameOrAutofillService)
                else:
                    eventStr = eventStr+"\nfieldClassNameOrAutofillService: "+str(event.fieldClassNameOrAutofillService)
                grepString = grepString +" "+str(event.fieldClassNameOrAutofillService)
            if event.value:
                name = "value"
                value = event.value
                if eventView in ["QS_WIFI","QS_ROTATIONLOCK","QS_LOCATION","QS_HOTSPOT","QS_FLASHLIGHT","QS_DND","QS_BLUETOOTH","QS_AIRPLANEMODE","QS_CAST","QS_COLORINVERSION"]:
                    if event.value == 0:
                        value = "OFF"
                    else:
                        value = "ON"
                    name = "setting"
                elif eventView == "SCREEN":
                    name = "userAction"
                    value = tron.TronEvent.TronEventType.Name(value)
                elif eventView == "ACTION_VOLUME_SLIDER" or eventView == "ACTION_VOLUME_KEY":
                    name = "volumeLevel"
                elif eventView == "ACTION_VOLUME_STREAM":
                    name = "stream"  #AudioSystem.java
                elif eventView == "ACTION_VOLUME_SLIDER":
                    name = "volumeLevel"
                eventStr = eventStr+"\n"+name+": "+str(value)
                grepString = grepString +" "+name+":"+str(value)
            if event.base64MessageDigest:
                eventStr = eventStr+"\nbase64MessageDigest: "+str(event.base64MessageDigest) 
            eventStr = eventStr+protoToString("\naccountInfo", event.accountInfo) 
            if event.moduleVersion:
                eventStr = eventStr+"\nmoduleVersion: "+str(event.moduleVersion) 
            # print out any other fields we might have missed
            unknown = protoUnknownFieldsToString(event)
            if len(unknown) > 0:
                eventStr = eventStr + "\n"+unknown
                try:
                    for extra in [31, 44]:
                        if fieldIsSet(event.DESCRIPTOR.fields_by_number[extra]):
                            grepString = grepString +" "+str(event.DESCRIPTOR.fields_by_number[extra])
                except:
                    pass
            res=res+str(eventStr)+"\n"
            res=res+"}\n"
        res=res+protoToString("experimentTokens", tron.experimentTokens)+"\n"
        res=res+"bootCount: "+str(tron.bootCount)+"\n"
        res=res+protoToString("connectionDetails", tron.connectionDetails)+"\n"
        # print out any other fields we might have missed
        unknown = protoUnknownFieldsToString(tron)
        if len(unknown) > 0:
            res=res+unknown+"\n"

        if True and len(grepString)>0:
            # print interesting content in a way that's easy to grep out of log file
            res=res+"+++TRON "+grepString+"\n"
        return res
    except Exception as e:
        if verbose:
            print(repr(e))
        return "Failed"


#f = open('/tmp/tron_bytes', 'rb')
if len(sys.argv)>1:
    fname=sys.argv[1]
else:
    fname='/tmp/tron_bytes'
f = open(fname, 'rb')
data = f.read()
f.close()
res=try_decode_pb_array("tron event", data, decode_tron_pb, verbose=True, debug=False)
#print(decode_pb(data))
print(res)
