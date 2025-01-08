import logbatch_pb2
import stats_log_pb2  # westworld
import lockbox_pb2
#import android_dialer_pb2
import subprocess
import textwrap
import sys, traceback
import os
import re
import dumper
import tempfile

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
from decoding_helpers import decode_pb, decode_wbxml, decode_log_batch, decode_firebase_analytics, try_decode_pb_array, protoUnknownFieldsToString, protoToString, fieldIsSet, makeIter
import gboard_pb3
import activity_recognition_pb2


def decode_messaging_pb(bb, verbose=False, terse=False, debug=False):
    if debug:
        fname='/tmp/message_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(bb)
    f.close()
    try:
        str = subprocess.check_output("cat "+fname+" | protoc --decode=AndroidMessaging_LogEntry -I='"+mypath+"' android_messaging.proto3",shell=True,stderr=subprocess.STDOUT, text=True)
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


def decode_dialer_pb(bb, verbose=False, terse=False, debug=False):
    if debug:
        fname='/tmp/dialer_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(bb)
    f.close()
    try:
        str = subprocess.check_output("cat "+fname+" | protoc --decode=AndroidDialer_LogEntry -I='"+mypath+"' android_dialer.proto3",shell=True,stderr=subprocess.STDOUT, text=True)
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


def decode_gboard_pb(bb, verbose=False, terse=False, grep=True, debug=False):
    if debug:
        fname='/tmp/gboard_bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(bb)
    f.close()
    try:
        str = subprocess.check_output("cat "+fname+" | protoc --decode=LatinIME_LogEntry -I='"+mypath+"' gboard.proto3",shell=True,stderr=subprocess.STDOUT, text=True)
        if str is not None and terse:
            # just write out minimal event info
            str = str.split('\n')
            out = ""; ts = False
            for s in str:
                m = re.match('timestamp: ([0-9]+)', s)
                if m and not ts:
                    out = out+m.group(1)+" "
                    ts = True
                elif re.search('eventType', s):
                    out = out+s
            print(out)
            return ""
        if grep:
            try: 
                gboard = gboard_pb3.LatinIME_LogEntry()
                gboard.ParseFromString(bb)
                if gboard.input_info.keyboard_usage_info:
                    packageName = gboard.input_info.keyboard_usage_info.applicationName
                    str=str+"+++LATIN_IME %s %s %s %s"%(gboard.currentTimeMillis,gboard.elapsedRealtime,gboard.keyboardEvent,packageName)
            except Exception as e:
                print("LATIN_IME grep failed:")
                print(e)
        return str
    except subprocess.CalledProcessError as e: 
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def printAtom(tt, a, strhash, westworld):
    if a is not None:
        for t in makeIter(tt):
            printAtomInfo(t, a, strhash, westworld)


def printAtomInfo(t, a, strhash, westworld):
    try:
        #print(a)
        atoms=stats_log_pb2.frameworks_dot_proto__logging_dot_stats_dot_atoms__pb2
        if fieldIsSet(a.ui_event_reported):
            u=a.ui_event_reported
            print("+++WESTWORLD_UIEVENT", t, atoms.UiEventId.Name(u.event_id), u.package_name)
        elif fieldIsSet(a.battery_level_changed):
            b=a.battery_level_changed
            print("+++WESTWORLD_BATTERY", t, b.battery_level)
        elif fieldIsSet(a.notification_reported):
            n=a.notification_reported
            print("+++WESTWORLD_NOTIFICATION", t, atoms.UiEventId.Name(n.event_id), n.package_name, n.instance_id, n.notification_id_hash, n.channel_id_hash, n.category)
        elif fieldIsSet(a.launcher_event):
            l=a.launcher_event
            if len(l.package_name)>0:
                # this check excludes purely launcher-related actions e.g. LAUNCHER_SWIPERIGHT, LAUNCHER_SWIPELEFT, LAUNCHER_TASK_DISMISS_SWIPE_UP
                print("+++WESTWORLD_LAUNCHER", t, atoms.UiEventId.Name(l.event_id), l.package_name, l.component_name, l.src_state, l.dst_state)
        elif fieldIsSet(a.launcher_snapshot):
            l=a.launcher_snapshot
            print("+++WESTWORLD_LAUNCHERSNAPSHOT", t, atoms.UiEventId.Name(l.event_id), l.package_name, l.component_name)
        elif fieldIsSet(a.settings_ui_changed):
            l=a.settings_ui_changed
            if l.action:
                print("+++WESTWORLD_SETTINGSUI", t, l.action, l.page_id, l.changed_preference_key)
        elif fieldIsSet(a.app_start_occurred):
            l=a.app_start_occurred
            print("+++WESTWORLD_APPSTART", t, l.type, l.calling_pkg_name, strhash, l.activity_name_hash, l.reason)
        # added app_usage_event_occurred 25/6/24
        elif fieldIsSet(a.app_usage_event_occurred):
            l=a.app_usage_event_occurred
            # MOVE_TO_FOREGROUND = 1; MOVE_TO_BACKGROUND = 2;
            print("+++WESTWORLD_APPUSAGE", t, l.event_type, strhash)
        elif fieldIsSet(a.setting_snapshot):
            l=a.setting_snapshot
            print("+++WESTWORLD_SETTINGSNAPSHOT", t, strhash, l.type, l.bool_value, l.int_value, l.float_value, l.str_value)
        elif fieldIsSet(a.back_gesture_reported_reported):
            l=a.back_gesture_reported_reported
            print("+++WESTWORLD_BACKGESTURE", t, l.x_location, l.start_x, l.start_y, l.end_x, l.end_y, l.package_name)
        elif fieldIsSet(a.screen_state_changed):
            l=a.screen_state_changed
            # DISPLAY_STATE_OFF = 1, DISPLAY_STATE_ON = 2, DISPLAY_STATE_DOZE = 3
            print("+++WESTWORLD_SCREENSTATE", t, l.state)
        elif fieldIsSet(a.grant_permissions_activity_button_actions):
            l=a.grant_permissions_activity_button_actions
            print("+++WESTWORLD_GRANTPERMISSION", t, l.permission_group_name,l.package_name)
        elif fieldIsSet(a.permission_grant_request_result_reported):
            l=a.permission_grant_request_result_reported
            print("+++WESTWORLD_PERMISSIONREPORT", t,l.permission_name,l.package_name, l.result)
        elif fieldIsSet(a.boot_sequence_reported):
            l=a.boot_sequence_reported
            print("+++WESTWORLD_BOOTREPORT", t,l.system_reason, l.end_time_millis)
        elif fieldIsSet(a.shutdown_sequence_reported):
            l=a.shutdown_sequence_reported
            print("+++WESTWORLD_SHUTDOWNREPORT", t,l.reboot, l.start_time_millis)
        elif fieldIsSet(a.keyguard_state_changed):
            l=a.keyguard_state_changed
            # HIDDEN = 1; SHOWN= 2;
            print("+++WESTWORLD_KEYGUARD", t, l.state)                                             
        elif fieldIsSet(a.usb_connector_state_changed):
            l=a.usb_connector_state_changed
            print("+++WESTWORLD_USB", t, l.state)   
        elif fieldIsSet(a.bluetooth_enabled_state_changed):
            l=a.bluetooth_enabled_state_changed
            print("+++WESTWORLD_BLUETOOTH", t, l.state, l.reason)                      
        elif fieldIsSet(a.bluetooth_socket_connection_state_changed):
            l=a.bluetooth_socket_connection_state_changed
            print("+++WESTWORLD_BLUETHOOTH_SOCKCONNECTIONSTATE", t, l.state)    
        # 'bluetooth_a2dp_playback_state_changed', 'bluetooth_acl_connection_state_changed', 'bluetooth_active_device_changed', 'bluetooth_activity_info', 'bluetooth_bond_state_changed', 'bluetooth_bytes_transfer', 'bluetooth_class_of_device_reported', 'bluetooth_classic_pairing_event_reported', 'bluetooth_connection_state_changed', 'bluetooth_device_failed_contact_counter_reported', 'bluetooth_device_info_reported', 'bluetooth_device_rssi_reported', 'bluetooth_device_tx_power_level_reported', 'bluetooth_enabled_state_changed', 'bluetooth_hal_crash_reason_reported', 'bluetooth_hci_timeout_reported', 'bluetooth_link_layer_connection_event', 'bluetooth_quality_report_reported', 'bluetooth_remote_version_info_reported', 'bluetooth_sco_connection_state_changed', 'bluetooth_sdp_attribute_reported', 'bluetooth_smp_pairing_event_reported', 'bluetooth_socket_connection_state_changed',                  
        elif fieldIsSet(a.network_validation_reported):
            l=a.network_validation_reported
            if fieldIsSet(l.probe_events):
                for p in makeIter(l.probe_events.probe_event):
                    success=0
                    if p.probe_type == 3: # HTTPS
                        success=p.probe_result # PR_SUCCESS = 1, PR_FAILURE = 2
                # transport_type: TT_CELLULAR = 1; TT_WIFI = 2; TT_CELLULAR_VPN = 7; TT_WIFI_VPN = 8;
                print("+++WESTWORLD_NETWORKREPORT", t, l.transport_type, success)

    except Exception as e:
        print("printAtom failed:")
        print(repr(e))
        traceback.print_exc(file=sys.stdout)
        print('----')
        print(a)
        print('----')
        #sys.exit()

    # face_settings, memory usage, temperature, surfaceflinger_stats per app, uid of all apps and app installer
    # plenty of histogram data
    # boot_sequence_reported, shutdown_sequence_reported, network_validation_reported
    # network_dns_event_reported


def grep_westworld(bytes):    
    try:        
        westworld = stats_log_pb2.WestworldRequest()
        westworld.ParseFromString(bytes)
        # print interesting content in a way that's easy to grep out of log file
        for w in makeIter(westworld.statsLogMetricsReport):
            if not w.configMetricsReportList:
                return
            for c in makeIter(w.configMetricsReportList):
                # do a first walk through to get strings and calc their hashes
                strhashes = {}
                bootTimeNanos = -1
                for r in makeIter(c.reports):
                    if r.current_report_elapsed_nanos:
                        print("+++WESTWORLD_TIME",r.current_report_elapsed_nanos,r.current_report_wall_clock_nanos)
                        bootTimeNanos = (r.current_report_wall_clock_nanos - r.current_report_elapsed_nanos)
                        print("+++bootTimeNanos=",bootTimeNanos)
                    if r.strings:
                        for s in makeIter(r.strings):
                            try:
                                res = subprocess.check_output('"'+mypath+'/SMHasher" '+'"'+s+'"', shell=True, stderr=subprocess.STDOUT, text=True)
                                res = int(res.strip())
                                print("+++WESTWORLD_STRINGS", s, res)
                                strhashes[res] = s   # mapping from hash to string
                            except Exception as e:
                                print("SMHasher failed:")
                                print(repr(e))
                if bootTimeNanos<0:
                    print("ERROR: bootTimeNanos not set by WESTWORLD!")
                # now walk through the events
                for r in makeIter(c.reports):
                    if r.metrics:
                        for m in makeIter(r.metrics):
                            a = None; strhash=None
                            if m.event_metrics and m.event_metrics.data:
                                try:
                                    for aa in makeIter(m.event_metrics.data):
                                        if aa.aggregated_atom_info:
                                            # updated 25/6/24 to show all elapsed times not just the first one
                                            for elapsed_time in aa.aggregated_atom_info.elapsed_timestamp_nanos:
                                                # updated 5/1/24 to print wall clock nanos.  DL
                                                printAtom(elapsed_time+bootTimeNanos, aa.aggregated_atom_info.atom, None, westworld)
                                        elif aa.atom:
                                            for elapsed_time in aa.aggregated_atom_info.elapsed_timestamp_nanos:
                                                printAtom(elapsed_time+bootTimeNanos, aa.atom, None, westworld)
                                except Exception as e:
                                    print("event metrics failed:"); print(repr(e))
                                    print("---"); print(aa); print("---")
                            elif m.gauge_metrics and m.gauge_metrics.data:
                                try:
                                    for aa in makeIter(m.gauge_metrics.data):
                                        if fieldIsSet(aa.dimension_leaf_values_in_what):
                                            for bb in makeIter(aa.dimension_leaf_values_in_what):
                                                if fieldIsSet(bb.value_str_hash):
                                                    strhash = bb.value_str_hash
                                                    if strhash in strhashes.keys():
                                                        strhash = strhashes[strhash]  # map hash back to string
                                        if aa.bucket_info:
                                            for b in makeIter(aa.bucket_info):
                                                # updated 5/1/24 to print wall clock nanos.  DL
                                                if b.aggregated_atom_info:
                                                    for c in makeIter(b.aggregated_atom_info):
                                                        # updated 25/6/24 to show all elapsed times not just the first one
                                                        for elapsed_time in c.elapsed_timestamp_nanos:
                                                            printAtom(elapsed_time+bootTimeNanos, c.atom, strhash, westworld)
                                                elif b.atom:
                                                    for c in makeIter(b.atom):
                                                        for elapsed_time in b.elapsed_timestamp_nanos:
                                                            printAtom(elapsed_time+bootTimeNanos, c, strhash, westworld)
                                except Exception as e:
                                    print("gauge metrics failed:"); print(repr(e))
                                    print("---"); print(aa); print("---")
    except Exception as e:
        print('grep westworld failed:')
        print(e)

def decode_westworld(bytes, verbose=False, terse=False, grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/westworld_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"android.os.statsd.WestworldRequest\" -I='"+mypath+"' stats_log.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        if grep:
            grep_westworld(bytes)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_lockbox(bytes, verbose=False, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/lockbox_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"LockboxRequest\" -I='"+mypath+"' lockbox.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        if Grep:
            lockbox = lockbox_pb2.LockboxRequest()
            lockbox.ParseFromString(bytes)
            # print interesting content in a way that's easy to grep out of log file
            for l in lockbox.lockboxUsageReport:
                print("+++LOCKBOX", l.timestamp, lockbox.EventType.Name(l.eventType), l.packageName, l.className)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_AR(bytes, verbose=False, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/AR_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"ActivityRecognitionRequest\" -I='"+mypath+"' activity_recognition.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        if Grep:
            try: 
                AR = activity_recognition_pb2.ActivityRecognitionRequest()
                AR.ParseFromString(bytes)
                # print interesting content in a way that's easy to grep out of log file
                if fieldIsSet(AR.activityRecognitionEvent):
                    for ar in makeIter(AR.activityRecognitionEvent):
                        if fieldIsSet(ar.activityDetectedList):
                            for a in makeIter(ar.activityDetectedList):
                                if fieldIsSet(a.activityDetected):
                                    for aa in makeIter(a.activityDetected):
                                        for aaa in makeIter(aa.activity):
                                            print("+++ACTIVITY_RECOGNITION", aa.timeMillis, aaa.activity, aaa.confidence)
                        elif fieldIsSet(ar.activityDetectedCHREList):
                            for a in makeIter(ar.activityDetectedCHREList):
                                if fieldIsSet(a.activityDetected):
                                    for aa in makeIter(a.activityDetected):
                                        for aaa in makeIter(aa.activity):
                                            if fieldIsSet(aaa.activity):
                                                print("+++ACTIVITY_RECOGNITION_CHRE", aa.timeMillis, aaa.activity, aaa.confidence)
                        elif fieldIsSet(ar.activityTransitionEvent):
                            aa=ar.activityTransitionEvent
                            aaa=ar.activityTransitionEvent.newActivity1
                            print("+++ACTIVITY_RECOGNITION_TRANSITION", aa.timeMillis, aaa.activity, aaa.confidence)
            except Exception as e:
                print("Failed grepping AR:")
                print(repr(e))
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


def decode_tron(bytes, verbose=True, terse=False, debug=False):
    try:
        #f = open('/tmp/tron_bytes', 'wb')
        if debug:
            fname='/tmp/tron_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        #decoded = subprocess.check_output("protoc --decode=\"TronRequest\" -I='"+mypath+"' tron.proto  </tmp/tron_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        decoded = subprocess.check_output("python3 '"+mypath+"/tron_decode.py' '"+fname+"'", 
                                      shell=True, stderr=subprocess.STDOUT, text=True)
        #print("TRON decoded="+decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"

def decode_netstats(bytes, verbose=False, terse=False, debug=False):
    try:
        if debug:
            fname='/tmp/netstats_bytes'
            f = open(fname, 'wb')
        else:
            f = tempfile.NamedTemporaryFile(delete=False)
            fname=f.name
        f.write(bytes)
        f.close()
        decoded = subprocess.check_output("protoc --decode=\"NetstatsRequest\" -I='"+mypath+"' netstats.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        #print(decoded)
        return(decoded)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(e.output)
            print(e)
        return "Failed"


if len(sys.argv)>1:
    fname=sys.argv[1]
else:
    fname='/tmp/batch_bytes'
f = open(fname, 'rb')
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
        #print("header{\n"+textwrap.indent(str(inner.header),'   ')+"}")
        print(protoToString("header", inner.header))
        if "androidID" in str(inner.header):
            androidID = True
        else:
            androidID = False
        print("currentTimeMillis: "+str(inner.currentTimeMillis))
        print("pseudonymousIdToken: "+inner.pseudonymousIdToken)
        print("elapsedTime: "+str(inner.elapsedTime))
        print("qosTier: "+str(inner.qosTier))
        print("deviceStatus{\n"+textwrap.indent(str(inner.deviceStatus),'   ')+"}")
        # print out any other fields we might have missed
        unknown = protoUnknownFieldsToString(inner)
        if len(unknown) > 0:
            print(unknown)

        if True:  #tag log source name with whether androidID is set in header
            if not androidID:
                print("logSourceName: "+inner.logSourceName+' (anon)') 
            else:
                print("logSourceName: "+inner.logSourceName)
        else:
            print("logSourceName: "+inner.logSourceName)
        #try_decode_pb_array("logEntry", inner.logEntry, decode_pb)   
        if inner.logSourceName == "ANDROID_MESSAGING":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_messaging_pb, verbose=True, debug=False) )  
        elif inner.logSourceName == "ANDROID_DIALER":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_dialer_pb, verbose=True, debug=False))
        elif inner.logSourceName == "LATIN_IME":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_gboard_pb, verbose=True, debug=False))
        elif inner.logSourceName == "WESTWORLD" or inner.logSourceName == "ANONYMOUS_WESTWORLD":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_westworld, verbose=True, debug=False))
        elif inner.logSourceName == "LB_AS" or inner.logSourceName == "LB_CFG":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_lockbox, verbose=True, debug=False))
        elif inner.logSourceName == "TRON":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_tron, verbose=True, debug=False))
            #print('logEntry:')
            #res=decode_tron(inner.logEntry) 
            #if res=="Failed":
        elif inner.logSourceName == "ACTIVITY_RECOGNITION":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_AR, verbose=True, debug=False))
        elif inner.logSourceName == "NETSTATS":
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_netstats, verbose=True, debug=True))
        else:
            print(try_decode_pb_array("logEntry", inner.logEntry, decode_pb, verbose=True, debug=False))
        print("}")
except Exception as e:
    print(e)

