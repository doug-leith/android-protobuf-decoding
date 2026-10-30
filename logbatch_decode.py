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
import base64
import functools
from datetime import datetime
import pytz

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
from decode_named import decode_named, message_class, DecodeNamedError  # in-process `protoc --decode`
from decoding_helpers import run_decoder_script, ScriptDecodeError, decode_pb, decode_wbxml, decode_log_batch, decode_firebase_analytics, try_decode_pb_array, protoUnknownFieldsToString, protoToString, fieldIsSet, makeIter
import gboard_named_pb  # LATIN_IME, from gboard_named.proto (old manual gboard.proto3 kept as gboard.proto3.backup)
import icing_named_pb  # ICING, from icing_named.proto (generated from the GMS 21.48.15 APK)
import activity_recognition_pb2


def decode_messaging_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    if debug:
        fname='/tmp/message_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("AndroidMessaging_LogEntry", "android_messaging.proto3", bb)
        grep=""
        if decoded is not None and (Grep or terse):
            # just write out minimal event info, handy for getting an overview of a sequence of events
            res = decoded.split('\n')
            out = ""; ts = False
            grep="+++ANDROID_MESSAGING "; 
            try:
                for s in res:
                    m = re.match('timestamp: ([0-9]+)', s)
                    if m and not ts:
                        tstamp=int(m.group(1))
                        out = out+str(tstamp)+" "
                        grep = grep+str(tstamp)+" "
                        date=datetime.utcfromtimestamp(tstamp/1000)
                        date_str = date.astimezone(pytz.FixedOffset(0)).strftime('%d/%m/%Y_%H:%M:%S.%f_%z')
                        grep = grep+date_str+" "
                        ts = True
                    elif re.search('eventType', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
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
                        grep=grep+s.replace(" ", "")+" "
                    #elif re.search('sendAttempt', s):
                    #    out = out+s
                    elif re.search('suggestionEventType', s):
                        out = out+s
                        grep=grep+s+" "
                    elif re.search('appLaunch', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('sha256HashMsg', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('sha256HashPrevMsg', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                grep=grep+"\n"
                if terse:
                    print(out)
                    return ""
            except Exception as e:
                print("***ERROR ANDROID_MESSAGING grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:         
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_dialer_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    if debug:
        fname='/tmp/dialer_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("AndroidDialer_LogEntry", "android_dialer.proto3", bb)
        grep=""
        if decoded is not None and (Grep or terse):
            # just write out minimal event info
            res = decoded.split('\n')
            out = ""; ts = False
            grep="+++ANDROID_DIALER "; 
            try:
                for s in res:
                    m = re.match('timestamp: ([0-9]+)', s)
                    if m and not ts:
                        #print(m.groups())
                        tstamp=int(m.group(1))
                        out = out+str(tstamp)+" "
                        grep = grep+str(tstamp)+" "
                        date=datetime.utcfromtimestamp(tstamp/1000)
                        date_str = date.astimezone(pytz.FixedOffset(0)).strftime('%d/%m/%Y_%H:%M:%S.%f_%z')
                        grep = grep+date_str+" "
                        ts = True
                    elif re.search('impressionEvent', s):
                        out = out+s
                        grep=grep+"impressionEvent "
                    elif re.search('AOSPEventType:', s):
                        out = out+s
                        #parts=s.split(" ")
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('eventType:', s):
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('searchQuery', s):
                        out = out+s
                        grep=grep+"searchQuery "
                    elif re.search('queryLength:', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('callDetails', s):
                        out = out+s
                        grep=grep+"callDetails "
                    elif re.search('callDuration:', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                grep=grep+"\n"
                if terse:
                    print(out)
                    return ""
            except Exception as e:
                print("***ERROR ANDROID_DIALER grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_gboard_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    if debug:
        fname='/tmp/gboard_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("LatinIME_LogEntry", "gboard_named.proto", bb)
        grep=""
        if decoded is not None and terse:
            # just write out minimal event info
            res = decoded.split('\n')
            out = ""; ts = False
            for s in res:
                m = re.match('timestamp: ([0-9]+)', s)
                if m and not ts:
                    out = out+m.group(1)+" "
                    ts = True
                elif re.search('eventType', s):
                    out = out+s
            print(out)
            return ""
        if Grep:
            try: 
                gboard = gboard_named_pb.LatinIME_LogEntry()
                gboard.ParseFromString(bb)
                packageName = "-NoPackageName"
                wordInfo="-NoWordInfo"
                if fieldIsSet(gboard.input_info):
                    if fieldIsSet(gboard.input_info.keyboard_usage_info):
                        if fieldIsSet(gboard.input_info.keyboard_usage_info.applicationName):
                            packageName = gboard.input_info.keyboard_usage_info.applicationName
                    if fieldIsSet(gboard.input_info.word_input_info):
                        if fieldIsSet(gboard.input_info.word_input_info.committedTextLength):
                            wordInfo="len:"+str(gboard.input_info.word_input_info.committedTextLength)
                        if fieldIsSet(gboard.input_info.word_input_info.timeToEnterWord):
                            wordInfo=wordInfo+"+time:"+str(gboard.input_info.word_input_info.timeToEnterWord)                   
                try:
                    kevent=gboard_named_pb.KeyboardEvent
                    event=kevent.Name(gboard.keyboardEvent)
                except:
                    event=str(gboard.keyboardEvent)
                grep="+++LATIN_IME %s %s %s %s %s\n"%(gboard.currentTimeMillis,gboard.elapsedRealtime,event,packageName,wordInfo)
            except Exception as e:
                print("***ERROR LATIN_IME grep: ",e)
        return grep+decoded
    except DecodeNamedError as e: 
        if verbose:
            print("***ERROR LATIN_IME: ",e)
        return "Failed"


def decode_icing_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # ICING log source: GMS icing (on-device search index) and the libraries that
    # log under it (MobileDataDownload, MDH channel sync, ProtoDataStore, MobStore)
    if debug:
        fname='/tmp/icing_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("Icing_LogEntry", "icing_named.proto", bb)
        grep=""
        if Grep:
            try:
                ev = icing_named_pb.Icing_LogEntry()
                ev.ParseFromString(bb)
                # which kinds of record this event carries (one or more IcingLogEvent fields)
                kinds = [fd.name for fd, _v in ev.icing_log_event.ListFields() if fd.name != "sample_interval"]
                pkg = ""
                if ev.icing_log_event.HasField("package_name_and_icing_version_proto"):
                    pkg = " ".join(str(v) for _fd, v in ev.icing_log_event.package_name_and_icing_version_proto.ListFields())
                grep="+++ICING %s %s %s %s\n"%(ev.currentTimeMillis, ev.eventId, ",".join(kinds) or "-", pkg)
            except Exception as e:
                print("***ERROR ICING grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR ICING: ",e)
        return "Failed"


def chime_event(fe):
    # "INTERACTION:SHOWN", "FAILURE:DROPPED_BY_CLIENT/SILENT_NOTIFICATION", ... for the +++CHIME grep line
    def name(msg, field):
        v = getattr(msg, field)
        e = msg.DESCRIPTOR.fields_by_name[field].enum_type.values_by_number.get(v)
        return e.name if e is not None else str(v)
    kind = fe.WhichOneof("entry")
    if kind == "interaction":
        i = fe.interaction
        detail = [name(i, f) for f in ("remove_reason", "fetch_reason", "built_in_action_type") if i.HasField(f)]
        if i.action_id:
            detail.append("action=" + i.action_id)
        return "/".join(["INTERACTION:" + name(i, "interaction_type")] + detail)
    if kind == "failure":
        f = fe.failure
        detail = [name(f, x) for x in ("drop_reason", "registration_failure_reason") if f.HasField(x)]
        if f.exception:
            detail.append("exception=" + f.exception)
        return "/".join(["FAILURE:" + name(f, "failure_type")] + detail)
    if kind == "system_event":
        return "SYSTEM_EVENT:" + name(fe.system_event, "system_event")
    return kind or "-"

def decode_chime_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # CHIME log source: notification events (delivered, shown, clicked, dropped, ...) from Google's notification
    # library GnpSdk/Chime in Google apps and GMS
    if debug:
        fname='/tmp/chime_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        ev = message_class("Chime_LogEntry", "chime_named.proto")()
        ev.MergeFromString(bb)
    except Exception:
        ev = None
    if ev is None or not ev.HasField("currentTimeMillis"):
        # not one LogEvent (e.g. try_decode_pb_array's first try with the whole length-delimited logEntry array)
        if verbose:
            print("***ERROR CHIME: not a LogEvent")
        return "Failed"
    try:
        decoded = decode_named("Chime_LogEntry", "chime_named.proto", bb)
        grep=""
        if Grep:
            try:
                fe = ev.chime_frontend_log.frontend_entry
                ctx = fe.context
                target = ctx.target
                pkg = target.package_name or target.chime_target.delivery_address.android_target.package_name or ev.packageName
                threads = "|".join(t.thread_id for t in ctx.thread) or "-"
                channels = [t.channel_id for t in ctx.thread if t.channel_id]
                if fe.interaction.HasField("channel"):
                    channels.append(fe.interaction.channel.channel_id)
                if fe.interaction.HasField("channel_group"):
                    channels.append("group:" + fe.interaction.channel_group.group_id)
                app_channels = "|".join(c.channel_id for c in ctx.render_context.device_info.notification_channel) or "-"
                grep="+++CHIME %s %s %s %s threads=%s channel=%s app_channels=%s\n"%(ev.currentTimeMillis, pkg or "-",
                    ctx.client_id or "-", chime_event(fe), threads, "|".join(channels) or "-", app_channels)
            except Exception as e:
                print("***ERROR CHIME grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR CHIME: ",e)
        return "Failed"


def decode_clientlogging_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # CLIENT_LOGGING_PROD log source: warning/error log records uploaded by Google apps built on TikTok
    if debug:
        fname='/tmp/clientlogging_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("ClientLogging_LogEntry", "client_logging_named.proto", bb)
        grep=""
        if Grep:
            try:
                ev = message_class("ClientLogging_LogEntry", "client_logging_named.proto")()
                ev.MergeFromString(bb)
                cl = ev.client_log
                rec = cl.log_record
                site = "%s.%s:%d"%(rec.class_name, rec.method_name, rec.line_number) if rec.class_name else "-"
                trace = "|".join(cl.trace.span_name) or "-"
                args = "|".join(a.value for a in cl.logged_argument) or "-"
                exc = rec.throwable.throwable.class_name or "-"
                count = " count=%d"%cl.repeat_count if cl.HasField("repeat_count") else ""
                grep="+++CLIENT_LOGGING %s %s %s level=%s %s%s thread=%s site=%s trace=%s args=%s exception=%s message=%r\n"%(
                    ev.currentTimeMillis, cl.client_info.app_info.package_name or "-", cl.client_info.app_info.version_name or "-",
                    rec.level, ev.client_log.DESCRIPTOR.fields_by_name["log_type"].enum_type.values_by_number[cl.log_type].name, count,
                    rec.thread_name or "-", site, trace, args, exc, rec.message)
            except Exception as e:
                print("***ERROR CLIENT_LOGGING grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR CLIENT_LOGGING: ",e)
        return "Failed"


def _primes_enum(msg, field):
    v = getattr(msg, field)
    e = msg.DESCRIPTOR.fields_by_name[field].enum_type.values_by_number.get(v)
    return e.name if e is not None else str(v)

def _primes_grep(m):
    # "metric types" plus "key=value" summaries of a SystemHealthMetric, for the +++PRIMES grep line
    common = ("application_info", "device_info", "sampling_parameters", "metric_extension", "accountable_component",
              "constant_event_name", "custom_event_name", "hashed_custom_event_name")
    kinds = [fd.name for fd, _v in m.ListFields() if fd.name not in common]
    info = []
    if m.constant_event_name:
        info.append("name=%s" % m.constant_event_name)
    if m.HasField("hashed_custom_event_name"):
        info.append("hashed_name=%016x" % m.hashed_custom_event_name)
    if m.accountable_component.custom_name:
        info.append("component=%s" % m.accountable_component.custom_name)
    if m.HasField("memory_usage_metric"):
        mu = m.memory_usage_metric
        info.append("memory_event=%s activity=%s rss_kb=%d" % (_primes_enum(mu, "memory_event_code"), mu.activity_name or "-",
                                                             mu.memory_stats.android_memory_stats.vm_rss_kb))
    if m.HasField("timer_metric"):
        info.append("duration_ms=%d" % m.timer_metric.duration_ms)
    if m.HasField("primes_trace"):
        tr = m.primes_trace
        info.append("trace=%s spans=%d%s" % (_primes_enum(tr, "trace_type"), len(tr.span),
                                             "(" + tr.span[0].constant_name + ")" if tr.span and tr.span[0].constant_name else ""))
        if tr.HasField("startup_metric"):
            st = tr.startup_metric
            acts = "|".join(a.activity_name for a in (st.first_activity, st.second_activity) if a.activity_name) or "-"
            info.append("startup=%s startup_ms=%d fully_drawn_ms=%d activities=%s" % (_primes_enum(st, "startup_type"),
                        st.startup_ms, st.app_fully_drawn_ms, acts))
    if m.HasField("jank_metric"):
        j = m.jank_metric
        info.append("jank_frames=%d/%d duration_ms=%d" % (j.jank_frame_count, j.rendered_frame_count, j.duration_ms))
    if m.HasField("network_usage_metric"):
        paths = [n.constant_rpc_path or n.request_path or "-" for n in m.network_usage_metric.network_event_usage]
        info.append("requests=%s" % "|".join(paths))
    if m.HasField("crash_metric"):
        c = m.crash_metric
        info.append("crash=%s exception=%s activity=%s thread=%s" % (_primes_enum(c, "crash_type"), c.exception_class_name or "-",
                                                                   c.active_activity_name or "-", c.thread_name or "-"))
    if m.HasField("primes_stats"):
        info.append("primes_event=%s" % _primes_enum(m.primes_stats, "primes_event"))
    if m.HasField("battery_usage_metric"):
        b = m.battery_usage_metric.battery_stats_diff
        info.append("battery=%s->%s duration_ms=%d" % (_primes_enum(b, "start_info"), _primes_enum(b, "end_info"), b.duration_ms))
    if m.HasField("application_exit_metric"):
        info.append("exits=%s" % ("|".join("%s:%s" % (x.process_name, _primes_enum(x, "reason"))
                                          for x in m.application_exit_metric.application_exit_info) or "-"))
    if m.HasField("ui_thread_hang"):
        h = m.ui_thread_hang
        info.append("ui_thread_blocked_ms=%d" % (h.blocked_for_ms or h.total_blocked_ms))
    if m.HasField("package_metric"):
        info.append("data_size=%d" % m.package_metric.data_size)
    return ",".join(kinds) or "-", " ".join(info)

def decode_primes_pb(bb, verbose=True, terse=False, Grep=True, debug=False, source="PRIMES"):
    # *_PRIMES log sources: performance metrics from Google's Primes library (memory, timers, app startup, jank,
    # network requests, crashes, battery), one SystemHealthMetric per event
    if debug:
        fname='/tmp/primes_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        ev = message_class("Primes_LogEntry", "primes_named.proto")()
        ev.MergeFromString(bb)
    except Exception:
        ev = None
    if ev is None or not ev.HasField("currentTimeMillis"):
        # every LogEvent has its event time; without it these bytes are not one event (e.g. try_decode_pb_array's
        # first try with the whole length-delimited logEntry array, which this broad schema would otherwise accept)
        if verbose:
            print("***ERROR PRIMES: not a LogEvent")
        return "Failed"
    try:
        decoded = decode_named("Primes_LogEntry", "primes_named.proto", bb)
        grep=""
        if Grep:
            try:
                m = ev.system_health_metric
                kinds, info = _primes_grep(m)
                grep="+++PRIMES %s %s %s %s %s %s\n"%(ev.currentTimeMillis, source, m.application_info.application_package_name or "-",
                    m.application_info.application_version_name or "-", kinds, info)
            except Exception as e:
                print("***ERROR PRIMES grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR PRIMES: ",e)
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
        print("***ERROR printAtom failed: ",e)
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
        for kv in westworld.keyValuePair:
            if kv.key == "CONSENT_INFO":
                print("CONSENT_INFO (decoded):")
                print(decode_named("ConsentInformationWrapper", "consentinfo.proto", base64.b64decode(kv.value)))

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
                                print("***ERROR SMHasher failed: ",e)
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
                                    print("***ERROR event metrics failed: ",e)
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
                                    print("***ERROR gauge metrics failed: ",e)
                                    print("---"); print(aa); print("---")
    except Exception as e:
        print("***ERROR WESTWORLD grep: ",e)

def decode_westworld(bytes, verbose=True, terse=False, grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/westworld_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("android.os.statsd.WestworldRequest", "stats_log.proto", bytes)
        #print(decoded)
        if grep:
            grep_westworld(bytes)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_lockbox(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/lockbox_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("LockboxRequest", "lockbox.proto", bytes)
        #print(decoded)
        if Grep:
            lockbox = lockbox_pb2.LockboxRequest()
            lockbox.ParseFromString(bytes)
            # print interesting content in a way that's easy to grep out of log file
            for l in lockbox.lockboxUsageReport:
                print("+++LOCKBOX", l.timestamp, lockbox.EventType.Name(l.eventType), l.packageName, l.className)
            for kv in lockbox.keyValuePair:
                if kv.key == "CONSENT_INFO":
                    print("CONSENT_INFO (decoded):")
                    print(decode_named("ConsentInformationWrapper", "consentinfo.proto", base64.b64decode(kv.value)))
        return(decoded)
    except (DecodeNamedError, ValueError) as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_AR(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/AR_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("ActivityRecognitionRequest", "activity_recognition.proto", bytes)
        #print(decoded)
        if Grep:
            try: 
                AR = activity_recognition_pb2.ActivityRecognitionRequest()
                AR.ParseFromString(bytes)
                # print interesting content in a way that's easy to grep out of log file
                # (the lists are repeated fields, so each is just looped over: fieldIsSet() of one is always
                # true, which hid the CHRE and transition lists behind activityDetectedList)
                for ar in AR.activityRecognitionEvent:
                    for a in ar.activityDetectedList:
                        for aa in a.activityDetected:
                            for aaa in aa.activity:
                                print("+++ACTIVITY_RECOGNITION", aa.timeMillis, aaa.activity, aaa.confidence)
                    for a in ar.activityDetectedCHREList:
                        for aa in a.activityDetected:
                            for aaa in aa.activity:
                                if aaa.HasField("activity"):
                                    print("+++ACTIVITY_RECOGNITION_CHRE", aa.chreAbsoluteTimeInMillis, aaa.activity, aaa.confidence)
                    for t in ar.activityTransitionEvent:
                        # a transition carries no time of its own: the request's
                        print("+++ACTIVITY_RECOGNITION_TRANSITION", AR.currentTimeMillis, t.newActivity1.activity, t.newActivity1.confidence)
            except Exception as e:
                print("***ERROR AR grep: ",e)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_tron(bytes, verbose=True, terse=False, debug=False):
    try:
        #f = open('/tmp/tron_bytes', 'wb')
        if debug:
            fname='/tmp/tron_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        #decoded = subprocess.check_output("protoc --decode=\"TronRequest\" -I='"+mypath+"' tron.proto  </tmp/tron_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        decoded = run_decoder_script("tron_decode", bytes)
        #print("TRON decoded="+decoded)
        return(decoded)
    except ScriptDecodeError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_netstats(bytes, verbose=True, terse=False, debug=False):
    try:
        if debug:
            fname='/tmp/netstats_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("NetstatsRequest", "netstats.proto", bytes)
        #print(decoded)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_scoobyevents(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/scoobyevents_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("ScoobyEventsRequest", "scoobyevents.proto", bytes)
        #print(decoded)
        grep=""
        if (decoded is not None) and Grep:
            grep="+++SCOOBY_EVENTS ";
            res = decoded.split('\n')
            try:
                found = False
                for s in res:
                    if re.search('phoneNumber', s):
                        grep=grep+s.replace(" ", "")
                        found=True
                if not found:
                    # try alt protobuf format (events in field 1, seen in some older measurements)
                    try:
                        decoded_alt = decode_named("AltScoobyEventsRequest", "scoobyevents.proto", bytes)
                    except DecodeNamedError:
                        decoded_alt = ""
                    res_alt = decoded_alt.split('\n')
                    for s in res_alt:
                        if re.search('phoneNumber', s):
                            grep=grep+s.replace(" ", "")
                            found=True
                    if found:
                        decoded = decoded_alt
                grep=grep+"\n"
            except Exception as e:
                print("***ERROR SCOOBY_EVENTS grep: ",e)
                return "Failed"
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_scoobymessage(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/scoobymessageevents_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("ScoobyEventsRequest", "scoobymessageevents.proto", bytes)
        #print(decoded)
        grep=""
        if (decoded is not None) and Grep:
            grep="+++SCOOBY_MESSAGE_LOG ";
            res = decoded.split('\n')
            try:
                for s in res:
                    if re.search('phoneNumber', s):
                        grep=grep+s.replace(" ", "")
                grep=grep+"\n"
            except Exception as e:
                print("***ERROR SCOOBY_MESSAGE_LOG grep: ",e)
                return "Failed"
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode(data):
    # prints what running this script on a file holding data prints
    #print(decode_pb(data))

    try:
        logbatch = logbatch_pb2.ClearcutLoggerEvents()
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
            elif inner.logSourceName == "ICING":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_icing_pb, verbose=True, debug=False))
            elif inner.logSourceName == "CLIENT_LOGGING_PROD":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_clientlogging_pb, verbose=True, debug=False))
            elif inner.logSourceName.endswith("_PRIMES"):  # ANDROID_MESSAGING_PRIMES, DIALER_ANDROID_PRIMES, GMM_PRIMES, ...
                print(try_decode_pb_array("logEntry", inner.logEntry, functools.partial(decode_primes_pb, source=inner.logSourceName), verbose=True, debug=False))
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
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_netstats, verbose=True, debug=False))
            elif inner.logSourceName == "SCOOBY_EVENTS":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_scoobyevents, verbose=True, debug=False))
            elif inner.logSourceName == "SCOOBY_MESSAGE_LOG":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_scoobymessage, verbose=True, debug=False))
            elif inner.logSourceName == "CHIME":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_chime_pb, verbose=True, debug=False))
            else:
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_pb, verbose=True, debug=False))
            print("}")
    except Exception as e:
        print("***ERROR: ",e)

if __name__ == "__main__":
    if len(sys.argv)>1:
        fname=sys.argv[1]
    else:
        fname='/tmp/batch_bytes'
    f = open(fname, 'rb')
    data = f.read()
    f.close()
    decode(data)
