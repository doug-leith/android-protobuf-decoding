# Partial Decoding of Google Play Services Binary Protobufs

For details of how to collect decrypted packet traces from an Android handset see https://github.com/doug-leith/cydia

To save a packet trace to a file using mitmdump use the -w option.  This binary file can then be parsed using the scripts described below.

## Quick start
We include an example mitmproxy trace file containing a connection to https://play.googleapis.com/log/batch made by the Google Play Services Clearbut logger in file example_messaging.mitm.   To decode this file use:

mitmdump --flow-detail 0 -s decoding_helpers.py -nr example_messaging.mitm | more

The output should match that in file example_messaging.txt.  This contains telemetry sent by the Google Messages app via the ANDROID_MESSAGING and CARRIER_SERVICES Clearcut logger log sources.

We also include a second example of a connection to https://app-measurement.com/a made by Google/Firebase Analytics in file example_firebase.mitm.  To decode this file use:

mitmdump --flow-detail 0 -s decoding_helpers.py -nr example_firebase.mitm | more

The output should match that in file example_firebase.txt.  This contains event logging by the Google Dialer app recording the fact that outgoing calls have been placed.

## Google/Firebase Analytics

- app_measurement.proto3 is decoded protobuf definition for messages sent to https://www.app-measurement.com/a endpoint.
- app_measurement_decode.py is a python script to decode and print out a binary protobuf stored in file /tmp/appmeas_bytes.
- firebase_logbatch.proto is decoded protobuf definition for messages sent to legacy endpoint https://firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog

## Google Play Services Clearcut Logger
Clearcut logger sends messages to https://play.googleapis.com/log/batch endpoint.

- logbatch.proto3 is (partially) decoded protobuf definition for clearcut logger messages.  

Each message contains a sequence of log events, which may be from different log sources.  Each event is a protobuf with a header and a sequence of event entries.   The event entries are sent as a binary message that encodes a protobuf array (a sequence of size, protobuf pairs), which needs some extra work to decode.  The format of the individual protobufs in the array depends on the log source. 

- logbatch_decode.py is a python script for decoding these messages, including the protobuf array.  For the ANDROID_MESSAGING, ANDROID_DIALER, LATIN_IME, LB_AS (Lockbox), WESTWORLD (aosp statsd service), TRON (aosp metric logger), ACTIVITY_RECOGNITION log sources the individual events are decoded using the protobuf definitions below, otherwise the events are decoded as raw protobufs (so field names are unknown and format of each field might be guessed incorrectly).
- decoding_helpers.py are helper functions for decoding

### ANDROID_MESSAGING log source (Google Messages App)

- android_messaging.proto3 is (partially) decoded protobuf definition

### ANDROID_DIALER log source (Google Dialer App)

- android_dialer.proto3 is (partially) decoded protobuf definition

### LATIN_IME log source (Google GBoard App)

- gboard.proto3 is (partially) decoded protobuf definition

### LB_AS log source (Google Play Services Lockbox component which logs app usage data)

- lockbox.proto is (partially) decoded protobuf definition

### WESTWORLD log source (Google Play Services Westworld component, sends AOSP statsd data)

- stats_log.proto is (partially) decoded protobuf definition.  hashes of strings are sent in log rather than text, plus a list of strings used.  SMHasher program calcs hash of a string and so can be used to construct a table mapping from the list of strings to hash values, see d ecode_westworld() in logbatch_decode.py

### TRON log source (Google Play Services Tron component, sends AOSP metric logger data)

- tron_decode.py is a python script to decode and print out a binary protobuf stored in file /tmp/tron_bytes
- tron.proto is (partially) decoded protobuf definition, but its messy to decode since the interpretation of fields is variable (see tron_decode.py)

### ACTIVITY_RECOGNITION log source (Google Play Services AR component, uses sensors to logs whether handset user user is estimated to be walk, driving, running etc)

- activity_recognition.proto is (partially) decoded protobuf definition

## Google Play Services https://android.clients.google.com/checkin

- checkin.proto is (partially) decoded protobuf definition

## Google Play Services /experimentsandconfigs

- exptsandconfigs_request.proto and exptsandconfigs_response.proto

## Google Play Services https://www.google.com/loc/m/api

- LocRequest within locm.proto is (partially) decoded protobuf definition (note that request is in gRPC format)

## Google Play Services https://android-context-data.googleapis.com/google.internal.android.location.kollektomat.v1.KollektomatService/Offer

- KollektomatRequest within locm.proto is (partially) decoded protobuf definition (note that request is in gRPC format)

## Google Play Store

- playstore_decode.py is a python script to decode and print out a binary protobuf stored in file /tmp/playstore_bytes.
- playstore.proto is (partially) decoded protobuf definition, but note that it contains serialized protobufs and so extra work is needed to fully decode data (see playstore_decode.py)

## Mitmproxy python addon

- decoding_helpers.py is a python addon script for mitmproxy.  Example usage:

mitmdump --flow-detail 0 -s decoding_helpers.py -nr mitmdump-file

where mitmdump-file is a packet trace file recorded using e.g. mitmdump -w mitmdump-file

- decoding_helpers.py also includes helper functions for decoding which can be called directly (the same code doubles up as a mitmproxy addon and as a set of helper functions)
