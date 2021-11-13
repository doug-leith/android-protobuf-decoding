# Partial Decoding of Google Play Services Binary Protobufs

## Google/Firebase Analytics

- app_measurement.proto3 is decoded protobuf definition for messages sent to https://www.app-measurement.com/a endpoint.
- app_measurement_decode.py is a python script to decode and print out a binary protobuf stored in file /tmp/bytes.

## Google Play Services Clearcut Logger
Clearcut logger sends messages to https://play.googleapis.com/log/batch endpoint.

- logbatch.proto3 is (partially) decoded protobuf definition for clearcut logger messages.  

Each message contains a sequence of log events, which may be from different log sources.  Each event is a protobuf with a header and a sequence of event entries.   The event entries are sent as a binary message that encodes a protobuf array (a sequence of size, protobuf pairs), which needs some extra work to decode.  The format of the individual protobufs in the array depends on the log source. 

- logbatch_decode.py is a python script for decoding these messages, including the protobuf array.  For the ANDROID_MESSAGING and ANDROID_DIALER log sources the individual events are decoded using the protobuf definitions below, otherwise the events are decoded as raw protobufs (so field names are unknown and format of each field might be guessed incorrectly).
- decoding_helpers.py are helper functions for decoding

### ANDROID_MESSAGING log source (Google Messages App)

- android_messaging.proto3 is (partially) decoded protobuf definition

### ANDROID_DIALER log source (Google Dialer App)

- android_dialer.proto3 is (partially) decoded protobuf definition

## Google Play Services /checkin

- checkin.proto is (partially) decoded protobuf definition

## Mitmproxy python addon

- addon.py is a python addon script for mitmproxy.  Example usage:

mitmdump --flow-detail 0 -s addon.py -nr mitmdump-file

where mitmdump-file is a packet trace file recorded using e.g. mitmdump -w mitmdump-file

- decoding_helpers.py are helper functions for decoding
