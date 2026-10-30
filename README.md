# Partial Decoding of Google Play Services Binary Protobufs

For details of how to collect decrypted packet traces from an Android handset see https://github.com/doug-leith/cydia

To save a packet trace to a file using mitmdump use the -w option.  This binary file can then be parsed using the scripts described below.

## Quick start

Clone the repo and install into a venv using:

```shell
git clone https://github.com/doug-leith/android-protobuf-decoding.git
cd android-protobuf-decoding
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

To test the installation use:

```shell
mitmdump --flow-detail 0 -s decoding_helpers.py -nr example_firebase.mitm | more
```

The output should match that in file example_firebase.txt.  This contains Google/Firebase Analytic event logging by the Google Play store app recording it being opened following a factory reset.

## Google/Firebase Analytics

- app_measurement.proto3 is decoded protobuf definition for messages sent to https://www.app-measurement.com/a endpoint.
- app_measurement_decode.py is a python script to decode and print out a binary protobuf stored in file /tmp/appmeas_bytes.
- firebase_logbatch.proto is decoded protobuf definition for messages sent to legacy endpoint https://firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog

## Google Play Services Clearcut Logger
Clearcut logger sends messages to https://play.googleapis.com/log/batch endpoint.

- logbatch.proto3 is (partially) decoded protobuf definition for clearcut logger messages.  

Each message contains a sequence of log events, which may be from different log sources.  Each event is a protobuf with a header and a sequence of event entries.   The event entries are sent as a binary message that encodes a protobuf array (a sequence of size, protobuf pairs), which needs some extra work to decode.  The format of the individual protobufs in the array depends on the log source. 

- logbatch_decode.py is a python script for decoding these messages, including the protobuf array.  For the ANDROID_MESSAGING, ANDROID_DIALER, LATIN_IME, ICING, CLIENT_LOGGING_PROD, CHIME, *_PRIMES, AUTOFILL_WITH_GOOGLE, ON_DEVICE_ABUSE, AGSA_* (the Google app), LB_AS (Lockbox), WESTWORLD (aosp statsd service), WESTWORLD_COUNTERS, TRON (aosp metric logger), ACTIVITY_RECOGNITION log sources the individual events are decoded using the protobuf definitions below, otherwise the events are decoded as raw protobufs (so field names are unknown and format of each field might be guessed incorrectly).
- decoding_helpers.py are helper functions for decoding

### ANDROID_MESSAGING log source (Google Messages App)

- android_messaging.proto3 is (partially) decoded protobuf definition

### ANDROID_DIALER log source (Google Dialer App)

- android_dialer.proto3 is (partially) decoded protobuf definition

### LATIN_IME log source (Google GBoard App)

- gboard_named.proto is (partially) decoded protobuf definition

### ICING log source (Google Play Services on-device search)

- icing_named.proto is decoded protobuf definition

### CLIENT_LOGGING_PROD log source (warning and error log records uploaded by Google apps)

- client_logging_named.proto is decoded protobuf definition

### CHIME log source (push notification events logged by Google apps: delivered, shown, clicked, dismissed, with the app's notification channels and FCM token)

- chime_named.proto is decoded protobuf definition

### **PRIMES log sources (performance metrics from Google apps' Primes library: memory, timers, app startup, jank, network requests, crashes, battery; e.g. ANDROID_MESSAGING_PRIMES, DIALER_ANDROID_PRIMES)**

- primes_named.proto is decoded protobuf definition; primes_hashed_names.txt lists the names recovered for the MD5 hashes Primes sends in place of some event names and request paths

### AUTOFILL_WITH_GOOGLE log source (Google Play Services Autofill service: the foreground app and activity of every app that shows input fields, with the detected field types and form domain or URL, whether or not Autofill with Google is turned on)

- autofill_named.proto is decoded protobuf definition

### ON_DEVICE_ABUSE log source (Google Messages' on-device spam/scam classifier, Moirai: classification verdicts and actions, rule/model package downloads and their transparency-log check, with download/classification counters and the server's protection token; no message content)

- on_device_abuse_named.proto is decoded protobuf definition

### **AGSA_* log sources (the Google app: Search, Assistant, At a Glance, Discover: app flows with their named steps, visual elements shown and tapped, settings and permission snapshots, account state and the NID cookie; e.g. AGSA_APA, AGSA_PROACTIVE_ASSISTANT, AGSA_ASSISTANT, AGSA_GOOGLE_APP)**

- agsa_named.proto is decoded protobuf definition; agsa_flow_names.json names the flow types and steps the events send as numbers

### LB_AS log source (Google Play Services Lockbox component which logs app usage data)

- lockbox.proto is (partially) decoded protobuf definition

### WESTWORLD log source (Google Play Services Westworld component, sends AOSP statsd data)

- stats_log.proto is (partially) decoded protobuf definition.  hashes of strings are sent in log rather than text, plus a list of strings used.  SMHasher program calcs hash of a string and so can be used to construct a table mapping from the list of strings to hash values, see d ecode_westworld() in logbatch_decode.py

### WESTWORLD_COUNTERS log source (Westworld's counts of its own alarms, statsd fetches and uploads)

- westworld_counters_named.proto is decoded protobuf definition; westworld_counters_names.txt lists the counter names behind the MD5 hashes sent

### CONSENT_INFO (sent with WESTWORLD, LB_AS and other log sources' events)

- consentinfo.proto is decoded protobuf definition of the consent settings Google Play Services checked before uploading the event

### TRON log source (Google Play Services Tron component, sends AOSP metric logger data)

- tron_decode.py is a python script to decode and print out a binary protobuf stored in file /tmp/tron_bytes
- tron.proto is (partially) decoded protobuf definition, but its messy to decode since the interpretation of fields is variable (see tron_decode.py)

### ACTIVITY_RECOGNITION log source (Google Play Services AR component, uses sensors to logs whether handset user user is estimated to be walk, driving, running etc)

- activity_recognition.proto is (partially) decoded protobuf definition

### NETSTATS log source (Google Play Services log of network usage by apps and components)

- netstats.proto is (partially) decoded protobuf definition

## Google Play Services https://android.clients.google.com/checkin

- checkin.proto is (partially) decoded protobuf definition

## Google Play Services https://www.googleapis.com/experimentsandconfigs/v1/getExperimentsAndConfigs

- exptsandconfigs_request.proto and exptsandconfigs_response.proto

## Google Play Services https://www.google.com/loc/m/api

- LocRequest within locm.proto is (partially) decoded protobuf definition (note that request is in gRPC format)

## Google Play Services https://android-context-data.googleapis.com/google.internal.android.location.kollektomat.v1.KollektomatService/Offer

- kollektomat_named.proto is decoded protobuf definition of the request (an lbs.GLocRequest: Wi-Fi scans, sensor samples, GNSS status); KollektomatRequest within locm.proto is the older format (note that request is in gRPC format)

## Google Messages and Play Protect https://ondevicesafety-pa.googleapis.com/google.internal.abuse.ondevicesafety.v1alpha.ProgramBlobService/DownloadBlob

- ondevicesafety_named.proto is decoded protobuf definition of request and response (gRPC): the on-device spam/scam classifier's encrypted rule/model package download, sending client id, device tier, labels, counters, the device's Tink public key and a DroidGuard token (Messages) or Android Keystore key attestation (Play Protect)

## Google Play Services https://voilatile-pa.googleapis.com/google.internal.android.location.voilatile.v1.VoilaTileService/FindTiles

- voilatile_named.proto is decoded protobuf definition of the request (the Wi-Fi BSSIDs and cell towers the phone sees) and response (location tiles giving each known access point's position); s2cell.py converts their S2 cell ids to latitude/longitude

## Google Play Services and apps https://federatedcompute-pa.googleapis.com

- federated_learning_protos/federatedcompute/ are the protobuf definitions of the federated learning and analytics protocol (from the open-source federated compute client): eligibility checks, task assignments and aggregation uploads, with the population and task names
- federatedcompute_decode.py picks the request and response type for each URL

## Google app https://www.google.com/m/voice-search/up and /down

- voice_search_named.proto is decoded protobuf definition of the Google app's S3 protocol, which carries Assistant queries, Assistant settings and client sync: each spoken query as its on-device transcript together with the last 10 earlier queries, the foreground app, the installed apps, alarms and device state, and the Assistant's replies
- wallet_client_token_named.proto is decoded protobuf definition of the Google Play Services Wallet client token attached to each Assistant query (IMEI, phone number, serial number, Android ID, IMSI, network location, IP addresses)
- voice_search_decode.py splits the streams into messages and decodes the typed values inside them

## Google Play Services https://android.googleapis.com/auth/devicekey

- devicekeyrequest.proto is (partially) decoded protobuf definition for request and response

## Google Play Store https://play.googleapis.com/play/log and https://play-fe.googleapis.com/fdfe

- playstore_decode.py is a python script to decode requests and responses for https://play.googleapis.com/play/log, and print out a binary protobuf stored in file /tmp/playstore_bytes.
- playstore.proto is (partially) decoded protobuf definition, but note that it contains serialized protobufs and so extra work is needed to fully decode data (see playstore_decode.py)
- playstoreresponse_decode.py decodes the responses sent by https://play-fe.googleapis.com/fdfe

## Google Play Services https://deviceintegritytokens-pa.googleapis.com/v1/getAdEventToken

- GetAdEventTokenRequest and GetAdEventTokenResponse in attok.proto are the decoded protobuf definitions. About once a day Google Play Services sends its event attestation public key, the Google Advertising Id and a DroidGuard result, and gets back a Google-signed token holding the key, a timestamp and the Advertising Id. Every attok token (below) carries this signed token.

## Google Play Services https://deviceintegritytokens-pa.googleapis.com/v1/getPoIntegrityToken and PO tokens

- potoken.proto is the decoded protobuf definition of the request, the reply and the PO tokens made from it. About once a day Google Play Services sends a DroidGuard result and gets back an integrity token, encrypted to Google, with a lifetime. From it Google Play Services makes a PO token for each app that asks (e.g. YouTube, the Play store): the calling app's name, signing certificate hash and data, encrypted, plus part of the integrity token in clear, the same in every PO token until the next refresh.
- The Play store sends its PO token in field 26 of the x-ps-rh header of its apps/contentSync and replicateLibrary requests; decoding_helpers.py decodes it after the header.

## AOSP https://remoteprovisioning.googleapis.com/v1/:signCertificates

- decodes signed public keys response

## Advert URL parameters ms, dc_ms, attok and gref

adparams_decode.py decodes these parameters in request urls and in location response headers. A value that is encrypted, or in an unknown format, is reported as such.

- ms (www.google.com/aclk and other advert links) and dc_ms (ad.doubleclick.net): the AdShield signal added to advert clicks and impressions. Values from the Google Play store app are decrypted and checked against the MD5 they carry. They hold touch, timing, uptime and battery measurements; ms_signal.proto is the decoded protobuf definition, with names from the app code, including the AdShield helper classes the app ships encrypted. Values produced by DroidGuard, encrypted to Google's Tink public key, or made by a different encoder build are reported as encrypted.
- attok: the event attestation token the Google Mobile Ads SDK adds to in-app advert links. attok.proto is the decoded protobuf definition. A token sent signed but unencrypted is decoded, including the Google-signed integrity token inside it, which holds the Google Advertising Id. A Tink-encrypted token is reported with its key id.
- gref: the protobuf in the intent:// Play store link returned by www.google.com/aclk. gref.proto is the decoded protobuf definition; no app code parses gref, so its names come from the captured values. It contains the gclid of the same link and an id for the advertised app.

## DroidGuard results

Google apps send a DroidGuard result with many requests, e.g. checkin, auth/devicekey, adAttest, getAdEventToken, Play store fdfe/sync, federatedcompute and cryptauth SyncKeys. decoding_helpers.py finds them in any request body (protobuf, gRPC or form) and decodes them after the body.

- droidguard.proto is the decoded protobuf definition. The main payload is encrypted, but the outer fields are not, among them a per-app client_uuid that stays the same until factory reset.

## x-goog-spatula header

- spatula.proto is (partially) decoded protobuf definition

## authorization: Bearer header

- intermediatetoken.proto is (partially) decoded protobuf definition

## Mitmproxy python addon

- decoding_helpers.py is a python addon script for mitmproxy.  Example usage:

mitmdump --flow-detail 0 -s decoding_helpers.py -nr mitmdump-file

where mitmdump-file is a packet trace file recorded using e.g. mitmdump -w mitmdump-file

- decoding_helpers.py also includes helper functions for decoding which can be called directly (the same code doubles up as a mitmproxy addon and as a set of helper functions)
