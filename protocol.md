# The ADB Protocol

The ADB "interface" canonically [consists of 3 components](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release#three-components-of-adb-pipeline):
- the device, is typically an Android device,
- the server, also called the host, is the background process that runs on your computer that you can start and stop with `adb start-server` and `adb kill-server` respectively, and
- the client, AKA the CLI.

This setup is rather convenient for multiplexing and aggregating operations many instances from many simultaneous tasks. For example running logcat while doing anything else. This is because USB communications require exclusive access. However, there are many new use-cases that have arisen for ADB that do not require long-lived multiplexed streams, not to mention ADB-over-WiFi, which does not carry the same single-stream constraint.

This purpose of this document is to clearly describe the process to communicate with an android device with lots of links, as well as to point out inconsistencies or inaccuracies with previously available documentation.

# Definitions

## Packet Header

The packet header is a 24-byte message that consists of 6 32-bit words which are sent across the wire in little-endian format.

This is a snippet of the type declaration from [the AOSP implementation](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/types.h#123):

```c
struct amessage {
    uint32_t command;     /* command identifier constant      */
    uint32_t arg0;        /* first argument                   */
    uint32_t arg1;        /* second argument                  */
    uint32_t data_length; /* length of payload (0 is allowed) */
    uint32_t data_check;  /* checksum of data payload         */
    uint32_t magic;       /* command ^ 0xffffffff             */
};
```

### Differences from previously available documentation

The packet structure [as documented in the AOSP repository](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/protocol.txt#31) contains an important mistake that is misleading at best:

```c
struct message {
    unsigned command;       /* command identifier constant (A_CNXN, ...) */
    unsigned arg0;          /* first argument                            */
    unsigned arg1;          /* second argument                           */
    unsigned data_length;   /* length of payload (0 is allowed)          */
    unsigned data_crc32;    /* crc32 of data payload                     */
    unsigned magic;         /* command ^ 0xffffffff                      */
};
```

The name and comment of the `data_crc32` field suggest that the value should be calculated using the [crc32 algorithm](https://en.wikipedia.org/wiki/Cyclic_redundancy_check). However, it is in fact just a sum of all the bytes in the payload as implemented [here](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/adb.cpp#107) and called [here](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/transport.cpp#561).

## Commands

There are 8 seemingly random values that are recognized packet commands.

```c
#define A_SYNC 0x434e5953
#define A_CNXN 0x4e584e43
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257
#define A_AUTH 0x48545541
#define A_STLS 0x534C5453
```

### A_SYNC

Despite being first on the list, the AOSP project claims that this packet is ["obsolete, no longer used"](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/protocol.txt#195). Scanning through the AOSP implementation source code, there are indeed no references [except for debugging](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/adb.cpp#203).

### A_CNXN

This packet uses 2 arg values. `arg0` is the version number of the protocol to use and `arg1` is the max size of payload that can be accepted. It is the first and last packet that is sent as part of the handshake process. The payload of this packet is the system identification string, it is also called the banner in the AOSP implementation. The payload may not be more than 4096 bytes long in the case that the device is operating with an older version of the protocol in which that is the limit.

### A_OPEN

This packet only uses 1 arg value. `arg0` is a socket id from the sender. The payload is [a service string](#services) that the device will connect the socket to.

### A_OKAY

This packet uses 2 arg values. `arg0` is the sender's socket id and `arg1` is the reciever's socket id. This packet does not contain a payload.

### A_CLSE

This packet uses 2 arg values. `arg0` is the sender's socket id and `arg1` is the reciever's socket id. This packet does not contain a payload.

### A_WRTE

This packet uses 2 arg values. `arg0` is the sender's socket id and `arg1` is the reciever's socket id. The payload is the raw data from the socket. The data must be <= max size from the `A_CNXN` packet.

### A_AUTH

This packet only uses 1 arg value. `arg0` determines the variant of the packet of which there are 3:

```c
/* AUTH packets first argument */
/* Request */
#define ADB_AUTH_TOKEN         1
/* Response */
#define ADB_AUTH_SIGNATURE     2
#define ADB_AUTH_RSAPUBLICKEY  3
```

#### ADB_AUTH_TOKEN

This variant is only sent from the device to the host. It is also known as the "auth request". It contains a payload of random bytes that is the challenge for the host.

#### ADB_AUTH_SIGNATURE

This variant is only sent from the host to the device. It is used to send the challenge signature to the device for verification. The signature must be the pkcs1 encoded sha1 signature of the challenge.

#### ADB_AUTH_RSAPUBLICKEY

This variant is only sent from the host to the device. It is used to send a public key to the device to register. The public key must be encoded in the ["Android RSA public key binary format"](#public-key-format) and then further encoded into base64.

The AOSP host implementation seems to add the system login name + hostname like an email address, but it is unused and is safe to omit.

### A_STLS

This packet only uses 1 arg value. `arg0` is the version of the stls protocol to use.

## Services

Services are types of requests that can be made to the device when opening a new socket.

Here is an incomplete list of services that were found scattered through the adb code base. See [SERVICES.TXT](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/SERVICES.TXT) for more information.

from daemon_service_to_socket
- jdwp
- track-jdwp
- track-app
- sink:{byte_count}
- source:{byte_count}

from daemon_service_to_fd
- abb:
- abb_exec:
- framebuffer:
- remount:
- reboot:
- root:
- unroot:
- backup
- restore:
- disable-verity:
- enable-verity:
- tcpip:
- usb:

from service_to_fd -> is_socket_spec
- tcp:
- acceptfd:
- vsock:

# The Handshake (non-TLS)

1. The host sends a `A_CNXN` packet.

2. If authentication is not required or already completed, the device sends a `A_CNXN` packet and the handshake is complete.

3. Otherwise, the device sends a `A_AUTH` packet with `arg0` set to `ADB_AUTH_TOKEN` and a challenge string for the host to sign with their private key.

4. The host sends a `A_AUTH` packet with `arg0` set to `ADB_AUTH_SIGNATURE` and the signature.

5. If the signature is successfully verified, the device sends a `A_CNXN` packet and the handshake is complete.

6. Otherwise, return to step 3 and repeat for each private key that the host holds. If all of the host's keys are rejected, the host sends a `A_AUTH` packet with `arg0` set to `ADB_AUTH_RSAPUBLICKEY` and a public key to request the device to register.

7. If the public key is accepted and registered, typically by prompting the user, the device sends a `A_CNXN` packet and the handshake is complete.

8. Otherwise, the device does not respond and the host must send another public key or give up.

# The Handshake (TLS)

NOTE: This section needs more research.

1. The host sends a `A_CNXN` packet.

2. The device sends a `A_STLS` packet.

3. The host sends a `A_STLS` packet.

4. The host starts a standard TLS handshake with the host set to the hex encoded form of the SHA256 hash of the public key, this is also called the fingerprint.

5. If the fingerprint matches one of the registered keys, the device sends an encrypted `A_CNXN` packet and the handshake if complete.

6. Otherwise, the device terminates the connection. Start from step 1 with another key.

# Public Key Format

Public Keys sent to the device are encoded in a custom RSA public key binary format. It only supports 2048-bit RSA. However strange this is, it seems rather restrictive but straight forward. The encoding and decoding code can be found in the AOSP [system/core repository](https://android.googlesource.com/platform/system/core/+/refs/heads/android14-release/libcrypto_utils/android_pubkey.cpp).
