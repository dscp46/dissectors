# D-Rats Data Transport version 2

> [!WARNING]
> This document IS NOT a specification, rather a scratchbook which details how messages are encoded.

## Message yEncoding
Prior to being sent, the messages are yEncoded with the following parameters:
  * Begin marker: `[SOB]`
  * End marker: `[SOB]`
  * Escape character: `=` (`0x3D`)
  * Forbidden characters: `0x00`, `0x11`, `0x13`, `0x1A`, `0xFD`, `0xFE`, `0xFF`
  * Offset: 64

## Message formatting

All fields, unless explicitely stated, are unsigned integers in the network order.

```mermaid
---
title: "DDT2 Message"
---
packet-beta
  0-7: "Magic"
  8-23: "Sequence"
  24-31: "Session"
  32-39: "Type"
  40-55: "Checksum"
  56-71: "Length"
  72-135: "Source Callsign (string)"
  136-199: "Destination Callsign (string)"
  200-223: "Body / Payload (variable length)"
```

The `Magic` field holds either of the following value:
  * `0x22` if the body / payload is not compressed.
  * `0xDD` if the body / payload is compressed using the DEFLATE algorithm.

The `Checksum` is computed using the CRC16-CCITT algorithm on the full message, with the checksum bytes set to `0x0000`. 

## How to classify packets

In the following graph:
  * `S` refers to the Session field value in the header
  * `T` refers to the Type field value in the header
  * `It` refers to the Inner Type (first byte of the body, once uncompressed, if applicable).

```mermaid
flowchart TD
    Root -->|S: 1| S1((Chat))

    S1 -->|T: 0| S1dfl((Default))
    S1dfl -->|^$GPRMC| GFix((GPS Fix))
    S1dfl -->|^$GPGGA| GFix((GPS Fix))
    S1dfl -->|^$$CRC| AFix((APRS Fix))
    S1dfl -->|dfl| Chat((Chat))

    S1 -->|T: 1| PingReq((Ping Req))
    S1 -->|T: 2| PingRsp((Ping Rsp))
    S1 -->|T: 3| EchoReq((Echo Req))
    S1 -->|T: 4| EchoRsp((Echo Rsp))

    S1 -->|T: 5| Status((Status))
    Status -->|It: 0| SUnk((Unknown))
    Status -->|It: 1| SOn((Online))
    Status -->|It: 2| SUnAtt((Unattended))
    Status -->|It: 9| SOff((Offline))

    Root -->|S: 2| S2((RPC))
    S2 -->|T: 0| RPCr((RPC Req))
    S2 -->|T: 1| RPCa((RPC Ack))

    Root -->|S: n| Sn((Dynamic))
    Root((Session)) -->|S: 0| S0((0 - Dyn))
    S0 -->|T: 254| Wu((Warmup))
    Sn -->|T: 0| TSyn((SYN))
    S0 -->|T: 0| TSyn
    Sn -->|T: 1| TAck((ACK))
    S0 -->|T: 1| TAck
    Sn -->|T: 2| TNak((NAK))
    S0 -->|T: 2| TNak
    Sn -->|T: 3| TDat((Data))
    S0 -->|T: 3| TDat
    Sn -->|T: 4| TReqAck((ReqAck))
    S0 -->|T: 4| TReqAck
```

