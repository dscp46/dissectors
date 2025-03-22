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

Per D-Star specification, section 6.2:
> データフレームが “0xE7, 0x84, 0x76” のデータ列となり、かつ音声フレームが無音 パターン“0x9E, 0x8D,
0x32, 0x88, 0x26, 0x1A, 0x3F, 0x61, 0xE8”の場合にパケッ トロスとして扱うため使用できません。

Best way to ensure we don't trigger packet loss mechanisms would be to also escape `0xE7`, as recommended in said subsection, I'll file a PR on this.

## Message formatting

  * Once yDecoded, a D-Rats packet is organised as described below.
  * All fields, unless explicitely stated, are unsigned integers in the network order.
  * Strings are fixed-size, not null-terminated.
  * Presence of a body / payload is optional (FIXME: confirm this reading back d-rats' code)
  * The field sizes, in the following graph are given in **bits**, not **bytes** for readability.

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

## How to classify message payload

In the following graph:
  * `S` refers to the Session field value in the header
  * `T` refers to the Type field value in the header
  * `It` refers to the Inner Type (ASCII decimal value of the first byte of the body, once uncompressed, if applicable).

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
    Sn -->|T: 5| STgen((Stateful Sess))
    S0 -->|T: 5| STgen
    Sn -->|T: 7| Socket((Socket))
    S0 -->|T: 7| Socket
    Sn -->|T: 8| FileXfer((File Xfer))
    S0 -->|T: 8| FileXfer
    Sn -->|T: 9| FormXfer((Form Xfer))
    S0 -->|T: 9| FormXfer
```

## Dynamic session ID:

In control.py, derived from stateful

```python
T_PNG = 0
T_END = 1
T_ACK = 2
T_NEW = 3

T_NEW + base.T_GENERAL  : stateful.StatefulSession,
T_NEW + base.T_FILEXFER : file.FileTransferSession,
T_NEW + base.T_FORMXFER : form.FormTransferSession,
T_NEW + base.T_SOCKET   : sock.SocketSession,
```
In base:
```
T_STATELESS = 0
T_GENERAL = 1
T_UNUSED2 = 2 # Old non-pipelined FileTransfer
T_UNUSED3 = 3 # Old non-pipelined FormTransfer
T_SOCKET = 4
T_FILEXFER = 5
T_FORMXFER = 6
T_RPC = 7
```

Stateful session: 4
Pipelined File transfer: 8
Pipelined Form transfer: 9
Socket session: 7

## Stateful session management

```mermaid
sequenceDiagram
    note right of Alice: Set up session from Session 0
    Alice->>+Carol: Type: Form Xfer, My Sess: Na
    Carol->>-Alice: Type: ACK, Ur Sess: Na, My Sess: Nb

    note over Alice,Carol: Form Transfer Session<br/><br/>Alice -> Carol: Session Nb<br/>Carol -> Alice: Session Na

    note right of Alice: Tear down session from Session 0
    Alice->>Carol: Type: End (Ur Sess: Nb, in decimal form)
    Carol->>Alice: Type: End (Ur Sess: Na, in decimal form)
    Alice->>Carol: Type: End (My Sess: Na, in decimal form)
```

## Form Transfer
```mermaid
sequenceDiagram
    note over Alice,Carol: Set up session from Session 0

        note right of Alice: Push File
    Alice->>+Carol: Type: Form Xfer, My Sess: Na
    Carol->>-Alice: Type: ACK, Ur Sess: Na, My Sess: Nb
    Alice-->>Carol: Type: Form Xfer, My Sess: Na

    note left of Carol: Acknowledge
    Alice->>Carol: Type: Data (Direction, ??, Filename, Seq=0)
    Alice->>Carol: Type: Request ACK (Seq=0, Payload=[Data's Seq])
    Carol-->>Alice: Type: End (Seq=0, Payload=[Req ACK's Seq])

    note left of Carol: Acknowledge
    Carol->>Alice: Type: Data ("OK", Filename, Seq=0)
    Carol->>Alice: Type: Request ACK (Seq=0, Payload=[Data's Seq])
    Alice-->>Carol: Type: End (Seq=0, Payload=[Req ACK's Seq])

    note right of Alice: Data transfer
    Alice-->>+Carol: Type: Data (Chunk 0, Filename, Seq=1)
    Alice-->>+Carol: Type: Data (Chunk 1, Filename, Seq=2)
    Alice-->>+Carol: Type: Data (Chunk n, Filename, Seq=n)
    Carol->>-Alice: Type: Request ACK (Seq=0, Payload=[Data's Seq])
    Alice-->>Carol: Type: End (Seq=0, Payload=[Req ACK's Seq])

    note over Alice,Carol: Tear down session from Session 0
```
