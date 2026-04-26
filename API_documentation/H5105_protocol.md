# Govee H5105 Thermo-Hygrometer BLE Protocol

Reverse-engineered from packet dumps of the Govee Home iOS app communicating
with a GVH5105 device, cross-referenced with the H5075 protocol.

---

## 1. BLE Services and Characteristics

The H5105 exposes three custom 128-bit UUID services beyond the standard GAP/GATT.
The device also has standard GAP (0x0001--0x000d) and GATT (0x000e-only) services.

### Service 1 -- INTELLI_ROCKS (primary data service)

| Handle range | Service UUID |
|---|---|
| 0x000e -- 0x001a | `494e5445-4c4c-495f-524f-434b535f4857` ("INTELLI_ROCKS_HW") |

| Name | Value Handle | UUID | Properties |
|---|---|---|---|
| DEVICE | 0x0010 | `494e5445-4c4c-495f-524f-434b535f2011` | Read, Write, Write-no-resp, Notify (0x1e) |
| COMMAND | 0x0014 | `494e5445-4c4c-495f-524f-434b535f2012` | Read, Write, Write-no-resp, Notify (0x1e) |
| DATA | 0x0018 | `494e5445-4c4c-495f-524f-434b535f2013` | Read, Notify (0x12) |

This is the **same** INTELLI_ROCKS service used by the H5075, H5074, H5179, etc.
All protocol commands and data transfers go through these characteristics.

### Service 2 -- Govee App Authentication Service

| Handle range | Service UUID |
|---|---|
| 0x001b -- 0x0027 | `00010203-0405-0607-0809-0a0b0c0d1910` |

| Name | Value Handle | UUID | Properties |
|---|---|---|---|
| AUTH_NOTIFY | 0x001d | `00010203-0405-0607-0809-0a0b0c0d2b10` | Read, Notify (0x12) |
| AUTH_WRITE | 0x0021 | `00010203-0405-0607-0809-0a0b0c0d2b11` | Read, Write, Write-no-resp, Notify (0x1e) |
| AUTH_CONFIG | 0x0025 | `00010203-0405-0607-0809-0a0b0c0d2b12` | Read, Write (0x0e) |

This service is **required** for all GATT communication. The H5105 will
disconnect immediately if it receives unencrypted data on the INTELLI_ROCKS
service without first completing the authentication handshake.

When the Govee app connects, it:
1. Reads AUTH_CONFIG (0x0025) -- returns `02 01 00 00 02 01 00 00 ...`
2. Subscribes to notifications on AUTH_NOTIFY (0x001d) and AUTH_WRITE (0x0021)
3. Writes TX1 (20-byte auth challenge) to AUTH_WRITE (0x0021)
4. Receives RX1 (20-byte response) on AUTH_NOTIFY (0x001d) → session key derived here
5. Writes TX2 (20-byte auth confirmation) to AUTH_WRITE (0x0021)
6. Receives RX2 (20-byte response) on AUTH_NOTIFY (0x001d)
7. All subsequent INTELLI_ROCKS traffic is **AES-128-ECB + RC4 encrypted**

The auth packets are constructed using AES-ECB-DECRYPT with the PSK
(`b"MakingLifeSmarte"`), not a simple XOR or token scheme. See §7 for the
complete key derivation and encryption specification.

### Service 3 -- Telink OTA Service

| Handle range | Service UUID |
|---|---|
| 0x0028 -- 0x0032 | `02f00000-0000-0000-0000-00000000fe00` |

| Name | Value Handle | UUID | Properties |
|---|---|---|---|
| (read) | 0x002a | `02f00000-0000-0000-0000-00000000ff03` | Read (0x02) |
| (notify) | 0x002c | `02f00000-0000-0000-0000-00000000ff02` | Read, Notify (0x12) |
| (read) | 0x0030 | `02f00000-0000-0000-0000-00000000ff00` | Read (0x02) |
| (write+notify) | 0x0032 | `02f00000-0000-0000-0000-00000000ff01` | Write-no-resp, Notify (0x0c) |

The CCCD for handle 0x002c (notify, UUID ff02) is at handle **0x002d**. The iOS
app subscribes to it during connection setup, which appears to be required by
the device state machine before it will respond to the auth write. Contains
characteristics for firmware update (Telink OTA). Not used for data access.

---

## 2. Packet Format

All commands and responses are exactly **20 bytes**:

```
[byte 0..1]  Command identifier (2 bytes)
[byte 2..18] Payload (17 bytes, zero-padded)
[byte 19]    XOR checksum of bytes 0..18
```

The checksum is calculated as: `byte[0] XOR byte[1] XOR ... XOR byte[18]`.

---

## 3. DEVICE Characteristic Commands (UUID 2011)

Written to and received from the DEVICE characteristic (handle 0x0010).

### 3.1 Request Hardware Version

```
Send:  aa 0d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a7
Reply: aa 0d [7 bytes ASCII version] 00 ... [checksum]
```

Example response: `aa 0d 33 2e 30 31 2e 30 30 ...` = hardware "3.01.00"

### 3.2 Request Firmware Version

```
Send:  aa 0e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a4
Reply: aa 0e [7 bytes ASCII version] 00 ... [checksum]
```

Example response: `aa 0e 31 2e 30 30 2e 31 37 ...` = firmware "1.00.17"

### 3.3 Request Battery Level

```
Send:  aa 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a2
Reply: aa 08 [battery%] 00 ... [checksum]
```

### 3.4 Request Current Measurement (aa 01)

```
Send:  aa 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ab
Reply: aa 01 [temp_hi] [temp_lo] [hum_hi] [hum_lo] [battery] 00 ... [checksum]
```

Temperature and humidity are big-endian signed 16-bit values divided by 100.

### 3.5 Other Device Queries

| Command | Description |
|---|---|
| `aa 03` | Request humidity alarm config |
| `aa 04` | Request temperature alarm config |
| `aa 06` | Request humidity offset |
| `aa 07` | Request temperature offset |
| `aa 0c` | Request MAC address and serial |
| `aa 0f` | Request MAC address |

---

## 4. Historical Data Download (COMMAND + DATA characteristics)

### 4.1 Initiating Download

Write to COMMAND characteristic (UUID 2012, handle 0x0014):

```
33 01 [start_hi] [start_lo] [end_hi] [end_lo] 00 ... [checksum]
```

- `start`: number of minutes back from now to start (big-endian uint16)
- `end`: typically `0x0001` (most recent minute)
- Example: to download last 24 hours: start = 1440 (0x05A0), end = 1 (0x0001)
- To download all available data: start = 0xFFFF, end = 0x0001

The device responds on COMMAND with `33 01 ...` confirming the download started.

### 4.2 Receiving Data

Data arrives as notifications on the DATA characteristic (UUID 2013, handle 0x0018):

```
[offset_hi] [offset_lo] [temp+hum 3 bytes] [temp+hum 3 bytes] ... [temp+hum 3 bytes]
```

Each notification contains:
- **Bytes 0--1**: Offset (big-endian uint16) -- minutes from download start, counting down
- **Bytes 2--19**: Up to 6 measurement records, each 3 bytes

### 4.3 Measurement Record Format (3 bytes)

Each 3-byte record encodes both temperature and humidity:

```python
raw = (byte[0] << 16) | (byte[1] << 8) | byte[2]  # 24-bit big-endian

is_negative = bool(raw & 0x800000)
raw = raw & 0x7FFFFF

temperature_C = (raw // 1000) / 10.0
if is_negative:
    temperature_C = -temperature_C

humidity_pct = (raw % 1000) / 10.0
```

A record of `ff ff ff` indicates no data (padding / gap).

### 4.4 Keep-Alive During Download

Every ~75 notifications, the client must send a keep-alive to COMMAND:

```
aa 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ab
```

Without this, the device may stop sending data.

### 4.5 Download Complete

When the download finishes, the device sends a notification on COMMAND:

```
ee 01 [msg_count_hi] [msg_count_lo] 00 ... [checksum]
```

`msg_count` is the total number of data notifications sent. Verify this matches
the number received to confirm a complete download.

### 4.6 Detecting End of Data

When the offset in a DATA notification reaches 6 or less, the final data has
been received and the download is complete.

---

## 5. BLE Advertisement Format

The H5105 broadcasts temperature/humidity data in BLE advertisements
under manufacturer data key `0x0001`:

```
[temp_lo] [temp_hi] [hum_b0] [hum_b1] [hum_b2] [battery]
```

- **Bytes 0--1**: Little-endian int16, temperature x 10 (e.g. 0x0101 = 257 = 25.7 C)
- **Bytes 2--4**: 3-byte big-endian packed value: `(raw % 1000) / 10.0` = humidity %
- **Byte 5**: Battery level in %

Some H5105 devices also advertise under key `0xec88` (H5075-compatible format).

---

## 6. Connection Sequence Summary

Authentication is **required** before any INTELLI_ROCKS traffic. The full
sequence observed from the Govee Home app:

1. **Connect** to device via BLE
2. **Discover services**
3. **Subscribe CCCDs** — in this order, all using Write Request (expects Write Response):
   - INTELLI_ROCKS DEVICE handle 0x0011 (CCCD for 0x0010)
   - INTELLI_ROCKS COMMAND handle 0x0015 (CCCD for 0x0014)
   - INTELLI_ROCKS DATA handle 0x0019 (CCCD for 0x0018)
   - AUTH_NOTIFY handle 0x001e (CCCD for 0x001d)
   - Telink ff02 handle 0x002d (CCCD for 0x002c)
4. **Auth handshake** (Auth service, handles 0x001d / 0x0021 / 0x0025):
   - Read AUTH_CONFIG (0x0025) — ignore response
   - Write TX1 to AUTH_WRITE (0x0021) using **Write Command** (no response, opcode 0x52)
   - Wait for RX1 notification on AUTH_NOTIFY → derive session key (see §7.4)
   - Write TX2 to AUTH_WRITE (0x0021) using Write Command
   - Wait for RX2 notification on AUTH_NOTIFY (optional)
5. **Enable notifications** on DEVICE (2011), COMMAND (2012), and DATA (2013)
5. **Init command**: write `33 10 04 f3 c3 01 00 ... [checksum]` (encrypted) to COMMAND
6. **Query device info** (all packets AES-encrypted with session key):
   - Write `aa 0e` to DEVICE -> firmware version
   - Write `aa 0d` to DEVICE -> hardware version
   - Write `aa 07` to DEVICE -> temperature offset
   - Write `aa 06` to DEVICE -> humidity offset
   - Write `aa 04` to DEVICE -> temperature alarm config
   - Write `aa 03` to DEVICE -> humidity alarm config
   - Write `aa 08` to DEVICE -> battery level
7. **Download historical data**:
   - Write `33 01 [start] [end]` (encrypted) to COMMAND
   - Receive encrypted data notifications on DATA, decrypt each
   - Send `aa 01` keep-alive to COMMAND every ~75 notifications
   - Wait for `ee 01` on COMMAND or offset <= 6 in DATA
8. **Disconnect**

---

## 7. Encryption

### 7.1 Overview

Unlike the H5075 which uses plaintext GATT communication, the H5105 encrypts
all INTELLI_ROCKS traffic. Each 20-byte GATT packet is encrypted as:

- **Bytes 0-15**: AES-128-ECB **encrypt** with the session key
- **Bytes 16-19**: RC4 keystream XOR with the session key (4 partial bytes)

RC4 is re-initialized from the session key on every packet (fresh S-box each
call), so there is no RC4 state carried between packets.

The encryption is fully deterministic within a session: the same plaintext
always produces the same ciphertext.

### 7.2 Encryption and Decryption

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 with fresh S-box on every call."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) & 0xff])
    return bytes(result)

def encrypt_packet(plaintext: bytes, session_key: bytes) -> bytes:
    """Encrypt a 20-byte plaintext packet."""
    cipher = Cipher(algorithms.AES(session_key), modes.ECB())
    encrypted = cipher.encryptor().update(plaintext[0:16])
    return encrypted + rc4(session_key, plaintext[16:20])

def decrypt_packet(ciphertext: bytes, session_key: bytes) -> bytes:
    """Decrypt a 20-byte ciphertext packet."""
    cipher = Cipher(algorithms.AES(session_key), modes.ECB())
    decrypted = cipher.decryptor().update(ciphertext[0:16])
    return decrypted + rc4(session_key, ciphertext[16:20])
```

### 7.3 Pre-Shared Key (PSK)

The Govee Home app contains a hardcoded 16-byte PSK, extracted from
`resources.arsc` in the APK (`classes13.dex`, package `com.govee.encryp.ble`):

```python
PSK = b"MakingLifeSmarte"  # 16 bytes
```

This PSK is used only during the auth handshake to derive the per-session key.

### 7.4 Session Key Derivation

The session key is derived from the first auth notification (RX1) received
from the device during the handshake:

```python
def derive_session_key(auth_rx1: bytes) -> bytes:
    """Derive the 16-byte AES session key from the 20-byte RX1 auth response."""
    # Decrypt RX1 using PSK: AES-ECB-DECRYPT for bytes 0-15, RC4 for bytes 16-19
    decrypted = (
        Cipher(algorithms.AES(PSK), modes.ECB()).decryptor().update(auth_rx1[0:16])
        + rc4(PSK, auth_rx1[16:20])
    )
    # Verify magic header: e7 01
    assert decrypted[0] == 0xe7 and decrypted[1] == 0x01
    # Session key is bytes 2-17
    return decrypted[2:18]
```

This was reverse-engineered from `Controller4Aes$Companion.g()` in the APK DEX.
The function `Safe$Companion.b(originBytes, key)` performs AES-ECB-DECRYPT for
full 16-byte blocks and RC4 for any partial remainder.

### 7.5 Auth Handshake Details

The app performs the auth handshake as follows:

1. **TX1** (write to AUTH_WRITE): `Safe$Companion.b(PSK, [0xe7, 0x01, <14 random bytes>])` + RC4 tail (bytes 16-18) + BCC checksum (byte 19)
2. **RX1** (notify on AUTH_NOTIFY): device's encrypted challenge response — used to derive session key
3. **TX2** (write to AUTH_WRITE): `Safe$Companion.b(PSK, [0xe7, 0x02, <derived bytes>])` + RC4 tail + BCC
4. **RX2** (notify on AUTH_NOTIFY): device confirmation

Note: On the wire, TX1 and TX2 are `AES-ECB-ENCRYPT(PSK, plaintext[0:16]) + RC4(PSK, plaintext[16:20])`.
The APK source uses `Safe$Companion.b()` (AES-ECB-DECRYPT direction), which appears
inverted, but the net result is equivalent to `safe_encrypt` as defined in §7.2.
The nonce in bytes 2-18 is generated randomly by the client each session; the device
does not validate it, only uses it to derive the shared session key.

---

## 8. Notes

- The H5105 stores approximately 20 days of data at 1-minute intervals.
- **Authentication and encryption are required** for GATT access. The device
  disconnects immediately if it receives unencrypted writes on INTELLI_ROCKS.
- BLE advertisements are NOT encrypted and can be read passively.
- Write operations should use `write_without_response` (ATT Write Command,
  opcode 0x52) for best compatibility.
- The device advertises as `GVH5105_XXXX` where XXXX is the last 4 hex
  digits of the MAC address.
- MAC addresses use prefixes: `C3:30:38:`, `A4:C1:38:`, `1C:9F:24:`,
  `D3:30:38:`.

---

## 9. Differences from H5075

| Feature | H5075 | H5105 |
|---|---|---|
| INTELLI_ROCKS service | Same UUIDs | Same UUIDs |
| Auth service (`00010203...`) | Not present | Present (**required**) |
| GATT encryption | None (plaintext) | AES-128-ECB |
| OTA service | Not present | Present |
| Advertisement key | `0xec88` | `0x0001` (also `0xec88` on some firmware) |
| Advertisement temp format | 3-byte packed | Little-endian int16 x 10 |
| Historical data format | 3-byte packed records | Same 3-byte packed records |
| GATT data download | `33 01` on UUID 2012 | Same `33 01` on UUID 2012 |

Sources:
- Packet dumps from Govee Home iOS app
- [GoveeBTTempLogger](https://github.com/wcbonner/GoveeBTTempLogger) by wcbonner
- [Govee-Reverse-Engineering](https://github.com/egold555/Govee-Reverse-Engineering) by egold555
- [Theengs Decoder - H5105](https://decoder.theengs.io/devices/H5105.html)
- [govee-h5075-thermo-hygrometer](https://github.com/Heckie75/govee-h5075-thermo-hygrometer)

