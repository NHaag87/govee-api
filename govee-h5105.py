#!/usr/bin/python3
# Govee H5105 thermometer/hygrometer support
# Adapted from govee-h5075.py; H5105 protocol reverse-engineered from BLE advertisements.
#
# H5105 advertisement format (manufacturer key 0x0001):
#   Bytes 0-1: little-endian int16, temperature * 10 (e.g. 0x0101 = 257 = 25.7 C)
#   Bytes 2-4: 3-byte big-endian unsigned, packed as (raw % 1000) / 10 = humidity %
#              e.g. 0x039fe8 = 237544 -> 54.4%
#   Byte 5:    battery level in %
#
# Hardware/firmware versions are readable via GATT (UUID_DEVICE aa0d/aa0e), but the
# All aa xx commands (alarms, offsets, battery, history) require an encrypted BLE
# auth handshake using PSK "MakingLifeSmarte" before they will respond.
import argparse
import asyncio
import json
import math
import os
import re
import struct
import sys
from datetime import datetime

from bleak import AdvertisementData, BleakClient, BleakScanner, BLEDevice
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_PSK = b"MakingLifeSmarte"


def _rc4(key: bytes, data: bytes) -> bytes:
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


def _safe_decrypt(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i in range(len(data) // 16):
        out += Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(data[i*16:(i+1)*16])
    if len(data) % 16:
        out += _rc4(key, data[(len(data) // 16) * 16:])
    return bytes(out)


def _safe_encrypt(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i in range(len(data) // 16):
        out += Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data[i*16:(i+1)*16])
    if len(data) % 16:
        out += _rc4(key, data[(len(data) // 16) * 16:])
    return bytes(out)


class MyLogger():

    LEVELS = {
        "DEBUG": 0,
        "INFO": 1,
        "WARN": 2,
        "ERROR": 3
    }

    NAMES = ["DEBUG", "INFO", "WARN", "ERROR"]

    def __init__(self, level: int) -> None:

        self.level = level

    def error(self, s: str):

        self.log(MyLogger.LEVELS["ERROR"], s)

    def warning(self, s: str):

        self.log(MyLogger.LEVELS["WARN"], s)

    def info(self, s: str):

        self.log(MyLogger.LEVELS["INFO"], s)

    def debug(self, s: str):

        self.log(MyLogger.LEVELS["DEBUG"], s)

    def log(self, level: int, s: str):

        if level >= self.level:
            print(f"{MyLogger.NAMES[level]}\t{s}", file=sys.stderr, flush=True)

    @staticmethod
    def hexstr(ba: bytearray) -> str:

        return " ".join([("0" + hex(b).replace("0x", ""))[-2:] for b in ba])


LOGGER = MyLogger(level=MyLogger.LEVELS["WARN"])


class Measurement():

    def __init__(self, timestamp: datetime, temperatureC: float, relHumidity: float, humidityOffset: float = 0, temperatureOffset: float = 0) -> None:

        self.timestamp: datetime = timestamp
        self.humidityOffset: float = humidityOffset
        self.temperatureOffset: float = temperatureOffset
        self.temperatureC: float = temperatureC + temperatureOffset
        self.relHumidity: float = relHumidity + humidityOffset

        z1 = (7.45 * self.temperatureC) / (235 + self.temperatureC)
        es = 6.1 * math.exp(z1*2.3025851)
        e = es * self.relHumidity / 100.0
        z2 = e / 6.1

        # absolute humidity / g/m3
        self.absHumidity: float = round(
            (216.7 * e) / (273.15 + self.temperatureC) * 10) / 10.0

        if z2 > 0:
            z3 = 0.434292289 * math.log(z2)
            self.dewPointC: float = int((235 * z3) / (7.45 - z3) * 10) / 10.0
        else:
            self.dewPointC: float = 0.0
        self.steamPressure: float = int(e * 10) / 10.0

        self.temperatureF: float = Measurement.to_fahrenheit(self.temperatureC)
        self.dewPointF: float = Measurement.to_fahrenheit(self.dewPointC)

    @staticmethod
    def to_fahrenheit(temperatureC: float) -> float:
        return temperatureC * 9.0/5.0 + 32

    @staticmethod
    def from_h5105_adv(data: bytearray, humidityOffset: float = 0, temperatureOffset: float = 0) -> 'Measurement':
        """
        Decode H5105 BLE advertisement payload (manufacturer key 0x0001).
        Layout: [temp_lo, temp_hi, hum_b0, hum_b1, hum_b2, battery]
        Bytes 0-1: little-endian int16, temperature x 10
        Bytes 2-4: 3-byte big-endian unsigned, H5075-style packed:
                   relHumidity = (raw % 1000) / 10
        Byte 5:    battery %
        """
        if len(data) < 6:
            return None

        raw_temp = struct.unpack_from("<h", data, 0)[0]
        temperatureC = raw_temp / 10.0

        raw_hum = struct.unpack(">I", bytearray([0]) + data[2:5])[0]
        relHumidity = (raw_hum % 1000) / 10.0

        return Measurement(
            timestamp=datetime.now(),
            temperatureC=temperatureC,
            relHumidity=relHumidity,
            humidityOffset=humidityOffset,
            temperatureOffset=temperatureOffset,
        )

    @staticmethod
    def from_bytes(bytes: bytearray, timestamp: datetime = None, little_endian=False, humidityOffset: float = 0, temperatureOffset: float = 0) -> 'Measurement':

        if not timestamp:
            timestamp = datetime.now()

        if len(bytes) == 4:
            temperatureC, relHumidity = struct.unpack(
                "<hh", bytes) if little_endian else struct.unpack(">hh", bytes)
            temperatureC /= 100
            relHumidity /= 100

        elif len(bytes) == 3:
            raw = struct.unpack(">I", bytearray([0]) + bytes)[0]
            if raw & 0x800000:
                is_negative = True
                raw = raw ^ 0x800000
            else:
                is_negative = False

            temperatureC = int(raw / 1000) / 10.0

            if is_negative:
                temperatureC = 0 - temperatureC

            relHumidity = (raw % 1000) / 10.0

        else:
            return None

        return Measurement(timestamp=timestamp, temperatureC=temperatureC, relHumidity=relHumidity, humidityOffset=humidityOffset, temperatureOffset=temperatureOffset)

    def __str__(self) -> str:

        s: 'list[str]' = list()

        s.append(f"Timestamp:            "
                 f"{self.timestamp.strftime('%Y-%m-%d %H:%M')}")
        s.append(f"Temperature:          "
                 f"{self.temperatureC:.1f} °C / {self.temperatureF:.1f} °F")
        if self.temperatureOffset:
            s.append(f"Temperature offset:   "
                     f"{self.temperatureOffset:.1f} °C / {Measurement.to_fahrenheit(self.temperatureOffset):.1f} °F")
        s.append(f"Rel. humidity:        {self.relHumidity:.1f} %")

        if self.humidityOffset:
            s.append(f"Rel. humidity offset: {self.humidityOffset:.1f} %")

        s.append(f"Dew point:            "
                 f"{self.dewPointC:.1f} °C / {self.dewPointF:.1f} °F")
        s.append(f"Abs. humidity:        {self.absHumidity:.1f} g/m³")
        s.append(f"Steam pressure:       {self.steamPressure:.1f} mbar")

        return "\n".join(s)

    def to_dict(self) -> dict:

        return {
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M"),
            "temperatureC": round(self.temperatureC, 1),
            "temperatureF": round(self.temperatureF, 1),
            "temperatureOffset": round(self.temperatureOffset, 1),
            "relHumidity": round(self.relHumidity, 1),
            "humidityOffset": round(self.humidityOffset, 1),
            "absHumidity": round(self.absHumidity, 1),
            "dewPointC": round(self.dewPointC, 1),
            "dewPointF": round(self.dewPointF, 1),
            "steamPressure": round(self.steamPressure, 1)
        }


class Alarm():

    def __init__(self, active: bool, lower: float, upper: float, unit: str = ""):
        self.active: bool = active
        self.lower: float = lower
        self.upper: float = upper
        self.unit: str = unit

    @staticmethod
    def from_bytes(bytes: bytearray, unit: str = None) -> 'Alarm':
        active, lower, upper = struct.unpack("<?hh", bytes)
        return Alarm(active=active, lower=lower/100.0, upper=upper/100.0, unit=unit)

    def to_bytes(self) -> bytearray:
        return struct.pack("<?hh", self.active, int(self.lower * 100), int(self.upper * 100))

    def __str__(self):
        return "%s, lower threshold: %.1f%s, upper threshold: %.1f%s" % (
            "active" if self.active else "inactive",
            self.lower, self.unit, self.upper, self.unit)

    def to_dict(self) -> dict:
        return {"active": self.active, "lower": self.lower, "upper": self.upper}


class MacAndSerial():

    def __init__(self, mac: str, serial: int):
        self.mac: str = mac
        self.serial: int = serial

    @staticmethod
    def from_bytes(bytes: bytearray) -> 'MacAndSerial':
        return MacAndSerial(mac=MacAndSerial.decode_mac(bytes=bytes),
                            serial=struct.unpack("<h", bytes[6:8])[0])

    @staticmethod
    def decode_mac(bytes: bytearray) -> str:
        mac = []
        for i in range(6):
            m = "0%s" % hex(bytes[5-i]).upper().replace("0X", "")
            mac.append(m[-2:])
        return ":".join(mac)

    def __str__(self):
        return f"{self.mac}, {self.serial}"

    def to_dict(self) -> dict:
        return {"mac": self.mac, "serial": self.serial}


class GoveeH5105(BleakClient):

    MAC_PREFIX = ["C3:30:38:", "A4:C1:38:", "1C:9F:24:"]

    H5105_MFG_KEY = 0x0001

    UUID_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
    UUID_DEVICE = "494e5445-4c4c-495f-524f-434b535f2011"
    UUID_COMMAND = "494e5445-4c4c-495f-524f-434b535f2012"
    UUID_DATA = "494e5445-4c4c-495f-524f-434b535f2013"

    UUID_AUTH_NOTIFY = "00010203-0405-0607-0809-0a0b0c0d2b10"
    UUID_AUTH_WRITE = "00010203-0405-0607-0809-0a0b0c0d2b11"
    UUID_AUTH_CONFIG = "00010203-0405-0607-0809-0a0b0c0d2b12"

    # Third-party service (Telink) — iOS app subscribes to this before auth
    UUID_TELINK_NOTIFY = "02f00000-0000-0000-0000-00000000ff02"

    REQUEST_CURRENT_MEASUREMENT = bytearray([0xaa, 0x01])
    REQUEST_ALARM_HUMIDITY = bytearray([0xaa, 0x03])
    REQUEST_ALARM_TEMPERATURE = bytearray([0xaa, 0x04])
    REQUEST_OFFSET_HUMIDITY = bytearray([0xaa, 0x06])
    REQUEST_OFFSET_TEMPERATURE = bytearray([0xaa, 0x07])
    REQUEST_BATTERY_LEVEL = bytearray([0xaa, 0x08])
    REQUEST_MAC_AND_SERIAL = bytearray([0xaa, 0x0c])
    REQUEST_HARDWARE = bytearray([0xaa, 0x0d])
    REQUEST_FIRMWARE = bytearray([0xaa, 0x0e])
    REQUEST_MAC_ADDRESS = bytearray([0xaa, 0x0f])

    def __init__(self, address) -> None:

        super().__init__(address, timeout=30.0)

        self.deviceName: str = None
        self.hardware: str = None
        self.firmware: str = None
        self.batteryLevel: int = None
        self.measurement: Measurement = None
        self.temperatureAlarm: Alarm = None
        self.humidityAlarm: Alarm = None
        self.temperatureOffset: float = None
        self.humidityOffset: float = None
        self.macAndSerial: MacAndSerial = None
        self._session_key: bytes = None

    async def connect(self) -> None:

        LOGGER.info(f"{self.address}: Request to connect")
        await super().connect()

        if self.is_connected:
            LOGGER.info(f"{self.address}: Successfully connected")
        else:
            LOGGER.error(f"{self.address}: Connecting has failed")

    async def disconnect(self) -> None:

        LOGGER.info(f"{self.address}: Request to disconnect")
        if self.is_connected:
            await super().disconnect()
            LOGGER.info(f"{self.address}: Successfully disconnected")

    @staticmethod
    def _build_packet(cmd: bytes) -> bytes:
        pkt = bytearray(cmd)
        if len(pkt) < 19:
            pkt.extend([0] * (19 - len(pkt)))
        checksum = 0
        for b in pkt[:19]:
            checksum ^= b
        pkt.append(checksum & 0xff)
        return bytes(pkt[:20])

    async def _auth_handshake(self) -> None:
        rx1_future: asyncio.Future = asyncio.get_event_loop().create_future()
        rx2_future: asyncio.Future = asyncio.get_event_loop().create_future()
        rx_count = [0]

        async def _on_auth_notify(_, data: bytearray) -> None:
            rx_count[0] += 1
            LOGGER.debug(f"{self.address}: <<< AUTH_NOTIFY #{rx_count[0]} ({MyLogger.hexstr(data)})")
            if rx_count[0] == 1 and not rx1_future.done():
                rx1_future.set_result(bytes(data))
            elif rx_count[0] == 2 and not rx2_future.done():
                rx2_future.set_result(bytes(data))

        # Subscribe to INTELLI_ROCKS characteristics first — the device state
        # machine requires these CCCDs to be enabled before it will respond to
        # the auth write on AUTH_WRITE.  Order matches the iOS packet dump exactly:
        # INTELLI_ROCKS x3, AUTH_NOTIFY, Telink notify, then read AUTH_CONFIG.
        async def _noop(_, __): pass
        for uuid in [GoveeH5105.UUID_DEVICE, GoveeH5105.UUID_COMMAND, GoveeH5105.UUID_DATA]:
            try:
                await self.start_notify(uuid, _noop)
                LOGGER.debug(f"{self.address}: subscribed to {uuid[-8:]}")
            except Exception as e:
                LOGGER.debug(f"{self.address}: could not subscribe to {uuid[-8:]}: {e}")

        LOGGER.debug(f"{self.address}: subscribing to AUTH_NOTIFY")
        await self.start_notify(GoveeH5105.UUID_AUTH_NOTIFY, _on_auth_notify)

        try:
            await self.start_notify(GoveeH5105.UUID_TELINK_NOTIFY, _noop)
            LOGGER.debug(f"{self.address}: subscribed to Telink notify")
        except Exception as e:
            LOGGER.debug(f"{self.address}: could not subscribe to Telink notify: {e}")

        LOGGER.debug(f"{self.address}: reading AUTH_CONFIG")
        cfg = await self.read_gatt_char(GoveeH5105.UUID_AUTH_CONFIG)
        LOGGER.debug(f"{self.address}: AUTH_CONFIG = {MyLogger.hexstr(bytearray(cfg))}")
        await asyncio.sleep(0.2)

        tx1_plain = GoveeH5105._build_packet(bytes([0xe7, 0x01]) + os.urandom(17))
        tx1 = _safe_encrypt(tx1_plain, _PSK)
        LOGGER.debug(f"{self.address}: >>> AUTH TX1 ({MyLogger.hexstr(bytearray(tx1))})")
        await self.write_gatt_char(GoveeH5105.UUID_AUTH_WRITE, tx1, response=False)
        LOGGER.debug(f"{self.address}: TX1 sent, waiting for RX1...")

        try:
            rx1 = await asyncio.wait_for(rx1_future, timeout=10.0)
        except asyncio.TimeoutError:
            raise RuntimeError("Auth handshake timed out waiting for RX1")

        LOGGER.debug(f"{self.address}: <<< AUTH RX1 ({MyLogger.hexstr(bytearray(rx1))})")
        dec = _safe_decrypt(rx1, _PSK)
        if dec[0] != 0xe7 or dec[1] != 0x01:
            raise RuntimeError(f"Auth RX1 magic mismatch: {dec[0]:02x} {dec[1]:02x}")
        self._session_key = dec[2:18]
        LOGGER.info(f"{self.address}: session key derived ({self._session_key.hex()})")

        tx2_plain = GoveeH5105._build_packet(bytes([0xe7, 0x02]) + os.urandom(17))
        tx2 = _safe_encrypt(tx2_plain, _PSK)
        LOGGER.debug(f"{self.address}: >>> AUTH TX2 ({MyLogger.hexstr(bytearray(tx2))})")
        await self.write_gatt_char(GoveeH5105.UUID_AUTH_WRITE, tx2, response=False)

        try:
            await asyncio.wait_for(rx2_future, timeout=5.0)
        except asyncio.TimeoutError:
            LOGGER.debug(f"{self.address}: no RX2 received (non-fatal)")

        await self.stop_notify(GoveeH5105.UUID_AUTH_NOTIFY)
        for uuid in [GoveeH5105.UUID_DEVICE, GoveeH5105.UUID_COMMAND, GoveeH5105.UUID_DATA,
                     GoveeH5105.UUID_TELINK_NOTIFY]:
            try:
                await self.stop_notify(uuid)
            except Exception:
                pass

    def _encrypt(self, plain20: bytes) -> bytes:
        pkt = GoveeH5105._build_packet(plain20)
        return _safe_encrypt(pkt, self._session_key)

    def _decrypt(self, cipher20: bytes) -> bytes:
        return _safe_decrypt(bytes(cipher20), self._session_key)

    async def write_gatt_char_encrypted(self, uuid: str, command: bytes, response: bool = False) -> None:
        pkt = GoveeH5105._build_packet(command)
        enc = _safe_encrypt(pkt, self._session_key)
        LOGGER.debug(f"{self.address}: >>> write_encrypted({uuid[-8:]}, plain={MyLogger.hexstr(bytearray(pkt))})")
        await self.write_gatt_char(uuid, enc, response=response)

    async def write_gatt_char_command(self, uuid: str, command: bytearray, params: bytearray = None, response: bool = True) -> None:

        if not uuid or not command:
            return None

        _bytearray = bytearray(command)
        if params:
            _bytearray.extend(params)

        ba_len = 20
        if len(_bytearray) < ba_len:
            _bytearray.extend([0] * (ba_len - 1 - len(_bytearray)))
            _checksum = 0
            for _b in _bytearray:
                _checksum ^= _b
            _bytearray.append(_checksum)

        LOGGER.debug("%s: >>> write_gatt_char(%s, %s)" %
                     (self.address, uuid, MyLogger.hexstr(_bytearray)))

        await self.write_gatt_char(uuid, _bytearray, response=response)

    async def requestConfig(self) -> None:
        """Query all device configuration: versions, battery, alarms, offsets, MAC.
        Requires prior _auth_handshake()."""

        LOGGER.info(f"{self.address}: requesting device configuration")

        queries = [
            GoveeH5105.REQUEST_HARDWARE,
            GoveeH5105.REQUEST_FIRMWARE,
            GoveeH5105.REQUEST_BATTERY_LEVEL,
            GoveeH5105.REQUEST_ALARM_TEMPERATURE,
            GoveeH5105.REQUEST_ALARM_HUMIDITY,
            GoveeH5105.REQUEST_OFFSET_TEMPERATURE,
            GoveeH5105.REQUEST_OFFSET_HUMIDITY,
            GoveeH5105.REQUEST_MAC_AND_SERIAL,
        ]
        remaining = [bytes(q) for q in queries]
        done = asyncio.Event()

        async def _handler(_, raw: bytearray) -> None:
            data = self._decrypt(raw)
            LOGGER.debug(f"{self.address}: <<< DEVICE ({MyLogger.hexstr(bytearray(data))})")
            cmd = bytes(data[0:2])
            if cmd == bytes(GoveeH5105.REQUEST_HARDWARE):
                self.hardware = data[2:9].decode(errors="ignore").rstrip("\x00")
                LOGGER.debug(f"{self.address}: hardware = {self.hardware!r}")
            elif cmd == bytes(GoveeH5105.REQUEST_FIRMWARE):
                self.firmware = data[2:9].decode(errors="ignore").rstrip("\x00")
                LOGGER.debug(f"{self.address}: firmware = {self.firmware!r}")
            elif cmd == bytes(GoveeH5105.REQUEST_BATTERY_LEVEL):
                self.batteryLevel = data[2]
                LOGGER.debug(f"{self.address}: battery = {self.batteryLevel} %")
            elif cmd == bytes(GoveeH5105.REQUEST_ALARM_TEMPERATURE):
                self.temperatureAlarm = Alarm.from_bytes(data[2:7], unit=" °C")
                LOGGER.debug(f"{self.address}: temp alarm = {self.temperatureAlarm}")
            elif cmd == bytes(GoveeH5105.REQUEST_ALARM_HUMIDITY):
                self.humidityAlarm = Alarm.from_bytes(data[2:7], unit=" %")
                LOGGER.debug(f"{self.address}: hum alarm = {self.humidityAlarm}")
            elif cmd == bytes(GoveeH5105.REQUEST_OFFSET_TEMPERATURE):
                self.temperatureOffset = struct.unpack("<h", data[2:4])[0] / 100.0
                LOGGER.debug(f"{self.address}: temp offset = {self.temperatureOffset} °C")
            elif cmd == bytes(GoveeH5105.REQUEST_OFFSET_HUMIDITY):
                self.humidityOffset = struct.unpack("<h", data[2:4])[0] / 100.0
                LOGGER.debug(f"{self.address}: hum offset = {self.humidityOffset} %")
            elif cmd == bytes(GoveeH5105.REQUEST_MAC_AND_SERIAL):
                self.macAndSerial = MacAndSerial.from_bytes(data[2:10])
                LOGGER.debug(f"{self.address}: mac/serial = {self.macAndSerial}")
            if cmd in remaining:
                remaining.remove(cmd)
            if not remaining:
                done.set()

        await self.start_notify(GoveeH5105.UUID_DEVICE, _handler)
        for q in queries:
            await self.write_gatt_char_encrypted(GoveeH5105.UUID_DEVICE, q)

        try:
            await asyncio.wait_for(done.wait(), timeout=8.0)
        except asyncio.TimeoutError:
            LOGGER.debug(f"{self.address}: config query timed out, missing: "
                         + ", ".join(r.hex() for r in remaining))

        try:
            await self.stop_notify(GoveeH5105.UUID_DEVICE)
        except Exception:
            pass

    async def requestVersions(self) -> None:
        """Backwards-compatible alias for requestConfig()."""
        await self.requestConfig()

    async def requestDeviceName(self) -> str:

        LOGGER.info(f"{self.address}: request device name")

        LOGGER.debug(f"{self.address}: >>> read_gatt_char({GoveeH5105.UUID_NAME})")
        try:
            raw = await super().read_gatt_char(GoveeH5105.UUID_NAME)
            name = raw.decode().replace("\x00", "") if raw else None
            LOGGER.debug(f"{self.address}: <<< {name!r}")
            self.deviceName = name or self.deviceName
        except Exception as e:
            LOGGER.debug(f"{self.address}: GAP device name not available ({e})")
        return self.deviceName

    async def downloadHistory(self, n_samples: int) -> 'list[Measurement]':
        """
        Download up to n_samples historical records via GATT.

        Requires a prior _auth_handshake() call.  Each DATA notification carries
        a 2-byte offset followed by up to 6 three-byte measurement records.
        The download ends when:
          - the device sends ee 01 on COMMAND, or
          - a DATA offset drops to 6 or below, or
          - no new packet arrives within a timeout.
        """
        if not self._session_key:
            raise RuntimeError("Auth handshake required before downloadHistory()")

        records: 'list[Measurement]' = []
        done_event = asyncio.Event()
        expected_notifications = [None]
        now = datetime.now()

        async def _on_data(_, raw: bytearray) -> None:
            data = self._decrypt(raw)
            LOGGER.debug(f"{self.address}: <<< DATA ({MyLogger.hexstr(bytearray(data))})")
            offset = struct.unpack_from(">H", data, 0)[0]
            for i in range(6):
                pos = 2 + i * 3
                chunk = data[pos:pos + 3]
                if chunk == b'\xff\xff\xff':
                    continue
                m = Measurement.from_bytes(bytes=chunk)
                if m:
                    records.append(m)
                    if len(records) >= n_samples:
                        done_event.set()
                        return
            if offset <= 6:
                done_event.set()

        async def _on_command(_, raw: bytearray) -> None:
            data = self._decrypt(raw)
            LOGGER.debug(f"{self.address}: <<< COMMAND ({MyLogger.hexstr(bytearray(data))})")
            if data[0] == 0xee and data[1] == 0x01:
                expected_notifications[0] = struct.unpack_from(">H", data, 2)[0]
                LOGGER.info(f"{self.address}: download complete, device reported {expected_notifications[0]} notifications")
                done_event.set()

        await self.start_notify(GoveeH5105.UUID_DATA, _on_data)
        await self.start_notify(GoveeH5105.UUID_COMMAND, _on_command)

        start_minutes = min(n_samples + 10, 0xffff)
        cmd = bytes([0x33, 0x01,
                     (start_minutes >> 8) & 0xff, start_minutes & 0xff,
                     0x00, 0x01])
        await self.write_gatt_char_encrypted(GoveeH5105.UUID_COMMAND, cmd)

        notify_count = [0]
        keepalive_cmd = bytes([0xaa, 0x01])

        async def _keepalive_loop():
            while not done_event.is_set():
                await asyncio.sleep(5.0)
                notify_count[0] += 1
                if notify_count[0] % 75 == 0:
                    await self.write_gatt_char_encrypted(GoveeH5105.UUID_COMMAND, keepalive_cmd)

        keepalive_task = asyncio.ensure_future(_keepalive_loop())
        try:
            await asyncio.wait_for(done_event.wait(), timeout=120.0)
        except asyncio.TimeoutError:
            LOGGER.warning(f"{self.address}: history download timed out after 120s")
        finally:
            keepalive_task.cancel()
            try:
                await keepalive_task
            except (asyncio.CancelledError, Exception):
                pass

        try:
            await self.stop_notify(GoveeH5105.UUID_DATA)
        except Exception:
            pass
        try:
            await self.stop_notify(GoveeH5105.UUID_COMMAND)
        except Exception:
            pass

        # Assign timestamps: records arrive newest-first (offset counts down).
        # Re-assign so record[0] is oldest and record[-1] is most recent.
        records.reverse()
        for i, m in enumerate(records):
            m.timestamp = datetime.fromtimestamp(
                now.timestamp() - (len(records) - 1 - i) * 60)

        return records[:n_samples]

    @staticmethod
    async def scan(consumer, duration: int = 20, unique: bool = True, mac_filter: str = None, progress=None):
        """
        Scan for H5105 devices via BLE advertisements.

        The H5105 broadcasts manufacturer data under key 0x0001 with layout:
          bytes 0-1: little-endian int16, temperature x 10
          bytes 2-4: 3-byte big-endian packed (raw % 1000 / 10 = humidity %)
          byte 5:    battery %

        If the device also advertises under 0xec88 (H5075-compatible firmware),
        that path is handled as a fallback using the 3-byte H5075 encoding.
        """
        found_devices = list()

        def callback(device: BLEDevice, advertising_data: AdvertisementData):

            if unique is False or device.address not in found_devices:
                mfg = advertising_data.manufacturer_data

                has_h5105 = GoveeH5105.H5105_MFG_KEY in mfg
                has_h5075_compat = 0xec88 in mfg

                if has_h5105 or has_h5075_compat:
                    found_devices.append(device.address)
                    LOGGER.debug(f"Found {device.address} ({device.name})")

                if device.name and device.address.upper()[0:9] in GoveeH5105.MAC_PREFIX:

                    if mac_filter and device.address.upper() != mac_filter.upper():
                        return

                    if has_h5105:
                        adv_bytes = mfg[GoveeH5105.H5105_MFG_KEY]
                        LOGGER.debug(
                            f"{device.address} ({device.name}): H5105 advertisement("
                            f"{MyLogger.hexstr(adv_bytes)})")

                        if len(adv_bytes) < 6:
                            LOGGER.warning(
                                f"{device.address}: advertisement payload too short ({len(adv_bytes)} bytes), skipping")
                            return

                        if device.address in alias.aliases:
                            humidityOffset = alias.aliases[device.address][1] or 0.0
                            temperatureOffset = alias.aliases[device.address][2] or 0.0
                        else:
                            humidityOffset = 0.0
                            temperatureOffset = 0.0

                        measurement = Measurement.from_h5105_adv(
                            adv_bytes,
                            humidityOffset=humidityOffset,
                            temperatureOffset=temperatureOffset)
                        battery = adv_bytes[5]

                        if measurement is None:
                            LOGGER.warning(f"{device.address}: Failed to decode H5105 advertisement")
                            return

                        consumer(device.address, device.name, battery, measurement)

                    elif has_h5075_compat:
                        adv_bytes = mfg[0xec88]
                        LOGGER.debug(
                            f"{device.address} ({device.name}): H5075-compat advertisement("
                            f"{MyLogger.hexstr(adv_bytes)})")

                        if device.address in alias.aliases:
                            humidityOffset = alias.aliases[device.address][1] or 0.0
                            temperatureOffset = alias.aliases[device.address][2] or 0.0
                        else:
                            humidityOffset = 0.0
                            temperatureOffset = 0.0

                        measurement = Measurement.from_bytes(
                            bytes=adv_bytes[1:4],
                            humidityOffset=humidityOffset,
                            temperatureOffset=temperatureOffset)
                        battery = adv_bytes[4]

                        consumer(device.address, device.name, battery, measurement)

                elif device.name and progress:
                    progress(len(found_devices))

        async with BleakScanner(callback):
            if duration:
                await asyncio.sleep(duration)
            else:
                while True:
                    await asyncio.sleep(1)

    @staticmethod
    async def scan_one(mac: str, timeout: int = 20) -> 'tuple[str, int, Measurement]':
        """Scan until one advertisement is received from the given MAC, or timeout."""
        result = asyncio.get_event_loop().create_future()

        def consumer(_, name: str, battery: int, measurement: Measurement):
            if not result.done():
                result.set_result((name, battery, measurement))

        scan_task = asyncio.ensure_future(
            GoveeH5105.scan(consumer=consumer, unique=False, duration=0, mac_filter=mac))

        try:
            name, battery, measurement = await asyncio.wait_for(result, timeout=timeout)
        except asyncio.TimeoutError:
            name, battery, measurement = None, None, None
        finally:
            scan_task.cancel()
            try:
                await scan_task
            except (asyncio.CancelledError, Exception):
                pass

        return name, battery, measurement

    def __str__(self) -> str:

        s: 'list[str]' = list()

        if self.deviceName:
            s.append(f"Devicename:           {self.deviceName}")

        s.append(f"Address:              {self.address}")

        if self.hardware:
            s.append(f"Hardware-Rev.:        {self.hardware}")

        if self.firmware:
            s.append(f"Firmware-Rev.:        {self.firmware}")

        if self.batteryLevel is not None:
            s.append(f"Battery level:        {self.batteryLevel} %")

        if self.macAndSerial:
            s.append(f"MAC / Serial:         {self.macAndSerial}")

        if self.temperatureAlarm:
            s.append(f"Temperature alarm:    {self.temperatureAlarm}")

        if self.humidityAlarm:
            s.append(f"Humidity alarm:       {self.humidityAlarm}")

        if self.temperatureOffset is not None:
            s.append(f"Temperature offset:   {self.temperatureOffset:.1f} °C")

        if self.humidityOffset is not None:
            s.append(f"Humidity offset:      {self.humidityOffset:.1f} %")

        if self.measurement:
            s.append(f"\n{str(self.measurement)}")

        return "\n".join(s)

    def to_dict(self) -> dict:

        return {
            "name": self.deviceName.strip() if self.deviceName else None,
            "address": self.address,
            "hardware": self.hardware,
            "firmware": self.firmware,
            "battery": self.batteryLevel,
            "macAndSerial": self.macAndSerial.to_dict() if self.macAndSerial else None,
            "temperatureAlarm": self.temperatureAlarm.to_dict() if self.temperatureAlarm else None,
            "humidityAlarm": self.humidityAlarm.to_dict() if self.humidityAlarm else None,
            "temperatureOffset": self.temperatureOffset,
            "humidityOffset": self.humidityOffset,
            "currentMeasurement": self.measurement.to_dict() if self.measurement else None
        }


class Alias():

    _KNOWN_DEVICES_FILE = ".known_govees"

    def __init__(self) -> None:

        self.aliases: 'dict[str,tuple[str, float, float]]' = dict()
        try:
            filename = os.path.join(
                os.environ['USERPROFILE'] if os.name == "nt" else os.environ.get('HOME', '~'),
                Alias._KNOWN_DEVICES_FILE)

            if os.path.isfile(filename):
                with open(filename, "r") as ins:
                    for line in ins:
                        _m = re.match(
                            r"([0-9A-Fa-f:]+) +([^ ]+)( (-?\d+\.\d) (-?\d+\.\d))?$", line)
                        if _m and _m.groups()[0].upper()[0:9] in GoveeH5105.MAC_PREFIX:

                            alias_name = _m.groups()[1].strip()
                            humidityOffset = float(_m.groups()[3]) if _m.groups()[3] else 0.0
                            temperatureOffset = float(_m.groups()[4]) if _m.groups()[4] else 0.0

                            self.aliases[_m.groups()[0]] = (
                                alias_name, humidityOffset, temperatureOffset)

        except Exception:
            pass

    def resolve(self, label: str) -> str:

        if label.upper()[0:9] in GoveeH5105.MAC_PREFIX:
            return label
        else:
            macs = [a for a in self.aliases if self.aliases[a][0].startswith(label)]
            return macs[0] if macs else None


def arg_parse(args: 'list[str]') -> dict:

    parser = argparse.ArgumentParser(
        prog='govee-h5105.py',
        description='Shell script in order to request Govee H5105 temperature humidity sensor')

    parser.add_argument('-a', '--address', help='MAC address or alias')
    parser.add_argument(
        '-s', '--scan', help='scan for devices for 20 seconds', action='store_true')
    parser.add_argument(
        '-m', '--measure', help='capture measurements/advertisements from nearby devices', action='store_true')
    parser.add_argument(
        '--status', help='request current temperature, humidity and battery level for given MAC address or alias', action='store_true')
    parser.add_argument(
        '-i', '--info', help='request device information for given MAC address or alias', action='store_true')
    parser.add_argument(
        '-d', '--download', help='download N historical samples via GATT (requires auth)', type=int, metavar='N')
    parser.add_argument(
        '-j', '--json', help='print in JSON format', action='store_true')
    parser.add_argument(
        '-l', '--log', help='print logging information', choices=MyLogger.NAMES)

    return parser.parse_args(args)


def scan():

    def stdout_consumer(address: str, name: str, battery: int, measurement: Measurement) -> None:

        label = (alias.aliases[address][0]
                 if address in alias.aliases else address) + " " * 21
        print(
            f"{label[:21]} {name}  {measurement.temperatureC:.1f}°C       {measurement.dewPointC:.1f}°C     {measurement.temperatureF:.1f}°F       {measurement.dewPointF:.1f}°F     {measurement.relHumidity:.1f}%          {measurement.absHumidity:.1f} g/m³      {measurement.steamPressure:.1f} mbar       {battery}%",
            flush=True)

    def progress(found: int) -> None:

        print(' %i bluetooth devices seen' % found, end='\r', file=sys.stderr)

    print("MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery", flush=True)
    asyncio.run(GoveeH5105.scan(consumer=stdout_consumer, progress=progress))


def measure():

    def stdout_consumer(address: str, name: str, battery: int, measurement: Measurement) -> None:

        timestamp = measurement.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        label = (alias.aliases[address][0]
                 if address in alias.aliases else address) + " " * 21

        print(
            f"{timestamp}   {label[:21]} {name}  {measurement.temperatureC:.1f}°C       {measurement.dewPointC:.1f}°C     {measurement.temperatureF:.1f}°F       {measurement.dewPointF:.1f}°F     {measurement.relHumidity:.1f}%          {measurement.absHumidity:.1f} g/m³      {measurement.steamPressure:.1f} mbar       {battery}%",
            flush=True)

    print("Timestamp             MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery", flush=True)
    asyncio.run(GoveeH5105.scan(unique=False, duration=0, consumer=stdout_consumer))


async def status(label: str, _json: bool = False) -> None:

    mac = alias.resolve(label=label)
    if not mac:
        LOGGER.error(f"Unable to resolve alias or mac {label}. Pls. check ~/.known_govees")
        return

    LOGGER.info(f"{mac}: waiting for advertisement...")
    _, battery, measurement = await GoveeH5105.scan_one(mac=mac)

    if measurement is None:
        print(f"No advertisement received from {mac} within timeout.", file=sys.stderr)
        return

    if _json:
        d = measurement.to_dict()
        d["battery"] = battery
        print(json.dumps(d, indent=2))
    else:
        print(str(measurement))
        print(f"Battery level:        {battery} %")


async def download_history(label: str, n_samples: int, _json: bool = False) -> None:

    mac = alias.resolve(label=label)
    if not mac:
        LOGGER.error(f"Unable to resolve alias or mac {label}. Pls. check ~/.known_govees")
        return

    device = GoveeH5105(mac)

    try:
        await device.connect()
        await device._auth_handshake()
        records = await device.downloadHistory(n_samples)
    except Exception as e:
        LOGGER.error(f"{mac}: history download failed: {e}")
        records = []
    finally:
        await device.disconnect()

    if not records:
        print(f"No history records received from {mac}.", file=sys.stderr)
        return

    if _json:
        print(json.dumps([m.to_dict() for m in records], indent=2))
    else:
        for m in records:
            print(f"{m.timestamp.strftime('%Y-%m-%d %H:%M')}  "
                  f"{m.temperatureC:6.1f} °C  {m.relHumidity:5.1f} %")


async def device_info(label: str, _json: bool = False) -> None:

    mac = alias.resolve(label=label)
    if not mac:
        LOGGER.error(f"Unable to resolve alias or mac {label}. Pls. check ~/.known_govees")
        return

    device = GoveeH5105(mac)

    try:
        await device.connect()
        await device.requestDeviceName()
        await device._auth_handshake()
        await device.requestConfig()
    except Exception as e:
        LOGGER.warning(f"{mac}: GATT connect failed ({e}), hardware/firmware unavailable")
    finally:
        await device.disconnect()

    LOGGER.info(f"{mac}: waiting for advertisement for current reading...")
    name, battery, measurement = await GoveeH5105.scan_one(mac=mac)
    if measurement is not None:
        device.batteryLevel = battery
        device.measurement = measurement
        if not device.deviceName and name:
            device.deviceName = name

    if _json:
        print(json.dumps(device.to_dict(), indent=2))
    else:
        print(str(device))


if __name__ == '__main__':
    alias = Alias()
    try:

        if len(sys.argv) == 1:
            scan()

        else:
            args = arg_parse(sys.argv[1:])

            if args.log:
                LOGGER.level = MyLogger.NAMES.index(args.log)

            if args.scan:
                scan()

            elif args.measure:
                measure()

            elif not args.address and (args.status or args.info or args.download):

                print("This operation requires to pass MAC address or alias",
                      file=sys.stderr, flush=True)

            elif args.download:
                asyncio.run(download_history(label=args.address, n_samples=args.download, _json=args.json))

            elif args.status:
                asyncio.run(status(label=args.address, _json=args.json))

            else:
                asyncio.run(device_info(label=args.address, _json=args.json))

    except KeyboardInterrupt:
        pass

    exit(0)
