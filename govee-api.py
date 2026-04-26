#!/usr/bin/python3
# Govee thermometer/hygrometer BLE client
# Supports H5074, H5075, H5179 (plaintext GATT) and H5105 (encrypted GATT / auth handshake)
import argparse
import asyncio
import json
import math
import os
import re
import struct
import sys
from datetime import datetime, timedelta

from bleak import AdvertisementData, BleakClient, BleakScanner, BLEDevice
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class MyLogger():

    LEVELS = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
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


# ---------------------------------------------------------------------------
# H5105 encryption helpers
# ---------------------------------------------------------------------------

_PSK = b"MakingLifeSmarte"


def _rc4(key: bytes, data: bytes) -> bytes:
    """RC4 with a fresh S-box on every call."""
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


# ---------------------------------------------------------------------------
# Shared data classes
# ---------------------------------------------------------------------------

class Measurement():

    def __init__(self, timestamp: datetime, temperatureC: float, relHumidity: float,
                 humidityOffset: float = 0, temperatureOffset: float = 0) -> None:

        self.timestamp: datetime = timestamp
        self.humidityOffset: float = humidityOffset
        self.temperatureOffset: float = temperatureOffset
        self.temperatureC: float = temperatureC + temperatureOffset
        self.relHumidity: float = relHumidity + humidityOffset

        z1 = (7.45 * self.temperatureC) / (235 + self.temperatureC)
        es = 6.1 * math.exp(z1 * 2.3025851)
        e = es * self.relHumidity / 100.0
        z2 = e / 6.1

        self.absHumidity: float = round((216.7 * e) / (273.15 + self.temperatureC) * 10) / 10.0

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
        return temperatureC * 9.0 / 5.0 + 32

    @staticmethod
    def twos_complement(n: int, w: int = 16) -> int:
        if n & (1 << (w - 1)):
            n = n - (1 << w)
        return n

    @staticmethod
    def unpack_h5179_date(byte_data: bytearray):
        mins_since_1970 = struct.unpack("<I", byte_data[0:4])
        return datetime(year=1970, month=1, day=1) + timedelta(minutes=mins_since_1970[0])

    @staticmethod
    def unpack_H5179_history_record(bytes: bytearray, timestamp: datetime = None,
                                    little_endian=True, humidityOffset: float = 0,
                                    temperatureOffset: float = 0) -> 'Measurement':
        temp, hum = struct.unpack_from("<HH", bytes)
        temperature = float(Measurement.twos_complement(temp) / 100.0)
        relHumidity = float(hum / 100.0)
        return Measurement(timestamp=timestamp, temperatureC=temperature,
                           relHumidity=relHumidity, humidityOffset=humidityOffset,
                           temperatureOffset=temperatureOffset)

    @staticmethod
    def from_h5105_adv(data: bytearray, humidityOffset: float = 0,
                       temperatureOffset: float = 0) -> 'Measurement':
        """Decode H5105 BLE advertisement payload (manufacturer key 0x0001)."""
        if len(data) < 6:
            return None
        raw_temp = struct.unpack_from("<h", data, 0)[0]
        temperatureC = raw_temp / 10.0
        raw_hum = struct.unpack(">I", bytearray([0]) + data[2:5])[0]
        relHumidity = (raw_hum % 1000) / 10.0
        return Measurement(timestamp=datetime.now(), temperatureC=temperatureC,
                           relHumidity=relHumidity, humidityOffset=humidityOffset,
                           temperatureOffset=temperatureOffset)

    @staticmethod
    def from_bytes(bytes: bytearray, timestamp: datetime = None, little_endian=False,
                   humidityOffset: float = 0, temperatureOffset: float = 0) -> 'Measurement':

        if not timestamp:
            timestamp = datetime.now()

        if len(bytes) == 4:
            temperatureC, relHumidity = (struct.unpack("<hh", bytes) if little_endian
                                         else struct.unpack(">hh", bytes))
            temperatureC /= 100
            relHumidity /= 100

        elif len(bytes) == 3:
            raw = struct.unpack(">I", bytearray([0]) + bytes)[0]
            is_negative = bool(raw & 0x800000)
            raw = raw & 0x7FFFFF
            temperatureC = int(raw / 1000) / 10.0
            if is_negative:
                temperatureC = -temperatureC
            relHumidity = (raw % 1000) / 10.0

        else:
            return None

        return Measurement(timestamp=timestamp, temperatureC=temperatureC,
                           relHumidity=relHumidity, humidityOffset=humidityOffset,
                           temperatureOffset=temperatureOffset)

    def __str__(self) -> str:
        s: 'list[str]' = []
        s.append(f"Timestamp:            {self.timestamp.strftime('%Y-%m-%d %H:%M')}")
        s.append(f"Temperature:          {self.temperatureC:.1f} °C / {self.temperatureF:.1f} °F")
        if self.temperatureOffset:
            s.append(f"Temperature offset:   "
                     f"{self.temperatureOffset:.1f} °C / "
                     f"{Measurement.to_fahrenheit(self.temperatureOffset):.1f} °F")
        s.append(f"Rel. humidity:        {self.relHumidity:.1f} %")
        if self.humidityOffset:
            s.append(f"Rel. humidity offset: {self.humidityOffset:.1f} %")
        s.append(f"Dew point:            {self.dewPointC:.1f} °C / {self.dewPointF:.1f} °F")
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
            "steamPressure": round(self.steamPressure, 1),
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
        return Alarm(active=active, lower=lower / 100.0, upper=upper / 100.0, unit=unit)

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
            m = "0%s" % hex(bytes[5 - i]).upper().replace("0X", "")
            mac.append(m[-2:])
        return ":".join(mac)

    def __str__(self):
        return f"{self.mac}, {self.serial}"

    def to_dict(self) -> dict:
        return {"mac": self.mac, "serial": self.serial}


class DataControl():

    DATA_CONTROL_IDLE = 0
    DATA_CONTROL_WAIT = 1
    DATA_CONTROL_STARTED = 2
    DATA_CONTROL_COMPLETE = 3
    DATA_CONTROL_INCOMPLETE = -1

    def __init__(self, expected_msg: int) -> None:
        self.timestamp: datetime = datetime.now()
        self.status: int = DataControl.DATA_CONTROL_IDLE
        self.expected_msg: int = expected_msg
        self.counted_msg: int = 0
        self.received_msg: int = 0
        self.measurements: 'list[Measurement]' = []
        self.device_category: str = ""
        self.set_device_category("")

    def set_device_category(self, device_type):
        self.device_category = DataControl.get_device_category(device_type)

    @staticmethod
    def get_device_category(device_type):
        if device_type == "H5179":
            return "H5179"
        return "H507*"

    def count(self) -> None:
        self.counted_msg += 1


# ---------------------------------------------------------------------------
# H507x / H5179 GATT client (plaintext)
# ---------------------------------------------------------------------------

class GoveeThermometerHygrometer(BleakClient):

    MAC_PREFIX = ["A4:C1:38:", "1C:9F:24:"]

    UUID_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
    UUID_DEVICE = "494e5445-4c4c-495f-524f-434b535f2011"
    UUID_COMMAND = "494e5445-4c4c-495f-524f-434b535f2012"
    UUID_DATA = "494e5445-4c4c-495f-524f-434b535f2013"

    REQUEST_CURRENT_MEASUREMENT = bytearray([0xaa, 0x01])
    REQUEST_CURRENT_MEASUREMENT2 = bytearray([0xaa, 0x0a])
    REQUEST_ALARM_HUMIDTY = bytearray([0xaa, 0x03])
    REQUEST_ALARM_TEMPERATURE = bytearray([0xaa, 0x04])
    REQUEST_OFFSET_HUMIDTY = bytearray([0xaa, 0x06])
    REQUEST_OFFSET_TEMPERATURE = bytearray([0xaa, 0x07])
    REQUEST_BATTERY_LEVEL = bytearray([0xaa, 0x08])
    REQUEST_MAC_AND_SERIAL = bytearray([0xaa, 0x0c])
    REQUEST_HARDWARE = bytearray([0xaa, 0x0d])
    REQUEST_FIRMWARE = bytearray([0xaa, 0x0e])
    REQUEST_MAC_ADDRESS = bytearray([0xaa, 0x0f])

    SEND_RECORDS_H5179_TX_REQUEST = bytearray([0x00, 0x00])
    SEND_RECORDS_TX_REQUEST = bytearray([0x33, 0x01])
    SEND_ALARM_HUMIDTY = bytearray([0x33, 0x03])
    SEND_ALARM_TEMPERATURE = bytearray([0x33, 0x04])
    SEND_OFFSET_HUMIDTY = bytearray([0x33, 0x06])
    SEND_OFFSET_TEMPERATURE = bytearray([0x33, 0x07])
    RECORDS_TX_COMPLETED = bytearray([0xee, 0x01])

    def __init__(self, address) -> None:
        super().__init__(address, timeout=30.0)
        self.deviceName: str = None
        self.manufacturer: str = None
        self.model: str = None
        self.hardware: str = None
        self.firmware: str = None
        self.macAndSerial: MacAndSerial = None
        self.mac: str = None
        self.batteryLevel: int = None
        self.humidityAlarm: Alarm = None
        self.temperatureAlarm: Alarm = None
        self.humidityOffset: float = 0
        self.temperatureOffset: float = 0
        self.measurement: Measurement = None
        self._data_control: DataControl = None

    async def connect(self) -> None:

        async def notification_handler_device(device: BLEDevice, bytes: bytearray) -> None:
            LOGGER.debug(f"{self.address}: <<< received notification with device data("
                         f"{MyLogger.hexstr(bytes)})")

            if bytes[0:2] == GoveeThermometerHygrometer.REQUEST_ALARM_HUMIDTY:
                self.humidityAlarm = Alarm.from_bytes(bytes[2:7], unit=" %")
                LOGGER.info(f'{self.address}: received configuration for humidity alarm: '
                            f'{str(self.humidityAlarm)}')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_ALARM_TEMPERATURE:
                self.temperatureAlarm = Alarm.from_bytes(bytes[2:7], unit=" °C")
                LOGGER.info(f'{self.address}: received configuration for temperature alarm: '
                            f'{str(self.temperatureAlarm)}')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_OFFSET_HUMIDTY:
                self.humidityOffset = struct.unpack("<h", bytes[2:4])[0] / 100.0
                LOGGER.info(f'{self.address}: received configuration for humidity offset: '
                            f'{self.humidityOffset:.1f} %')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_OFFSET_TEMPERATURE:
                self.temperatureOffset = struct.unpack("<h", bytes[2:4])[0] / 100.0
                LOGGER.info(f'{self.address}: received configuration for temperature offset: '
                            f'{self.temperatureOffset:.1f} °C')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_BATTERY_LEVEL:
                self.batteryLevel = bytes[2]
                LOGGER.info(f'{self.address}: received battery level: {self.batteryLevel} %')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_CURRENT_MEASUREMENT2:
                self.measurement = Measurement.from_bytes(
                    bytes=bytes[2:6], little_endian=True,
                    humidityOffset=self.humidityOffset or 0,
                    temperatureOffset=self.temperatureOffset or 0)
                LOGGER.info(f'{self.address}: received current measurement:\n'
                            f'{str(self.measurement)}')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_MAC_AND_SERIAL:
                self.macAndSerial = MacAndSerial.from_bytes(bytes[2:10])
                LOGGER.info(f'{self.address}: received mac address and serial: '
                            f'{str(self.macAndSerial)}')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_HARDWARE:
                self.hardware = bytes[2:9].decode()
                LOGGER.info(f'{self.address}: received hardware version: {self.hardware}')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_FIRMWARE:
                self.firmware = bytes[2:9].decode()
                LOGGER.info(f'{self.address}: received firmware version: {self.firmware}')
            elif bytes[0:2] == GoveeThermometerHygrometer.REQUEST_MAC_ADDRESS:
                self.mac = MacAndSerial.decode_mac(bytes[2:8])
                LOGGER.info(f'{self.address}: received mac address: {str(self.mac)}')
            elif bytes[0:2] == GoveeThermometerHygrometer.SEND_ALARM_HUMIDTY:
                LOGGER.info(f'{self.address}: configuration for humidity alarm successful')
            elif bytes[0:2] == GoveeThermometerHygrometer.SEND_ALARM_TEMPERATURE:
                LOGGER.info(f'{self.address}: configuration for temperature alarm successful')
            elif bytes[0:2] == GoveeThermometerHygrometer.SEND_OFFSET_HUMIDTY:
                LOGGER.info(f'{self.address}: configuration for humidity offset successful')
            elif bytes[0:2] == GoveeThermometerHygrometer.SEND_OFFSET_TEMPERATURE:
                LOGGER.info(f'{self.address}: configuration for temperature offset successful')

        async def notification_handler_data(device: BLEDevice, bytes: bytearray) -> None:
            LOGGER.debug(f"{self.address}: <<< received notification with measurement data ("
                         f"{MyLogger.hexstr(bytes)})")

            if not self._data_control:
                return

            if self._data_control.device_category == "H5179":
                record_time = Measurement.unpack_h5179_date(bytes)
                for i in range(4):
                    spos = 4 + (i * 4)
                    epos = spos + 4
                    if bytes[spos] != 0xff:
                        measurement = Measurement.unpack_H5179_history_record(
                            bytes[spos:epos], timestamp=record_time,
                            humidityOffset=self.humidityOffset,
                            temperatureOffset=self.temperatureOffset)
                        LOGGER.debug(f"{self.address}: Time: {record_time} "
                                     f"temperature={measurement.temperatureC} °C, "
                                     f"humidity={measurement.relHumidity} %")
                        self._data_control.measurements.append(measurement)
                    record_time = record_time - timedelta(minutes=1)
            else:
                for i in range(6):
                    minutes_back = struct.unpack(">H", bytes[0:2])[0]
                    if bytes[2 + 3 * i] == 0xff:
                        continue
                    timestamp = self._data_control.timestamp - timedelta(minutes=minutes_back - i)
                    _ba = bytearray(bytes[2 + 3 * i:5 + 3 * i])
                    measurement = Measurement.from_bytes(
                        bytes=_ba, timestamp=timestamp,
                        humidityOffset=self.humidityOffset,
                        temperatureOffset=self.temperatureOffset)
                    LOGGER.debug(f"{self.address}: Decoded measurement data("
                                 f"{MyLogger.hexstr(_ba)}) is "
                                 f"temperature={measurement.temperatureC} °C, "
                                 f"humidity={measurement.relHumidity} %")
                    self._data_control.measurements.append(measurement)

            self._data_control.count()

        async def notification_handler_command(device: BLEDevice, bytes: bytearray) -> None:
            LOGGER.debug(f"{self.address}: <<< received notification after command ("
                         f"{MyLogger.hexstr(bytes)})")

            if bytes[0:2] == GoveeThermometerHygrometer.REQUEST_CURRENT_MEASUREMENT:
                self.measurement = Measurement.from_bytes(
                    bytes=bytes[2:6], little_endian=False,
                    humidityOffset=self.humidityOffset or 0,
                    temperatureOffset=self.temperatureOffset or 0)
                self.batteryLevel = bytes[6]
                LOGGER.info(f'{self.address}: received current measurement and battery level:\n'
                            f'{str(self.measurement)}\nBattery level:        {self.batteryLevel} %')
            elif bytes[0:2] == GoveeThermometerHygrometer.SEND_RECORDS_TX_REQUEST and self._data_control:
                LOGGER.info(f"{self.address}: Data transmission starts")
                self._data_control.status = DataControl.DATA_CONTROL_STARTED
            elif bytes[0:2] == GoveeThermometerHygrometer.RECORDS_TX_COMPLETED and self._data_control:
                self._data_control.received_msg = struct.unpack(">H", bytes[2:4])[0]
                if self._data_control.received_msg == self._data_control.counted_msg:
                    LOGGER.info(f"{self.address}: Data transmission completed")
                    self._data_control.status = DataControl.DATA_CONTROL_COMPLETE
                else:
                    LOGGER.info(f"{self.address}: Data transmission aborted")
                    self._data_control.status = DataControl.DATA_CONTROL_INCOMPLETE

        LOGGER.info(f"{self.address}: Request to connect")
        await super().connect()

        if self.is_connected:
            LOGGER.info(f"{self.address}: Successfully connected")
            await self.start_notify(self.UUID_DEVICE, callback=notification_handler_device)
            await self.start_notify(self.UUID_COMMAND, callback=notification_handler_command)
            await self.start_notify(self.UUID_DATA, callback=notification_handler_data)
            await asyncio.sleep(.2)
        else:
            LOGGER.error(f"{self.address}: Connecting has failed")

    async def disconnect(self) -> None:
        LOGGER.info(f"{self.address}: Request to disconnect")
        if self.is_connected:
            await super().disconnect()
            LOGGER.info(f"{self.address}: Successfully disconnected")

    async def write_H5179_hist_gatt_char_command(self, uuid: str, command: bytearray,
                                                  start: int = None, end: int = None) -> None:
        _bytearray = bytearray(command)
        if start and end:
            _bytearray = _bytearray + start.to_bytes(4, byteorder="little")
            _bytearray = _bytearray + end.to_bytes(4, byteorder="little")
        else:
            ba_len = 10
            if len(_bytearray) < ba_len:
                _bytearray.extend([0] * (ba_len - 1 - len(_bytearray)))
                _checksum = 0
                for _b in _bytearray:
                    _checksum ^= _b
                _bytearray.append(_checksum)
        LOGGER.debug("%s: >>> write_gatt_char(%s, %s)" %
                     (self.address, uuid, MyLogger.hexstr(_bytearray)))
        await self.write_gatt_char(uuid, _bytearray, response=True)

    async def write_gatt_char_command(self, uuid: str, command: bytearray,
                                      params: bytearray = None) -> None:
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
        await self.write_gatt_char(uuid, _bytearray, response=True)

    async def read_gatt_char_as_str(self, uuid: str) -> str:
        if not uuid:
            return None
        LOGGER.debug(f"{self.address}: >>> read_gatt_char({GoveeThermometerHygrometer.UUID_NAME})")
        bytes = await super().read_gatt_char(GoveeThermometerHygrometer.UUID_NAME)
        if not bytes:
            LOGGER.debug(f"{self.address}: <<< no response data received")
            return None
        LOGGER.debug(f"{self.address}: <<< response data({MyLogger.hexstr(bytes)})")
        return bytes.decode().replace("\u0000", "")

    async def requestRecordedData(self, start: int, end: int,
                                   device_type: str = "H5075") -> 'list[Measurement]':
        device_category = DataControl.get_device_category(device_type)
        if device_category == "H5179":
            records_per_msg = 4
            LOGGER.info(f"{self.address}: request recorded measurements from "
                        f"{start} to {end} minutes since 1/1/1970 00:00")
        else:
            records_per_msg = 6
            LOGGER.info(f"{self.address}: request recorded measurements from "
                        f"{start} to {end} minutes in the past")

        self._data_control = DataControl(
            expected_msg=math.ceil((start - end + 1) / records_per_msg))
        self._data_control.set_device_category(device_type)

        if device_category == "H5179":
            await self.write_H5179_hist_gatt_char_command(
                uuid=GoveeThermometerHygrometer.UUID_COMMAND,
                command=GoveeThermometerHygrometer.SEND_RECORDS_H5179_TX_REQUEST,
                start=start, end=end)
        else:
            await self.write_gatt_char_command(
                uuid=GoveeThermometerHygrometer.UUID_COMMAND,
                command=GoveeThermometerHygrometer.SEND_RECORDS_TX_REQUEST,
                params=[start >> 8, start & 0xff, end >> 8, end & 0xff])

        i = 0
        while i < 600 and (self._data_control.status not in
                           [DataControl.DATA_CONTROL_COMPLETE, DataControl.DATA_CONTROL_INCOMPLETE]):
            await asyncio.sleep(.1)
            i += 1

        measurements = self._data_control.measurements
        self._data_control = None
        return measurements

    async def requestDeviceName(self) -> str:
        LOGGER.info(f"{self.address}: request device name")
        name = await self.read_gatt_char_as_str(uuid=GoveeThermometerHygrometer.UUID_NAME)
        LOGGER.info(f"{self.address}: received device name: {name}")
        self.deviceName = name or self.deviceName
        if "H5075" in self.deviceName:
            self.manufacturer = name[0:2]
            self.model = name[2:7]
        elif "H5074" in self.deviceName or "H5179" in self.deviceName:
            self.manufacturer = name[0:5]
            self.model = name[6:11]
        else:
            self.manufacturer = "Unknown"
            self.model = "Unknown"
        return self.deviceName

    async def requestHumidityAlarm(self) -> None:
        LOGGER.info(f"{self.address}: request configuration for humidity alarm")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_ALARM_HUMIDTY)

    async def requestTemperatureAlarm(self) -> None:
        LOGGER.info(f"{self.address}: request configuration for temperature alarm")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_ALARM_TEMPERATURE)

    async def requestHumidityOffset(self) -> None:
        LOGGER.info(f"{self.address}: request configuration for humidity offset")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_OFFSET_HUMIDTY)

    async def requestTemperatureOffset(self) -> None:
        LOGGER.info(f"{self.address}: request configuration for temperature offset")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_OFFSET_TEMPERATURE)

    async def requestBatteryLevel(self) -> None:
        LOGGER.info(f"{self.address}: request battery level")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_BATTERY_LEVEL)

    async def requestMacAddress(self) -> None:
        LOGGER.info(f"{self.address}: request MAC address")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_MAC_ADDRESS)

    async def requestMacAndSerial(self) -> None:
        LOGGER.info(f"{self.address}: request MAC address and serial no.")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_MAC_AND_SERIAL)

    async def requestHardwareVersion(self) -> None:
        LOGGER.info(f"{self.address}: request hardware version")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_HARDWARE)

    async def requestFirmwareVersion(self) -> None:
        LOGGER.info(f"{self.address}: request firmware version")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_FIRMWARE)

    async def requestMeasurement(self) -> None:
        LOGGER.info(f"{self.address}: request current measurement")
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.REQUEST_CURRENT_MEASUREMENT2)

    async def requestMeasurementAndBattery(self, device_type: str = "H5075") -> None:
        LOGGER.info(f"{self.address}: request current measurement and battery")
        if device_type == "H5179":
            await self.write_H5179_hist_gatt_char_command(
                uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                command=GoveeThermometerHygrometer.REQUEST_CURRENT_MEASUREMENT2)
        else:
            await self.write_gatt_char_command(
                uuid=GoveeThermometerHygrometer.UUID_COMMAND,
                command=GoveeThermometerHygrometer.REQUEST_CURRENT_MEASUREMENT)

    async def setHumidityAlarm(self, alarm: Alarm) -> None:
        LOGGER.info(f"{self.address}: set humidity alarm: {str(alarm)}")
        if alarm.active is None or alarm.lower < 0.0 or alarm.lower > 99.9 or alarm.upper < 0.1 or alarm.upper > 100:
            LOGGER.error("Values for humidity alarm are invalid.")
            return None
        bytes = alarm.to_bytes()
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.SEND_ALARM_HUMIDTY,
                                           params=bytes)

    async def setTemperatureAlarm(self, alarm: Alarm) -> None:
        LOGGER.info(f"{self.address}: set temperature alarm: {str(alarm)}")
        if alarm.active is None or alarm.lower < -20.0 or alarm.lower > 59.9 or alarm.upper < -19.9 or alarm.upper > 60.0:
            LOGGER.error("Values for temperature alarm are invalid.")
            return None
        bytes = alarm.to_bytes()
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.SEND_ALARM_TEMPERATURE,
                                           params=bytes)

    async def setHumidityOffset(self, offset: float) -> None:
        LOGGER.info(f"{self.address}: set humidity offset: {offset:.1f} %")
        if offset is None or offset < -20.0 or offset > 20.0:
            LOGGER.error("Value for humidity offset is invalid. Must be between -20.0 and 20.0")
            return None
        bytes = struct.pack("<h", int(offset * 100))
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.SEND_OFFSET_HUMIDTY,
                                           params=bytes)

    async def setTemperatureOffset(self, offset: float) -> None:
        LOGGER.info(f"{self.address}: set temperature offset: {offset:.1f} °C")
        if offset is None or offset < -3.0 or offset > 3.0:
            LOGGER.error("Value for temperature offset is invalid. Must be between -3.0 and 3.0")
            return None
        bytes = struct.pack("<h", int(offset * 100))
        await self.write_gatt_char_command(uuid=GoveeThermometerHygrometer.UUID_DEVICE,
                                           command=GoveeThermometerHygrometer.SEND_OFFSET_TEMPERATURE,
                                           params=bytes)

    def __str__(self) -> str:
        s: 'list[str]' = []
        if self.deviceName:
            s.append(f"Devicename:           {self.deviceName}")
        s.append(f"Address:              {self.address}")
        if self.manufacturer:
            s.append(f"Manufacturer:         {self.manufacturer}")
        if self.model:
            s.append(f"Model:                {self.model}")
        if self.hardware:
            s.append(f"Hardware-Rev.:        {self.hardware}")
        if self.firmware:
            s.append(f"Firmware-Rev.:        {self.firmware}")
        if self.batteryLevel:
            s.append(f"Battery level:        {self.batteryLevel} %")
        if self.humidityAlarm:
            s.append(f"Humidity alarm:       {str(self.humidityAlarm)}")
        if self.temperatureAlarm:
            s.append(f"Temperature alarm:    {str(self.temperatureAlarm)}")
        if self.humidityOffset:
            s.append(f"Humidity offset:      {self.humidityOffset:.1f} %")
        if self.temperatureOffset:
            s.append(f"Temperature offset:   {self.temperatureOffset:.1f} °C")
        if self.measurement:
            s.append(f"\n{str(self.measurement)}")
        return "\n".join(s)

    def to_dict(self) -> dict:
        return {
            "name": self.deviceName.strip() if self.deviceName else None,
            "address": self.address,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "hardware": self.hardware,
            "firmware": self.firmware,
            "battery": self.batteryLevel,
            "humidityAlarm": self.humidityAlarm.to_dict() if self.humidityAlarm else None,
            "temperatureAlarm": self.temperatureAlarm.to_dict() if self.temperatureAlarm else None,
            "humidityOffset": self.humidityOffset,
            "temperatureOffset": self.temperatureOffset,
            "currentMeasurement": self.measurement.to_dict() if self.measurement else None,
        }


# ---------------------------------------------------------------------------
# H5105 GATT client (encrypted, auth handshake required)
# ---------------------------------------------------------------------------

class GoveeH5105(BleakClient):

    MAC_PREFIX = ["C3:30:38:", "A4:C1:38:", "1C:9F:24:", "D3:30:38:"]

    UUID_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
    UUID_DEVICE = "494e5445-4c4c-495f-524f-434b535f2011"
    UUID_COMMAND = "494e5445-4c4c-495f-524f-434b535f2012"
    UUID_DATA = "494e5445-4c4c-495f-524f-434b535f2013"

    UUID_AUTH_NOTIFY = "00010203-0405-0607-0809-0a0b0c0d2b10"
    UUID_AUTH_WRITE = "00010203-0405-0607-0809-0a0b0c0d2b11"
    UUID_AUTH_CONFIG = "00010203-0405-0607-0809-0a0b0c0d2b12"
    UUID_TELINK_NOTIFY = "02f00000-0000-0000-0000-00000000ff02"

    H5105_MFG_KEY = 0x0001

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
        for uuid in [GoveeH5105.UUID_DEVICE, GoveeH5105.UUID_COMMAND,
                     GoveeH5105.UUID_DATA, GoveeH5105.UUID_TELINK_NOTIFY]:
            try:
                await self.stop_notify(uuid)
            except Exception:
                pass

    def _encrypt(self, plain20: bytes) -> bytes:
        pkt = GoveeH5105._build_packet(plain20)
        return _safe_encrypt(pkt, self._session_key)

    def _decrypt(self, cipher20: bytes) -> bytes:
        return _safe_decrypt(bytes(cipher20), self._session_key)

    async def write_gatt_char_encrypted(self, uuid: str, command: bytes,
                                         response: bool = False) -> None:
        pkt = GoveeH5105._build_packet(command)
        enc = _safe_encrypt(pkt, self._session_key)
        LOGGER.debug(f"{self.address}: >>> write_encrypted({uuid[-8:]}, "
                     f"plain={MyLogger.hexstr(bytearray(pkt))})")
        await self.write_gatt_char(uuid, enc, response=response)

    async def requestConfig(self) -> None:
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
            elif cmd == bytes(GoveeH5105.REQUEST_FIRMWARE):
                self.firmware = data[2:9].decode(errors="ignore").rstrip("\x00")
            elif cmd == bytes(GoveeH5105.REQUEST_BATTERY_LEVEL):
                self.batteryLevel = data[2]
            elif cmd == bytes(GoveeH5105.REQUEST_ALARM_TEMPERATURE):
                self.temperatureAlarm = Alarm.from_bytes(data[2:7], unit=" °C")
            elif cmd == bytes(GoveeH5105.REQUEST_ALARM_HUMIDITY):
                self.humidityAlarm = Alarm.from_bytes(data[2:7], unit=" %")
            elif cmd == bytes(GoveeH5105.REQUEST_OFFSET_TEMPERATURE):
                self.temperatureOffset = struct.unpack("<h", data[2:4])[0] / 100.0
            elif cmd == bytes(GoveeH5105.REQUEST_OFFSET_HUMIDITY):
                self.humidityOffset = struct.unpack("<h", data[2:4])[0] / 100.0
            elif cmd == bytes(GoveeH5105.REQUEST_MAC_AND_SERIAL):
                self.macAndSerial = MacAndSerial.from_bytes(data[2:10])
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

    async def requestDeviceName(self) -> str:
        LOGGER.info(f"{self.address}: request device name")
        try:
            raw = await super().read_gatt_char(GoveeH5105.UUID_NAME)
            name = raw.decode().replace("\x00", "") if raw else None
            LOGGER.debug(f"{self.address}: <<< {name!r}")
            self.deviceName = name or self.deviceName
        except Exception as e:
            LOGGER.debug(f"{self.address}: GAP device name not available ({e})")
        return self.deviceName

    async def downloadHistory(self, n_samples: int) -> 'list[Measurement]':
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
                LOGGER.info(f"{self.address}: download complete, device reported "
                            f"{expected_notifications[0]} notifications")
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

        for uuid in [GoveeH5105.UUID_DATA, GoveeH5105.UUID_COMMAND]:
            try:
                await self.stop_notify(uuid)
            except Exception:
                pass

        records.reverse()
        for i, m in enumerate(records):
            m.timestamp = datetime.fromtimestamp(
                now.timestamp() - (len(records) - 1 - i) * 60)

        return records[:n_samples]

    def __str__(self) -> str:
        s: 'list[str]' = []
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
            "currentMeasurement": self.measurement.to_dict() if self.measurement else None,
        }


# ---------------------------------------------------------------------------
# Alias store (shared — covers all supported MAC prefixes)
# ---------------------------------------------------------------------------

# All MAC prefixes for all supported devices
_ALL_MAC_PREFIXES = GoveeThermometerHygrometer.MAC_PREFIX + [
    p for p in GoveeH5105.MAC_PREFIX
    if p not in GoveeThermometerHygrometer.MAC_PREFIX
]


def _is_h5105_name(name: str) -> bool:
    return name is not None and "H5105" in name


class Alias():

    _KNOWN_DEVICES_FILE = ".known_govees"

    def __init__(self) -> None:
        self.aliases: 'dict[str,tuple[str, float, float]]' = {}
        try:
            filename = os.path.join(
                os.environ['USERPROFILE'] if os.name == "nt" else os.environ.get('HOME', '~'),
                Alias._KNOWN_DEVICES_FILE)

            if os.path.isfile(filename):
                with open(filename, "r") as ins:
                    for line in ins:
                        _m = re.match(
                            r"([0-9A-Fa-f:]+) +([^ ]+)( (-?\d+\.\d) (-?\d+\.\d))?$", line)
                        if _m and _m.groups()[0].upper()[0:9] in _ALL_MAC_PREFIXES:
                            alias_name = _m.groups()[1].strip()
                            humidityOffset = float(_m.groups()[3]) if _m.groups()[3] else 0.0
                            temperatureOffset = float(_m.groups()[4]) if _m.groups()[4] else 0.0
                            self.aliases[_m.groups()[0]] = (alias_name, humidityOffset, temperatureOffset)
        except Exception:
            pass

    def resolve(self, label: str) -> str:
        if label.upper()[0:9] in _ALL_MAC_PREFIXES:
            return label
        macs = [a for a in self.aliases if self.aliases[a][0].startswith(label)]
        return macs[0] if macs else None


# ---------------------------------------------------------------------------
# Unified BLE scanner
# ---------------------------------------------------------------------------

async def _scan_all(consumer, duration: int = 20, unique: bool = True,
                    mac_filter: str = None, progress=None):
    """
    Scan for all supported Govee devices.

    Dispatches on manufacturer data key and device name:
      0x0001  → H5105 advertisement format
      0xec88  → H5075 / H5074 format (also H5105 fallback firmware)
      0x8801  → H5179 format
    """
    found_devices = []

    def decode_5074(bytes) -> 'tuple[float, float, int]':
        temperatureC, relHumidity = struct.unpack("<hh", bytes[1:5])
        return round(temperatureC / 100, 1), round(relHumidity / 100, 1), bytes[5]

    def decode_5179(mfg_data):
        temp, hum, batt = struct.unpack_from("<HHB", mfg_data, 4)
        return float(Measurement.twos_complement(temp) / 100.0), float(hum / 100.0), int(batt)

    def callback(device: BLEDevice, advertising_data: AdvertisementData):
        mfg = advertising_data.manufacturer_data
        name = device.name
        addr = device.address
        prefix = addr.upper()[0:9]

        has_h5105 = GoveeH5105.H5105_MFG_KEY in mfg
        has_ec88 = 0xec88 in mfg
        has_8801 = 0x8801 in mfg

        if unique is False or addr not in found_devices:
            if has_h5105 or has_ec88 or has_8801:
                found_devices.append(addr)
                LOGGER.debug(f"Found {addr} ({name})")

        if not name or prefix not in _ALL_MAC_PREFIXES:
            if name and progress:
                progress(len(found_devices))
            return

        if mac_filter and addr.upper() != mac_filter.upper():
            return

        if unique and addr in found_devices[:-1]:
            return

        humidityOffset = 0.0
        temperatureOffset = 0.0
        if addr in alias.aliases:
            humidityOffset = alias.aliases[addr][1] or 0.0
            temperatureOffset = alias.aliases[addr][2] or 0.0

        if has_h5105 and _is_h5105_name(name):
            adv_bytes = mfg[GoveeH5105.H5105_MFG_KEY]
            LOGGER.debug(f"{addr} ({name}): H5105 advertisement({MyLogger.hexstr(adv_bytes)})")
            if len(adv_bytes) < 6:
                LOGGER.warning(f"{addr}: advertisement payload too short, skipping")
                return
            measurement = Measurement.from_h5105_adv(
                adv_bytes, humidityOffset=humidityOffset, temperatureOffset=temperatureOffset)
            if measurement is None:
                LOGGER.warning(f"{addr}: Failed to decode H5105 advertisement")
                return
            consumer(addr, name, adv_bytes[5], measurement)

        elif has_ec88:
            adv_bytes = mfg[0xec88]
            LOGGER.debug(f"{addr} ({name}): H507x advertisement({MyLogger.hexstr(adv_bytes)})")
            if "H5074" in name:
                temperatureC, relHumidity, battery = decode_5074(adv_bytes)
                measurement = Measurement(datetime.now(), temperatureC, relHumidity, 0, 0)
            elif _is_h5105_name(name):
                # H5105 on old firmware that only advertises 0xec88
                measurement = Measurement.from_bytes(
                    bytes=adv_bytes[1:4],
                    humidityOffset=humidityOffset, temperatureOffset=temperatureOffset)
                battery = adv_bytes[4]
            else:
                measurement = Measurement.from_bytes(
                    bytes=adv_bytes[1:4],
                    humidityOffset=humidityOffset, temperatureOffset=temperatureOffset)
                battery = adv_bytes[4]
            consumer(addr, name, battery, measurement)

        elif has_8801:
            adv_bytes = mfg[0x8801]
            LOGGER.debug(f"{addr} ({name}): H5179 advertisement({MyLogger.hexstr(adv_bytes)})")
            temperatureC, relHumidity, battery = decode_5179(adv_bytes)
            measurement = Measurement(datetime.now(), temperatureC, relHumidity, 0, 0)
            consumer(addr, name, battery, measurement)

    async with BleakScanner(callback):
        if duration:
            await asyncio.sleep(duration)
        else:
            while True:
                await asyncio.sleep(1)


async def _scan_one(mac: str, timeout: int = 20) -> 'tuple[str, int, Measurement]':
    """Scan until one advertisement is received from the given MAC, or timeout."""
    result = asyncio.get_event_loop().create_future()

    def consumer(_, name: str, battery: int, measurement: Measurement):
        if not result.done():
            result.set_result((name, battery, measurement))

    scan_task = asyncio.ensure_future(
        _scan_all(consumer=consumer, unique=False, duration=0, mac_filter=mac))
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


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def scan():

    def stdout_consumer(address: str, name: str, battery: int, measurement: Measurement) -> None:
        label = (alias.aliases[address][0] if address in alias.aliases else address) + " " * 21
        print(
            f"{label[:21]} {name}  "
            f"{measurement.temperatureC:.1f}°C       {measurement.dewPointC:.1f}°C     "
            f"{measurement.temperatureF:.1f}°F       {measurement.dewPointF:.1f}°F     "
            f"{measurement.relHumidity:.1f}%          {measurement.absHumidity:.1f} g/m³      "
            f"{measurement.steamPressure:.1f} mbar       {battery}%",
            flush=True)

    def progress(found: int) -> None:
        print(' %i bluetooth devices seen' % found, end='\r', file=sys.stderr)

    print("MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  "
          "Rel. humidity  Abs. humidity  Steam pressure  Battery", flush=True)
    asyncio.run(_scan_all(consumer=stdout_consumer, progress=progress))


def measure():

    def stdout_consumer(address: str, name: str, battery: int, measurement: Measurement) -> None:
        timestamp = measurement.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        label = (alias.aliases[address][0] if address in alias.aliases else address) + " " * 21
        print(
            f"{timestamp}   {label[:21]} {name}  "
            f"{measurement.temperatureC:.1f}°C       {measurement.dewPointC:.1f}°C     "
            f"{measurement.temperatureF:.1f}°F       {measurement.dewPointF:.1f}°F     "
            f"{measurement.relHumidity:.1f}%          {measurement.absHumidity:.1f} g/m³      "
            f"{measurement.steamPressure:.1f} mbar       {battery}%",
            flush=True)

    print("Timestamp             MAC-Address/Alias     Device name   Temperature  Dew point  "
          "Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery",
          flush=True)
    asyncio.run(_scan_all(unique=False, duration=0, consumer=stdout_consumer))


async def status(label: str, _json: bool = False) -> None:
    mac = alias.resolve(label=label)
    if not mac:
        LOGGER.error(f"Unable to resolve alias or mac {label}. Pls. check ~/.known_govees")
        return

    LOGGER.info(f"{mac}: waiting for advertisement...")
    name, battery, measurement = await _scan_one(mac=mac)

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


async def device_info(label: str, _json: bool = False) -> None:
    mac = alias.resolve(label=label)
    if not mac:
        LOGGER.error(f"Unable to resolve alias or mac {label}. Pls. check ~/.known_govees")
        return

    # Determine device model from a quick BLE advertisement scan
    LOGGER.info(f"{mac}: scanning for advertisement to detect model...")
    name, battery, adv_measurement = await _scan_one(mac=mac)

    if _is_h5105_name(name):
        # --- H5105 path ---
        device = GoveeH5105(mac)
        try:
            await device.connect()
            await device.requestDeviceName()
            await device._auth_handshake()
            await device.requestConfig()
        except Exception as e:
            LOGGER.warning(f"{mac}: GATT connect failed ({e}), some info unavailable")
        finally:
            await device.disconnect()

        if adv_measurement is not None:
            device.batteryLevel = battery
            device.measurement = adv_measurement
            if not device.deviceName and name:
                device.deviceName = name

        if _json:
            print(json.dumps(device.to_dict(), indent=2))
        else:
            print(str(device))

    else:
        # --- H507x / H5179 path ---
        device = GoveeThermometerHygrometer(mac)
        try:
            await device.connect()
            await device.requestDeviceName()
            await device.requestHumidityAlarm()
            await device.requestTemperatureAlarm()
            await device.requestHumidityOffset()
            await device.requestTemperatureOffset()
            await device.requestHardwareVersion()
            await device.requestFirmwareVersion()
            await device.requestBatteryLevel()
            device_type = device.model
            if device_type == "H5179":
                await device.requestMeasurement()
            else:
                await device.requestMeasurementAndBattery(device_type)
            await asyncio.sleep(.5)
        except Exception as e:
            LOGGER.error(f"{mac}: {str(e)}")
        finally:
            await device.disconnect()

        if _json:
            print(json.dumps(device.to_dict(), indent=2))
        else:
            print(str(device))


async def download_history(label: str, n_samples: int, _json: bool = False) -> None:
    """Download historical records from an H5105 device."""
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


async def recorded_data(label: str, start: str, end: str, _json: bool = False):
    """Download historical records from an H507x / H5179 device."""

    def parseTimeStr(s: str) -> int:
        a = s.split(":")
        return (int(a[0]) * 60 + int(a[1])) if len(a) == 2 else int(a[0])

    def get_1970_offset(minutes_before_now):
        t_delta = datetime.now() - datetime(year=1970, month=1, day=1)
        return int(t_delta.total_seconds() / 60) - minutes_before_now

    try:
        mac = alias.resolve(label=label)
        device = GoveeThermometerHygrometer(mac)
        await device.connect()
        await device.requestDeviceName()
        device_type = device.model
        if device_type == "H5179":
            start = get_1970_offset(parseTimeStr(start)) if start else get_1970_offset(60)
            end = get_1970_offset(parseTimeStr(end)) if end else get_1970_offset(0)
            starttime = start if start < end else end
            endtime = end if end > start else start
        else:
            start = min(parseTimeStr(start) if start else 60, 28800)
            end = min(parseTimeStr(end) if end else 0, 28800)
            starttime = start if start > end else end
            endtime = end if end < start else start
        LOGGER.debug(f"Device type: {device_type}, start: {str(start)}, end: {str(end)}")
        await device.requestHumidityOffset()
        await device.requestTemperatureOffset()
        measurements = await device.requestRecordedData(
            start=starttime, end=endtime, device_type=device_type)
        if _json:
            print(json.dumps([m.to_dict() for m in measurements], indent=2))
        else:
            print("Timestamp         Temperature  Dew point  Temperature  Dew point  "
                  "Rel. humidity  Abs. humidity  Steam pressure", flush=True)
            for m in measurements:
                timestamp = m.timestamp.strftime("%Y-%m-%d %H:%M")
                print(f"{timestamp}  {m.temperatureC:.1f}°C       {m.dewPointC:.1f}°C     "
                      f"{m.temperatureF:.1f}°F       {m.dewPointF:.1f}°F     "
                      f"{m.relHumidity:.1f}%          {m.absHumidity:.1f} g/m³      "
                      f"{m.steamPressure:.1f} mbar", flush=True)

    except Exception as e:
        LOGGER.error(f"An exception has occurred: {str(e)}")
    finally:
        await device.disconnect()


async def configure_device(label: str, humidityAlarm: str = None, temperatureAlarm: str = None,
                            humidityOffset: float = None, temperatureOffset: float = None) -> None:

    def parseAlarm(arg: str) -> 'tuple[bool, float, float]':
        if not arg:
            return None, None, None
        m = re.match(r"^(on|off) (-?\d{1,2}\.\d) (-?\d{1,3}\.\d)$", arg.lower())
        if not m:
            return None, None, None
        return "on" == m.groups()[0], float(m.groups()[1]), float(m.groups()[2])

    has_errors = False
    if humidityAlarm:
        humidityAlarmActive, humidityAlarmLower, humidityAlarmUpper = parseAlarm(arg=humidityAlarm)
        if humidityAlarmActive is None or humidityAlarmLower < 0 or humidityAlarmLower > 99.9 or humidityAlarmUpper < 0.1 or humidityAlarmUpper > 100:
            LOGGER.error("Parameters for humidity alarm are incorrect.")
            has_errors = True

    if temperatureAlarm:
        temperatureAlarmActive, temperatureAlarmLower, temperatureAlarmUpper = parseAlarm(arg=temperatureAlarm)
        if temperatureAlarmActive is None or temperatureAlarmLower < -20.0 or temperatureAlarmLower > 59.9 or temperatureAlarmUpper < -19.9 or temperatureAlarmUpper > 60:
            LOGGER.error("Parameters for temperature alarm are incorrect.")
            has_errors = True

    if humidityOffset is not None and (humidityOffset < -20.0 or humidityOffset > 20.0):
        LOGGER.error("Parameter for humidity offset is incorrect.")
        has_errors = True

    if temperatureOffset is not None and (temperatureOffset < -3.0 or temperatureOffset > 3.0):
        LOGGER.error("Parameter for temperature offset is incorrect.")
        has_errors = True

    if has_errors:
        return

    try:
        mac = alias.resolve(label=label)
        device = GoveeThermometerHygrometer(mac)
        await device.connect()

        if humidityAlarm is not None:
            await device.setHumidityAlarm(
                alarm=Alarm(active=humidityAlarmActive, lower=humidityAlarmLower,
                            upper=humidityAlarmUpper, unit=" %"))
        if temperatureAlarm is not None:
            await device.setTemperatureAlarm(
                alarm=Alarm(active=temperatureAlarmActive, lower=temperatureAlarmLower,
                            upper=temperatureAlarmUpper, unit=" °C"))
        if humidityOffset is not None:
            await device.setHumidityOffset(offset=humidityOffset)
        if temperatureOffset is not None:
            await device.setTemperatureOffset(offset=temperatureOffset)

        await asyncio.sleep(.5)

    except Exception as e:
        LOGGER.error(f"{mac}: {str(type(e))} {str(e)}")
    finally:
        await device.disconnect()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def arg_parse(args: 'list[str]') -> dict:
    parser = argparse.ArgumentParser(
        prog='govee-api.py',
        description='Shell interface for Govee H5074 / H5075 / H5105 / H5179 '
                    'temperature & humidity sensors')

    parser.add_argument('-a', '--address', help='MAC address or alias')
    parser.add_argument('-s', '--scan',
                        help='scan for devices for 20 seconds', action='store_true')
    parser.add_argument('-m', '--measure',
                        help='capture measurements/advertisements from nearby devices',
                        action='store_true')
    parser.add_argument('--status',
                        help='request current temperature, humidity and battery level '
                             'for given MAC address or alias',
                        action='store_true')
    parser.add_argument('-i', '--info',
                        help='request device information and configuration for given '
                             'MAC address or alias',
                        action='store_true')
    # H5105-specific history download
    parser.add_argument('-d', '--download',
                        help='download N historical samples via GATT (H5105, requires auth)',
                        type=int, metavar='N')
    # H507x / H5179 history download
    parser.add_argument('--data',
                        help='request recorded data for given MAC address or alias '
                             '(H5074 / H5075 / H5179)',
                        action='store_true')
    parser.add_argument('--start', metavar="<hhh:mm>",
                        help='request recorded data from start time expression, '
                             'e.g. 480:00 (max. 20 days)',
                        type=str, default=None)
    parser.add_argument('--end', metavar="<hhh:mm>",
                        help='request recorded data to end time expression, '
                             'e.g. 480:00 (max. 20 days)',
                        type=str, default=None)
    # Configuration (H507x / H5179 only)
    parser.add_argument('--set-humidity-alarm',
                        metavar="\"<on|off> <lower> <upper>\"",
                        help='set humidity alarm, e.g. "on 30.0 75.0"',
                        type=str)
    parser.add_argument('--set-temperature-alarm',
                        metavar="\"<on|off> <lower> <upper>\"",
                        help='set temperature alarm, e.g. "on 15.0 26.0"',
                        type=str)
    parser.add_argument('--set-humidity-offset', metavar="<offset>",
                        help='set humidity calibration offset (-20.0 … 20.0)',
                        type=float)
    parser.add_argument('--set-temperature-offset', metavar="<offset>",
                        help='set temperature calibration offset (-3.0 … 3.0)',
                        type=float)
    parser.add_argument('-j', '--json', help='print in JSON format', action='store_true')
    parser.add_argument('-l', '--log', help='print logging information',
                        choices=MyLogger.NAMES)

    return parser.parse_args(args)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

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

            elif not args.address and (args.status or args.info or args.download or args.data
                                       or args.set_humidity_alarm or args.set_temperature_alarm
                                       or args.set_humidity_offset or args.set_temperature_offset):
                print("This operation requires to pass MAC address or alias",
                      file=sys.stderr, flush=True)

            elif args.download:
                asyncio.run(download_history(label=args.address, n_samples=args.download,
                                             _json=args.json))

            elif args.data:
                asyncio.run(recorded_data(label=args.address, start=args.start,
                                          end=args.end, _json=args.json))

            elif args.set_humidity_alarm or args.set_temperature_alarm \
                    or args.set_humidity_offset is not None \
                    or args.set_temperature_offset is not None:
                asyncio.run(configure_device(
                    label=args.address,
                    humidityAlarm=args.set_humidity_alarm,
                    temperatureAlarm=args.set_temperature_alarm,
                    humidityOffset=args.set_humidity_offset,
                    temperatureOffset=args.set_temperature_offset))

            elif args.status:
                asyncio.run(status(label=args.address, _json=args.json))

            else:
                asyncio.run(device_info(label=args.address, _json=args.json))

    except KeyboardInterrupt:
        pass

    exit(0)
