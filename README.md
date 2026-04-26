# Govee Python API for H5074, H5075, H5105 and H5179 hygrometers

Python script for Govee H5074, H5075, H5105 and H5179 thermometer / hygrometer for Linux, Raspberry Pis and Windows. Forked from [govee-h5075-thermo-hygrometer](https://github.com/Heckie75/govee-h5075-thermo-hygrometer).

Vibe-coded with claude code ;)

## Preconditions
Install the python modules [bleak](https://bleak.readthedocs.io/en/latest/) and [pycryptodomex](https://pycryptodome.readthedocs.io/en/latest/):

```
$ pip install bleak pycryptodomex
```

or globally for all users (maybe also required on Raspberry Pi OS)
```
sudo apt install python3-bleak python3-pycryptodome
```

## Help
```
$ ./govee-api.py --help
usage: govee-api.py [-h] [-a ADDRESS] [-s] [-m] [--status] [-i] [-d N]
                    [--data] [--start <hhh:mm>] [--end <hhh:mm>]
                    [--set-humidity-alarm "<on|off> <lower> <upper>"]
                    [--set-temperature-alarm "<on|off> <lower> <upper>"]
                    [--set-humidity-offset <offset>]
                    [--set-temperature-offset <offset>] [-j]
                    [-l {DEBUG,INFO,WARN,ERROR}]

Shell interface for Govee H5074 / H5075 / H5105 / H5179 temperature & humidity
sensors

options:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        MAC address or alias
  -s, --scan            scan for devices for 20 seconds
  -m, --measure         capture measurements/advertisements from nearby
                        devices
  --status              request current temperature, humidity and battery
                        level for given MAC address or alias
  -i, --info            request device information and configuration for given
                        MAC address or alias
  -d N, --download N    download N historical samples via GATT (H5105,
                        requires auth)
  --data                request recorded data for given MAC address or alias
                        (H5074 / H5075 / H5179)
  --start <hhh:mm>      request recorded data from start time expression, e.g.
                        480:00 (max. 20 days)
  --end <hhh:mm>        request recorded data to end time expression, e.g.
                        480:00 (max. 20 days)
  --set-humidity-alarm "<on|off> <lower> <upper>"
                        set humidity alarm, e.g. "on 30.0 75.0"
  --set-temperature-alarm "<on|off> <lower> <upper>"
                        set temperature alarm, e.g. "on 15.0 26.0"
  --set-humidity-offset <offset>
                        set humidity calibration offset (-20.0 … 20.0)
  --set-temperature-offset <offset>
                        set temperature calibration offset (-3.0 … 3.0)
  -j, --json            print in JSON format
  -l {DEBUG,INFO,WARN,ERROR}, --log {DEBUG,INFO,WARN,ERROR}
                        print logging information
```

## Scan for nearby devices and grab measurement

Scan for devices for 20 seconds
```
$ ./govee-api.py -s
MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery
A4:C1:38:68:41:23     GVH5075_4123  21.9°C       14.5°C     71.4°F       58.1°F     63.0%          12.2 g/m³      16.5 mbar       96%
A4:C1:38:5A:20:A1     GVH5075_20A1  22.0°C       13.9°C     71.6°F       57.0°F     60.3%          11.7 g/m³      15.9 mbar       95%
C3:30:38:12:34:56     GVH5105_3456  21.5°C       13.2°C     70.7°F       55.8°F     58.9%          11.4 g/m³      15.5 mbar       82%
 28 bluetooth devices seen
```

or even without any parameters:
```
$ ./govee-api.py
MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery
A4:C1:38:5A:20:A1     GVH5075_20A1  22.0°C       13.9°C     71.6°F       57.0°F     60.4%          11.7 g/m³      15.9 mbar       95%
A4:C1:38:68:41:23     GVH5075_4123  21.9°C       14.5°C     71.4°F       58.1°F     63.0%          12.2 g/m³      16.5 mbar       96%
```

The script automatically detects all supported device models from their BLE advertisements.

## Put ```.known_govees```-file to your home directory
To use friendly device names and request devices by name, place a ```.known_govees``` file in your home directory.

This file is crucial for accurate calibration when receiving advertisement data during measurement and scanning. Calibration data is not sourced from device configuration in these instances. Calibration data is only applied when querying measurement or historical data.

Example:
```
A4:C1:38:68:41:23 Bedroom 0.0 0.0
A4:C1:38:5A:20:A1 Livingroom 0.0 0.0
C3:30:38:12:34:56 Cellar 0.0 0.0
```

The meaning of columns is as follows:
1. MAC address
2. Alias
3. Offset / calibration for humidity
4. Offset / calibration for temperature

Afterwards you'll see the alias if you scan or grab measurements instead of the MAC address.

## Continuously grab measurements from nearby devices
```
$ ./govee-api.py -m
Timestamp             MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery
2023-09-19 13:42:37   Bedroom               GVH5075_4123  22.0°C       14.6°C     71.6°F       58.3°F     63.1%          12.3 g/m³      16.7 mbar       96%
2023-09-19 13:42:39   Bedroom               GVH5075_4123  21.9°C       14.5°C     71.4°F       58.1°F     63.1%          12.2 g/m³      16.6 mbar       96%
2023-09-19 13:42:41   Bedroom               GVH5075_4123  22.0°C       14.6°C     71.6°F       58.3°F     63.1%          12.3 g/m³      16.7 mbar       96%
2023-09-19 13:42:42   Livingroom            GVH5075_20A1  22.0°C       13.9°C     71.6°F       57.0°F     60.3%          11.7 g/m³      15.9 mbar       95%
```

End this by pressing CTRL+C.

## Request device information

For H5074 / H5075 / H5179 devices:
```
$ ./govee-api.py -a Bedr -i
Devicename:           GVH5075_4123
Address:              A4:C1:38:68:41:23
Manufacturer:         GV
Model:                H5075
Hardware-Rev.:        1.03.02
Firmware-Rev.:        1.04.06
Battery level:        15 %
Humidity alarm:       active, lower threshold: 40.0 %, upper threshold: 60.0 %
Temperature alarm:    active, lower threshold: 16.0 °C, upper threshold: 24.0 °C

Timestamp:            2025-01-05 09:02
Temperature:          19.9 °C / 67.8 °F
Rel. humidity:        46.6 %
Dew point:            8.1 °C / 46.6 °F
Abs. humidity:        8.0 g/m³
Steam pressure:       10.8 mbar
```

For H5105 devices (uses encrypted GATT with auth handshake):
```
$ ./govee-api.py -a Cellar -i
Devicename:           GVH5105_3456
Address:              C3:30:38:12:34:56
Hardware-Rev.:        3.01.00
Firmware-Rev.:        1.00.17
Battery level:        82 %
MAC / Serial:         C3:30:38:12:34:56, 1234
Temperature alarm:    active, lower threshold: 5.0 °C, upper threshold: 30.0 °C
Humidity alarm:       active, lower threshold: 30.0 %, upper threshold: 80.0 %
Temperature offset:   0.0 °C
Humidity offset:      0.0 %

Timestamp:            2025-01-05 09:02
Temperature:          21.5 °C / 70.7 °F
Rel. humidity:        58.9 %
Dew point:            13.2 °C / 55.8 °F
Abs. humidity:        11.4 g/m³
Steam pressure:       15.5 mbar
```

Note: The alias has been used. It works also if you just enter the first letters of the alias.

If you want to have the result in JSON format you can call it like this:
```
$ ./govee-api.py -a Bedr -j
{
  "name": "GVH5075_4123",
  "address": "A4:C1:38:68:41:23",
  "manufacturer": "GV",
  "model": "H5075",
  "hardware": "1.03.02",
  "firmware": "1.04.06",
  "battery": 15,
  "humidityAlarm": {
    "active": true,
    "lower": 40.0,
    "upper": 60.0
  },
  "temperatureAlarm": {
    "active": true,
    "lower": 16.0,
    "upper": 24.0
  },
  "humidityOffset": 0.0,
  "temperatureOffset": 0.0,
  "currentMeasurement": {
    "timestamp": "2025-01-05 09:03",
    "temperatureC": 19.9,
    "temperatureF": 67.9,
    "temperatureOffset": 0,
    "relHumidity": 46.6,
    "humidityOffset": 0,
    "absHumidity": 8.0,
    "dewPointC": 8.1,
    "dewPointF": 46.6,
    "steamPressure": 10.8
  }
}
```

Note: If you want to get device information you can also leave out the `-i` switch.

## Request historical data

### H5074 / H5075 / H5179 — `--data`

In this example recorded data of the last 10 minutes is requested.
```
$ ./govee-api.py -a Bedroom --data --start 0:10
Timestamp         Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure
2025-01-05 08:55  19.8°C       8.1°C     67.6°F       46.6°F     46.7%          8.0 g/m³      10.8 mbar
2025-01-05 08:56  19.8°C       8.1°C     67.6°F       46.6°F     46.7%          8.0 g/m³      10.8 mbar
2025-01-05 08:57  19.8°C       8.1°C     67.6°F       46.6°F     46.7%          8.0 g/m³      10.8 mbar
2025-01-05 08:58  19.8°C       8.1°C     67.6°F       46.6°F     46.7%          8.0 g/m³      10.8 mbar
2025-01-05 08:59  19.8°C       8.0°C     67.6°F       46.4°F     46.6%          8.0 g/m³      10.7 mbar
2025-01-05 09:00  19.8°C       8.0°C     67.6°F       46.4°F     46.6%          8.0 g/m³      10.7 mbar
2025-01-05 09:01  19.9°C       8.1°C     67.8°F       46.6°F     46.6%          8.0 g/m³      10.8 mbar
2025-01-05 09:02  19.9°C       8.1°C     67.8°F       46.6°F     46.5%          8.0 g/m³      10.8 mbar
2025-01-05 09:03  19.9°C       8.1°C     67.8°F       46.6°F     46.5%          8.0 g/m³      10.8 mbar
2025-01-05 09:04  19.9°C       8.1°C     67.8°F       46.6°F     46.5%          8.0 g/m³      10.8 mbar
2025-01-05 09:05  19.9°C       8.1°C     67.8°F       46.6°F     46.5%          8.0 g/m³      10.8 mbar
```

You can also specify a time window with `--start` and `--end`:
```
$ ./govee-api.py -a Bedroom --data --start 0:20 --end 0:10 -j
```

For the H5179 use the MAC address or alias directly:
```
$ ./govee-api.py -a "1C:9F:24:E2:AB:C6" --data --start 0:10
Timestamp         Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure
2025-03-18 18:57  6.4°C       5.3°C     43.5°F       41.5°F     92.7%          6.9 g/m³      8.9 mbar
2025-03-18 18:56  6.5°C       5.4°C     43.7°F       41.7°F     92.7%          7.0 g/m³      8.9 mbar
2025-03-18 18:55  6.5°C       5.4°C     43.7°F       41.7°F     92.8%          7.0 g/m³      8.9 mbar
2025-03-18 18:54  6.5°C       5.4°C     43.7°F       41.7°F     92.8%          7.0 g/m³      8.9 mbar
2025-03-18 18:53  6.5°C       5.4°C     43.7°F       41.7°F     92.8%          7.0 g/m³      8.9 mbar
2025-03-18 18:52  6.6°C       5.5°C     43.9°F       41.9°F     92.8%          7.0 g/m³      9.0 mbar
2025-03-18 18:51  6.6°C       5.5°C     43.9°F       41.9°F     92.8%          7.0 g/m³      9.0 mbar
2025-03-18 18:50  6.6°C       5.5°C     43.9°F       41.9°F     92.8%          7.0 g/m³      9.0 mbar
```

### H5105 — `--download N`

The H5105 uses an encrypted GATT connection with an auth handshake, so it has a separate flag. Pass the number of samples to download:
```
$ ./govee-api.py -a Cellar --download 10
Timestamp         Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure
2025-01-05 08:55  21.5°C       13.1°C     70.7°F       55.6°F     58.8%          11.4 g/m³      15.4 mbar
2025-01-05 08:56  21.5°C       13.2°C     70.7°F       55.8°F     58.9%          11.4 g/m³      15.5 mbar
2025-01-05 08:57  21.6°C       13.2°C     70.9°F       55.8°F     58.7%          11.4 g/m³      15.5 mbar
2025-01-05 08:58  21.6°C       13.3°C     70.9°F       55.9°F     58.9%          11.5 g/m³      15.5 mbar
2025-01-05 08:59  21.5°C       13.1°C     70.7°F       55.6°F     58.8%          11.4 g/m³      15.4 mbar
2025-01-05 09:00  21.5°C       13.1°C     70.7°F       55.6°F     58.7%          11.4 g/m³      15.4 mbar
2025-01-05 09:01  21.5°C       13.2°C     70.7°F       55.8°F     58.9%          11.4 g/m³      15.5 mbar
2025-01-05 09:02  21.6°C       13.2°C     70.9°F       55.8°F     58.8%          11.4 g/m³      15.5 mbar
2025-01-05 09:03  21.6°C       13.3°C     70.9°F       55.9°F     58.9%          11.5 g/m³      15.5 mbar
2025-01-05 09:04  21.5°C       13.1°C     70.7°F       55.6°F     58.8%          11.4 g/m³      15.4 mbar
```

The H5105 stores approximately 20 days of data at 1-minute intervals (up to 28800 samples).

## Configure device
To configure alarms and offset values (H5074 / H5075 / H5179 only):
```
$ ./govee-api.py -a Bedroom --set-humidity-alarm "on 40.0 60.0" --set-temperature-alarm "on 16.0 25.0" --set-humidity-offset 0.0 --set-temperature-offset 0.0
```

## Logging
If you want to get information about what's going over the air enable logging like this:
```
$ ./govee-api.py -a Bedroom --log DEBUG
INFO    A4:C1:38:68:41:23: Request to connect
INFO    A4:C1:38:68:41:23: Successfully connected
INFO    A4:C1:38:68:41:23: request device name
DEBUG   A4:C1:38:68:41:23: >>> read_gatt_char(00002a00-0000-1000-8000-00805f9b34fb)
DEBUG   A4:C1:38:68:41:23: <<< response data(47 56 48 35 30 37 35 5f 34 31 32 33)
INFO    A4:C1:38:68:41:23: received device name: GVH5075_4123
INFO    A4:C1:38:68:41:23: request configuration for humidity alarm
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2011, aa 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a9)
DEBUG   A4:C1:38:68:41:23: <<< received notification with device data(aa 03 01 a0 0f 70 17 00 00 00 00 00 00 00 00 00 00 00 00 60)
INFO    A4:C1:38:68:41:23: received configuration for humidity alarm: active, lower threshold: 40.0 %, upper threshold: 60.0 %
INFO    A4:C1:38:68:41:23: request configuration for temperature alarm
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2011, aa 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ae)
DEBUG   A4:C1:38:68:41:23: <<< received notification with device data(aa 04 01 40 06 c4 09 00 00 00 00 00 00 00 00 00 00 00 00 24)
INFO    A4:C1:38:68:41:23: received configuration for temperature alarm: active, lower threshold: 16.0 °C, upper threshold: 25.0 °C
INFO    A4:C1:38:68:41:23: request configuration for humidity offset
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2011, aa 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ac)
DEBUG   A4:C1:38:68:41:23: <<< received notification with device data(aa 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ac)
INFO    A4:C1:38:68:41:23: received configuration for humidity offset: 0.0 %
INFO    A4:C1:38:68:41:23: request configuration for temperature offset
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2011, aa 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ad)
DEBUG   A4:C1:38:68:41:23: <<< received notification with device data(aa 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ad)
INFO    A4:C1:38:68:41:23: received configuration for temperature offset: 0.0 °C
INFO    A4:C1:38:68:41:23: request hardware version
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2011, aa 0d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a7)
DEBUG   A4:C1:38:68:41:23: <<< received notification with device data(aa 0d 31 2e 30 33 2e 30 32 00 00 00 00 00 00 00 00 00 00 97)
INFO    A4:C1:38:68:41:23: received hardware version: 1.03.02
INFO    A4:C1:38:68:41:23: request firmware version
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2011, aa 0e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a4)
DEBUG   A4:C1:38:68:41:23: <<< received notification with device data(aa 0e 31 2e 30 34 2e 30 36 00 00 00 00 00 00 00 00 00 00 97)
INFO    A4:C1:38:68:41:23: received firmware version: 1.04.06
INFO    A4:C1:38:68:41:23: request current measurement and battery
DEBUG   A4:C1:38:68:41:23: >>> write_gatt_char(494e5445-4c4c-495f-524f-434b535f2012, aa 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ab)
DEBUG   A4:C1:38:68:41:23: <<< received notification after command (aa 01 07 df 12 16 0f 00 00 00 00 00 00 00 00 00 00 00 00 78)
INFO    A4:C1:38:68:41:23: received current measurement and battery level:
Timestamp:            2025-01-05 09:17
Temperature:          20.1 °C / 68.3 °F
Rel. humidity:        46.3 %
Dew point:            8.2 °C / 46.8 °F
Abs. humidity:        8.1 g/m³
Steam pressure:       10.9 mbar
Battery level:        15 %
Devicename:           GVH5075_4123
Address:              A4:C1:38:68:41:23
Manufacturer:         GV
Model:                H5075
Hardware-Rev.:        1.03.02
Firmware-Rev.:        1.04.06
Battery level:        15 %
Humidity alarm:       active, lower threshold: 40.0 %, upper threshold: 60.0 %
Temperature alarm:    active, lower threshold: 16.0 °C, upper threshold: 25.0 °C

Timestamp:            2025-01-05 09:17
Temperature:          20.1 °C / 68.3 °F
Rel. humidity:        46.3 %
Dew point:            8.2 °C / 46.8 °F
Abs. humidity:        8.1 g/m³
Steam pressure:       10.9 mbar
INFO    A4:C1:38:68:41:23: Request to disconnect
INFO    A4:C1:38:68:41:23: Successfully disconnected
```

## Usage in your python code
### Grab measurements from nearby devices
```python
def measure():

    def stdout_consumer(address: str, name: str, battery: int, measurement: Measurement) -> None:

        timestamp = measurement.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        label = (alias.aliases[address][0]
                 if address in alias.aliases else address) + " " * 21
        print(
            f"{timestamp}   {label[:21]} {name}  {measurement.temperatureC:.1f}°C       {measurement.dewPointC:.1f}°C     {measurement.temperatureF:.1f}°F       {measurement.dewPointF:.1f}°F     {measurement.relHumidity:.1f}%          {measurement.absHumidity:.1f} g/m³      {measurement.steamPressure:.1f} mbar       {battery}%", flush=True)

    print("Timestamp             MAC-Address/Alias     Device name   Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure  Battery", flush=True)
    asyncio.run(_scan_all(unique=False, duration=0, consumer=stdout_consumer))
```

### Request recorded data (H5074 / H5075 / H5179)
```python
async def recorded_data(address: str, start: int, end: int):

    try:
        device = GoveeThermometerHygrometer(address)
        await device.connect()
        measurements = await device.requestRecordedData(start=start, end=end)
        print("Timestamp         Temperature  Dew point  Temperature  Dew point  Rel. humidity  Abs. humidity  Steam pressure", flush=True)
        for m in measurements:
            timestamp = m.timestamp.strftime("%Y-%m-%d %H:%M")
            print(f"{timestamp}  {m.temperatureC:.1f}°C       {m.dewPointC:.1f}°C     {m.temperatureF:.1f}°F       {m.dewPointF:.1f}°F     {m.relHumidity:.1f}%          {m.absHumidity:.1f} g/m³      {m.steamPressure:.1f} mbar", flush=True)
    finally:
        await device.disconnect()
```

### Download historical data (H5105)
```python
async def download_h5105(address: str, n_samples: int):

    device = GoveeH5105(address)
    try:
        await device.connect()
        await device._auth_handshake()
        records = await device.downloadHistory(n_samples)
        for m in records:
            timestamp = m.timestamp.strftime("%Y-%m-%d %H:%M")
            print(f"{timestamp}  {m.temperatureC:.1f}°C       {m.dewPointC:.1f}°C     {m.temperatureF:.1f}°F       {m.dewPointF:.1f}°F     {m.relHumidity:.1f}%          {m.absHumidity:.1f} g/m³      {m.steamPressure:.1f} mbar", flush=True)
    finally:
        await device.disconnect()
```
