# Flashing and recovery

## Before flashing

1. Read the fitted ESP32-S3-WROOM-1U marking. Use the N8 image for 8 MB or the
   N4 image for 4 MB. Do not guess when programming production units.
2. Verify the selected file against `firmware/SHA256SUMS.txt`.
3. Do not burn eFuses as part of these procedures.

## Initial development upload

With factory-default USB eFuses, connect the PCB USB-A plug and identify the
ESP32-S3 USB Serial/JTAG port (`/dev/ttyACM*` on Linux). Then run:

```sh
pio run -e esp32-s3 -t upload --upload-port /dev/ttyACM0
```

Use `esp32-s3-4mb` for an N4 module. The current hardware documentation expects
USB Serial/JTAG automatic download; this must be tested on the prototype.

## Complete image

The merged image contains bootloader, partition table, boot_app0, and
application:

```sh
esptool --chip esp32s3 --port /dev/ttyACM0 \
  write-flash 0x0 firmware/VaultKey_revD_8MB_factory.bin
```

The application-only image is written at `0x10000` only when a matching
partition table is already installed:

```sh
esptool --chip esp32s3 --port /dev/ttyACM0 \
  write-flash 0x10000 firmware/VaultKey_revD_8MB_firmware.bin
```

## Normal updates after TinyUSB firmware is running

The application enumerates as TinyUSB CDC + HID. Arduino's CDC implementation
recognizes the uploader's control-line/1200-baud sequence, switches back to
USB Serial/JTAG, requests forced download boot, and restarts. The CDC port may
disappear and return with a different device identity during this operation.

This update path is application-dependent. It is not a substitute for ROM
recovery.

## ROM download recovery

The ESP32-S3 recovery sequence is:

1. Drive GPIO0/BOOT low.
2. Pulse EN low using RESET/SW5.
3. Release EN while GPIO0 remains low.
4. Release GPIO0 after the ROM downloader enumerates.
5. Flash a known-good complete image at offset `0x0`.

Rev-D has no BOOT switch or GPIO0 pad, so this procedure is currently blocked
without physically probing U1.27/R7. SW5 alone cannot force download mode.

For the next PCB revision, retain R7 and add labelled hidden pads for:

```text
GPIO0 / BOOT
EN / RESET
GND
USB D−
USB D+
```

GPIO0, EN, and GND are the minimum reliable recovery set. Place them where a
pogo fixture or recessed service opening can reach them.

## Factory reset is not firmware recovery

The OLED factory-reset menu deletes vault records, settings, and wrapped key
material. It preserves the bootloader and application. SW5 hardware reset
preserves all data. Neither operation repairs broken firmware.
