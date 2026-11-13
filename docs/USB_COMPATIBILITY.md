# USB architecture and compatibility

## Physical path

The fabricated netlist verifies:

```text
J1.2 D− -> USB_DM -> U5.3/U5.4 -> U1.13 -> GPIO19 / USB_D−
J1.3 D+ -> USB_DP -> U5.1/U5.6 -> U1.14 -> GPIO20 / USB_D+
```

U5 is the USBLC6-2SC6 ESD array. There is no external USB-UART bridge and no
second connector.

## Implemented runtime architecture

The firmware builds with:

```text
ARDUINO_USB_MODE=0
ARDUINO_USB_CDC_ON_BOOT=0
```

It explicitly starts the ESP32-S3 USB-OTG peripheral using Arduino's TinyUSB
device stack and registers these interfaces before enumeration:

- CDC-ACM serial
- HID boot keyboard

The result is one composite USB device on the single USB-A plug. CDC and HID
are both TinyUSB interfaces; the fixed USB Serial/JTAG CDC is not part of this
composite device. The prototype uses Espressif's default VID/PID `303A:0002`.
Production distribution requires an appropriate VID/PID policy.

The descriptor declares a bus-powered device. No USB PHY-selection eFuse is
burned or changed.

## Shared PHY consequence

ESP32-S3 USB Serial/JTAG and USB OTG share one internal full-speed PHY. Only
one controller can own it at a time. Runtime TinyUSB therefore disables use of
the fixed-function USB Serial/JTAG interface until the device returns to the
ROM downloader. An external PHY is unnecessary for the chosen composite
device because TinyUSB itself provides both CDC and HID.

## Flashing behavior

1. **Factory/initial flash:** with default eFuses, ESP32-S3 USB Serial/JTAG can
   accept an `esptool` upload on GPIO19/20.
2. **Normal subsequent flash:** Arduino TinyUSB CDC recognizes the upload
   control-line/1200-baud sequence, switches the PHY back to USB Serial/JTAG,
   sets forced download boot, and restarts. This path depends on healthy
   application firmware and working USB descriptors.
3. **ROM recovery:** hold GPIO0 low while pulsing EN low, then release GPIO0 and
   flash the ROM downloader over the same USB data pair.

## Verified limitation

Rev-D does not expose GPIO0. If firmware fails before TinyUSB starts, has bad
descriptors, reconfigures GPIO19/20, or enters a reset loop, normal automatic
flashing may be unavailable. SW5 alone only resets EN while R7 keeps GPIO0
high, so it boots the same application again.

Reliable recovery is therefore **not physically testable or guaranteed on the
current board**. Add hidden GPIO0, EN, and GND pads (or a recessed BOOT switch)
before calling the hardware production-recoverable. No D+/D− reroute is needed.

## Host validation still required

Enumeration and upload must be tested on the physical board on Linux, Windows,
and macOS. Compilation proves that both TinyUSB interfaces and descriptors are
linked, but it does not prove signal integrity, host enumeration, keyboard
layout behavior, or ROM recovery.
