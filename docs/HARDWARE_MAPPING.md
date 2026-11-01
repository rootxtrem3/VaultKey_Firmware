# VaultKey rev-D hardware mapping

This mapping was extracted from the actual files in
`/home/rootx/Projects/VaultKey_USB`, principally `VaultKey_USB.kicad_sch`,
`VaultKey_USB.kicad_pcb`, `fabrication/reports/VaultKey_USB.net`, and
`generator/design.py`. It is not based on an ESP32-S3 development board.

## ESP32-S3 assignments

| Function | Net | ESP32-S3 GPIO | U1 module pad | Electrical behavior |
|---|---|---:|---:|---|
| SELECT | `SW_SELECT` | 4 | 4 | Active-low switch to GND; firmware pull-up |
| DOWN | `SW_DOWN` | 5 | 5 | Active-low switch to GND; firmware pull-up |
| BACK | `SW_BACK` | 6 | 6 | Active-low switch to GND; firmware pull-up |
| UP | `SW_UP` | 7 | 7 | Active-low switch to GND; firmware pull-up |
| OLED/low-side I²C SDA | `OLED_SDA` | 8 | 12 | 4.7 kΩ pull-up to 3.3 V |
| OLED/low-side I²C SCL | `OLED_SCL` | 9 | 17 | 4.7 kΩ pull-up to 3.3 V |
| OLED reset | `OLED_RST` | 13 | 21 | Dedicated reset output |
| USB D− | `USB_DM` | 19 | 13 | Native USB D− through U5 |
| USB D+ | `USB_DP` | 20 | 14 | Native USB D+ through U5 |
| Boot strap | `BOOT` | 0 | 27 | R7 10 kΩ pull-up; no switch/test pad on rev-D |
| Chip enable/reset | `EN` | — | 3 | R6 10 kΩ pull-up, C7 100 nF to GND, SW5 to GND |

## Display

- **DS1:** Adafruit SSD1306 1.3-inch I²C breakout
- **Controller:** SSD1306, as named by the schematic symbol and footprint
- **Resolution:** 128×64 monochrome
- **I²C address used by firmware:** `0x3C`
- **Reset:** GPIO13 / `OLED_RST`
- **Power:** breakout VIN is on +5 V; I²C signals remain on the 3.3 V side

The controller, resolution, and footprint are schematic-verified. Address and
actual fitted module still require confirmation on the physical prototype.

## RTC and actual I²C topology

There is one ESP32 I²C controller and one logical bus, operated at 100 kHz:

```text
ESP32 GPIO8/9 --- OLED_SDA/SCL ---+--- SSD1306 DS1 (3.3 V side)
                                  |
                                  +--- PCA9306 U4 --- RTC_SDA/SCL --- DS1307 U2
                                       3.3 V side       5 V side       0x68
```

- U4 pad 4/3 connects to `OLED_SDA`/`OLED_SCL`.
- U4 pad 5/6 connects to `RTC_SDA`/`RTC_SCL`.
- R1/R2 pull the low side to 3.3 V; R3/R4 pull the RTC side to 5 V.
- DS1307 address is fixed at `0x68`.
- X1 is 32.768 kHz; BT1 is the CR2032 backup source.
- DS1307 is limited to standard-mode I²C, so firmware fixes the bus at 100 kHz.

## Startup, reset, and BOOT

- USB VBUS feeds +5 V through F1; U3 generates 3.3 V.
- R6/C7 allow EN to rise automatically, so firmware starts on USB insertion.
- SW5 is the recessed EN-to-GND hardware reset. It never maps to a GPIO and
  firmware does not interpret it as factory reset.
- The current rev-D PCB has **no SW6 BOOT switch** despite the older component
  list in the specification. `BOOT`/GPIO0 only connects to U1.27 and R7.
- Consequently, a broken USB-OTG application cannot be guaranteed recoverable
  without physically accessing GPIO0. A future PCB revision should add hidden
  GPIO0, EN, and GND programming pads or a recessed GPIO0-to-GND switch.

## Other verified absences

- D1 is a green **power LED wired to the 3.3 V rail**, not an MCU output.
- There is no RGB/WS2812 LED.
- There is no RTC interrupt connection.
- There is no buzzer.

Firmware represents the LED as explicitly unavailable and never claims to
produce programmable status patterns on rev-D.
