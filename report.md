# VAULTKEY FIRMWARE REPORT

Test date: 2026-11-13  
Source folder: `/home/rootx/Projects/VaultKey_Firmware`  
Hardware connected during this run: **NO**

```text
VAULTKEY FIRMWARE REPORT

BUILD
  Compilation (8 MB): PASS
  Compilation (4 MB): PASS
  Firmware binary: YES
  Factory merged images: YES
  Source complete: YES

HARDWARE
  GPIO mapping verified from schematic/netlist: YES
  OLED driver/controller verified from schematic: YES
  OLED physical initialization: NOT RUN
  DS1307 communication: NOT RUN
  Button drivers: BUILD PASS; PHYSICAL TEST NOT RUN
  Automatic USB-power startup: NOT RUN
  EN reset persistence: NOT RUN

TIME
  Calendar/Unix conversion: PASS (native tests)
  RTC reading: NOT RUN
  RTC write/BCD/CH handling: BUILD PASS; HARDWARE TEST NOT RUN
  RFC 6238 TOTP accuracy: PASS (SHA-1/SHA-256/SHA-512 official vectors)
  RFC 4226 HOTP accuracy: PASS (official vectors)

SECURITY
  PIN authentication: BUILD PASS; DEVICE TEST NOT RUN
  AES-256-GCM known-answer test: PASS (native)
  GCM tamper rejection/output clearing: PASS (native)
  PBKDF2-HMAC-SHA256 known-answer test: PASS (native)
  HKDF-SHA256 RFC 5869 known-answer test: PASS (native)
  Encrypted record codec: PASS (native)
  Persistent storage: BUILD PASS; POWER-LOSS TEST NOT RUN
  Secure wipe: BUILD PASS; FLASH TEST NOT RUN

USB
  TinyUSB CDC interface: BUILD PASS; ENUMERATION NOT RUN
  TinyUSB HID keyboard: BUILD PASS; ENUMERATION NOT RUN
  Composite operation: BUILD PASS; HOST TEST NOT RUN
  Normal application-triggered flashing: NOT RUN
  ROM recovery: BLOCKED BY REV-D GPIO0 ACCESS

UI
  Navigation: BUILD PASS; PHYSICAL TEST NOT RUN
  Credential screen: BUILD PASS; DISPLAY TEST NOT RUN
  TOTP screen: BUILD PASS; DISPLAY TEST NOT RUN
  Settings: BUILD PASS; DISPLAY TEST NOT RUN

UNRESOLVED ISSUES:
  1. No physical rev-D board was attached, so no hardware-dependent item can
     honestly be marked PASS.
  2. Rev-D has no BOOT switch or GPIO0 test pad. Reliable ROM recovery from a
     broken TinyUSB application is not guaranteed.
  3. The fitted WROOM-1U flash capacity is unknown; separate N8 and N4 images
     are supplied and the module marking must be checked before flashing.
  4. USB enumeration, CDC, HID typing, keyboard layouts, reconnect, and normal
     upload must be tested on Linux, Windows, and macOS.
  5. DS1307 oscillator, CR2032 retention, drift, BCD edge cases, and I2C level
     translation require physical measurement.
  6. LittleFS atomic-update recovery needs deliberate power interruption tests.
  7. Firmware has not received an independent security audit. ESP32 secure
     boot, flash encryption, and NVS encryption remain deliberately disabled.
  8. D1 is power-only, so requested programmable LED patterns are impossible
     on rev-D.
  9. Long credential text and otpauth secrets are provisioned/edited through
     authorized CDC; the four-button UI browses, reveals, types, and deletes
     records but does not provide a practical full text editor.
```

## Commands executed

```sh
pio test -e native
pio run -e esp32-s3
pio run -e esp32-s3-4mb
```

Native result: **10 tests passed** after adding RFC 4226, malformed otpauth,
and TOTP record-corruption coverage. Re-run `pio test -e native` to reproduce
the current count and detailed line-by-line output.

## Acceptance status

This is a compile-verified, algorithm-tested **first physical prototype
candidate**, not a production-approved device. The specification's final
acceptance criteria explicitly require actual hardware and host tests; those
remain open rather than being represented as successful.
