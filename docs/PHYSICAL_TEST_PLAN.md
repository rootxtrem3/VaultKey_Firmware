# First-prototype physical test plan

Do not promote the firmware from prototype candidate until every applicable
item is recorded with board serial number, firmware hash, host OS, and result.

## Power, boot, and reset

1. Insert USB with no buttons held; confirm automatic boot and startup screen.
2. Measure 5 V and 3.3 V rails and observe EN rise.
3. Create a PIN and records, press recessed SW5, and confirm all data remains.
4. Remove USB with CR2032 fitted, wait, reconnect, and verify RTC continuity.
5. Repeat unexpected resets during list display, TOTP display, provisioning,
   encryption, and record update. No reset may trigger factory wipe.

## Buttons and UI

- Capture at least 100 presses per button; check missed/duplicate events.
- Test short press, 700 ms long press, UP/DOWN repeat, and two-second BACK lock.
- Press combinations and verify no unintended factory reset or HID action.
- Visit every screen with empty, one-entry, full-page, and maximum-length data.
- Verify clipping, password auto-hide, cancellation, inactivity lock, and error
  screens.

## OLED/I²C

- Confirm SSD1306 acknowledgement at `0x3C` and DS1307 at `0x68` at 100 kHz.
- Verify GPIO13 reset and every contrast setting.
- Disconnect/replace each peripheral and ensure the UI reports real failure
  without a reboot loop or fabricated state.
- Inspect SDA/SCL levels on both sides of PCA9306.

## RTC

- Read/write UTC across leap day, month/year rollover, midnight, and 12/24-hour
  encoded register cases.
- Set CH, invalid BCD, impossible dates, and missing crystal conditions; TOTP
  must remain unavailable.
- Measure backup retention and DS1307 drift over an appropriate interval.
- Verify display timezone never changes the TOTP result.

## TOTP

- Compare SHA-1, SHA-256, and SHA-512 tokens against an independent tool at
  period boundaries, including leading-zero values and six/eight digits.
- Unplug/reconnect around a boundary and verify the RTC-derived result.
- Import malformed and valid otpauth URIs; no partial record may remain.

## Storage/security

- Inspect raw NVS/LittleFS and confirm no plaintext PIN, password, username,
  notes, or TOTP secret is visible.
- Interrupt power before/during/after temporary write, record rename, manifest
  rename, deletion, PIN change, and factory reset.
- Corrupt ciphertext, tag, header, manifest, envelope, and record length.
  Firmware must fail closed and never display partial plaintext.
- Exercise lockout across EN reset and RTC-valid/invalid transitions.
- Confirm lock and factory reset clear all application-visible plaintext.
- Benchmark the stored PBKDF2 iteration count and unlock latency on hardware.

## USB by operating system

For Linux, Windows, and macOS:

- Confirm one composite device with CDC and HID interfaces.
- Open/close CDC repeatedly; verify connection status is real.
- Exercise every JSON command, malformed input, maximum line, disconnect during
  command, and expired/revoked authorization.
- Verify no sensitive response is available while locked.
- Test every supported keyboard layout in a plain text editor.
- Confirm each authorized string is sent once, BACK cancels, lock sends a
  neutral report, and reconnect never triggers typing.
- Test initial upload, healthy-app update, disconnect/reconnect, and ROM
  recovery using proper GPIO0 access.

## Acceptance record

Update `docs/TEST_REPORT.md` only with observed results. “Build PASS” must never
be converted to “hardware PASS” without a board test.
