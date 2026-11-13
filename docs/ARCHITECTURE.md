# Firmware architecture

## Startup state machine

`Application` advances through explicit states:

```text
POWER_ON
  -> HARDWARE_INIT
  -> I2C_INIT
  -> DISPLAY_INIT
  -> RTC_CHECK
  -> STORAGE_INIT
  -> SECURITY_INIT
  -> USB_INIT
  -> UI_INIT
  -> LOCKED_HOME | FAULT
```

OLED, crypto, configuration, key metadata, and storage failures enter `FAULT`
without an intentional reboot loop. RTC failure is non-fatal but disables TOTP.
USB failure is non-fatal because the local vault remains usable. The loop task
watchdog is enabled before initialization.

## Runtime execution

The main loop is event driven:

```text
button debouncer -> fixed event queue -> UI state manager
RTC service --------------------------> UI/TOTP
CDC stream -> bounded JSON parser ----> application services
UI confirmation ----------------------> asynchronous HID sender
authentication -> key manager -> encrypted storage -> record managers
```

USB stack callbacks only update small volatile state flags. Button handling is
polled and contains no cryptography, display work, or flash writes. I²C, flash,
and cryptographic work runs in application context. Record sizes and protocol
lines are bounded.

## Module boundaries

- `hardware/`: physical GPIO, display, RTC, and USB implementation.
- `security/`: primitives, key envelope, authentication, and sealed storage.
- `vault/`: record models/codecs and credential operations.
- `authenticator/`: strict Base32/otpauth, HOTP/TOTP, and token operations.
- `usb/`: framing and validation of JSON Lines; application owns command policy.
- `interface/`: OLED rendering and physical authorization workflows.
- `core/`: startup, orchestration, settings, watchdog, and calendar conversion.

Display code never performs encryption. USB framing never owns keys. Storage
never renders UI. TOTP generation is independently host-testable.

## Lock transition

Every lock path—including idle timeout, long BACK, and CDC `LOCK_DEVICE`—uses
the same transition:

1. send a neutral HID report and erase pending HID text;
2. revoke provisioning and clear the CDC input buffer;
3. clear decrypted credential/TOTP indexes;
4. erase derived storage keys;
5. erase the in-RAM master key;
6. return the UI to the locked screen.

Hardware EN reset does not execute a wipe path. Persistent ciphertext and RTC
backup state remain intact.
