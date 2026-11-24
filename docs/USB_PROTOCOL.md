# VaultKey USB CDC protocol v1

VaultKey uses UTF-8 JSON Lines: one JSON object followed by LF (`\n`) per
request and response. The maximum input line is 2048 bytes. Baud-rate settings
are ignored by USB CDC, although terminals may display 115200.

## Envelope

Request:

```json
{"v":1,"id":"client-1","cmd":"HELLO"}
```

Successful response:

```json
{"v":1,"id":"client-1","product":"VaultKey","firmware":"0.1.0-prototype","hardware":"rev-E","protocol":1,"ok":true}
```

Error response:

```json
{"v":1,"id":"client-1","ok":false,"error":"device_locked"}
```

`id` is optional and is copied to the response for correlation. Unknown
commands and malformed fields fail closed.

## Authorization states

These commands are available while locked:

- `HELLO`
- `GET_VERSION`
- `GET_STATUS`
- `GET_TIME` (fails when RTC time is invalid)
- `LOCK_DEVICE`

All other commands require both:

1. a successful PIN unlock on the physical device; and
2. an open CDC connection; and
3. **USB Functions → Authorize CDC 5 min** selected on the physical device.

Authorization expires after five minutes, USB unmount/disconnect, lock, reset,
or manual revocation. Merely connecting a host never authorizes provisioning.

## Commands

### `GET_STATUS`

Returns real lock, RTC, storage, USB mount, CDC, HID, and provisioning state.
Entry counts are returned only during an authorized provisioning window.

### `GET_TIME`

Returns the validated DS1307 UTC Unix timestamp:

```json
{"v":1,"cmd":"GET_TIME"}
```

### `SET_TIME`

Authorized command. `unix` must convert to a valid DS1307 calendar year in
2000–2099. It is written as UTC; display timezone does not alter TOTP time.

```json
{"v":1,"cmd":"SET_TIME","unix":1794528000}
```

### `LIST_SERVICES`

Authorized command. Returns credential service names and TOTP issuer/account
labels, never usernames, passwords, notes, or secret keys. Optional `query`
filters labels case-insensitively. `offset` defaults to 0 and `limit` defaults
to 20 with a maximum of 25; totals are returned for bounded pagination.

```json
{"v":1,"cmd":"LIST_SERVICES","query":"git","offset":0,"limit":20}
```

### `ADD_CREDENTIAL`

Authorized command. Required fields are `service` and non-empty `password`.
`username`, `url`, and `notes` are optional.

```json
{"v":1,"cmd":"ADD_CREDENTIAL","service":"Example","username":"user@example.test","password":"<password>","url":"https://example.test","notes":"optional"}
```

The response contains only the new `entry_id`.

### `UPDATE_CREDENTIAL`

Authorized command. Requires `entry_id` and a complete replacement set of the
same fields as `ADD_CREDENTIAL`. The old authenticated record is replaced
atomically with a fresh GCM nonce.

### `ADD_TOTP`

Authorized command. Imports an RFC-style `otpauth://totp/` URI:

```json
{"v":1,"cmd":"ADD_TOTP","uri":"otpauth://totp/Issuer%3Aaccount?secret=<BASE32>&issuer=Issuer&algorithm=SHA1&digits=6&period=30"}
```

Supported algorithms are SHA1, SHA256, and SHA512; digits are 6 or 8; periods
are 15–300 seconds. The parser rejects malformed Base32, duplicate parameters,
unsupported algorithms, invalid periods/digits, and mismatched issuers.

### `DELETE_ENTRY`

Authorized command. The five-minute authorization is the physical
confirmation boundary for CDC provisioning operations. On-device deletion has
an additional two-second SELECT hold.

```json
{"v":1,"cmd":"DELETE_ENTRY","type":"credential","entry_id":1234}
```

`type` is `credential` or `totp`.

### `LOCK_DEVICE`

Immediately cancels HID transmission, revokes provisioning, clears decrypted
state, and locks the vault. It is accepted even if already locked.

## Common errors

```text
invalid_json
line_too_long
unsupported_protocol
missing_command
unknown_command
device_locked
provisioning_not_authorized
rtc_time_invalid
invalid_time
invalid_query
invalid_pagination
invalid_credential
invalid_uri
invalid_totp
entry_not_found
invalid_entry_type
storage_failed
delete_failed
```

Requests and secrets are never printed to a diagnostic log. The mutable input
line is erased after each request.
