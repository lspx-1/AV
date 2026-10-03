# Licensing API

Bastion works fully offline with **signed license files**. A license server is optional. When you
enter its URL under *Einstellungen → Erweitert → Lizenzserver*, Bastion activates, validates and
deactivates license keys online. This document describes what that server has to implement.

## Concepts

| Term | Meaning |
|---|---|
| **License key** | What the customer types: `BSTN-XXXX-XXXX-XXXX-XXXX` (Crockford Base32, last character is a checksum). It is only an identifier. |
| **License token** | The signed license: `base64url(json) + "." + base64url(signature)`. Bastion only accepts tokens signed with the private key that belongs to the public key built into the app. |
| **Device ID** | 16 hex characters, a hash of the Windows MachineGuid. Stable per Windows installation, contains no personal data. |
| **Seats** | How many devices may use a key at the same time. |

## Signing

* Algorithm: **ECDSA P-256 with SHA-256**, signature in IEEE P1363 format (64 bytes, `r || s`).
* Payload: UTF-8 JSON of the license document, camelCase, enums as strings.
* The server signs with the private key created by `bastion-keygen init` (`keys/license-private.pem`).
  Reuse `LicenseCodec.Sign` from `Bastion.Core` if the server is written in .NET.

### License document

```json
{
  "version": 1,
  "licenseId": "8f0c…",
  "key": "BSTN-7Q4M-2D9K-P1XA-K2XR",
  "plan": "Pro",
  "licensee": "Max Muster",
  "email": "max@example.com",
  "seats": 3,
  "issuedAt": "2026-10-03T10:00:00+00:00",
  "expiresAt": "2027-10-03T10:00:00+00:00",
  "deviceId": "9f3ca1e0b2c4d6e8",
  "activatedSeats": 1,
  "features": ["scheduled-scans", "custom-rules", "hourly-updates"]
}
```

* `deviceId` **must** be set for tokens returned by the server, so a token copied to another PC is rejected.
* `expiresAt` may be `null` for lifetime licenses.
* `features` empty means "all Pro features".

## Endpoints

All endpoints are `POST`, JSON in and out, under `{baseUrl}/api/v1/licenses/`. Use HTTPS.
Every response has this shape (also for errors, with an appropriate HTTP status):

```json
{ "ok": true, "token": "<license token or null>", "status": "active", "message": null }
```

`status` is one of `active`, `revoked`, `expired`, `unknown`, `deactivated`, `seats_exhausted`.
`message` is shown to the user as is, so write it in plain German.

### `POST /activate`

```json
{ "key": "BSTN-…", "deviceId": "9f3ca1e0b2c4d6e8", "deviceName": "DESKTOP-LH24", "appVersion": "0.1.0" }
```

* Unknown key → `ok: false`, `status: "unknown"`, message e.g. *"Diesen Lizenzschlüssel gibt es nicht."*
* All seats used by other devices → `ok: false`, `status: "seats_exhausted"`.
* Device already activated → return a fresh token (idempotent).
* Success → store the activation (key, deviceId, deviceName, time) and return a token bound to `deviceId`.

### `POST /validate`

Called once a day and when the user clicks *Status prüfen*.

```json
{ "key": "BSTN-…", "deviceId": "9f3ca1e0b2c4d6e8", "appVersion": "0.1.0" }
```

* Still valid → `ok: true` with a fresh token (lets you extend expiry or change seats).
* Revoked, refunded or device removed in the admin tool → `ok: false`, `status: "revoked"` or `"deactivated"`.
  Bastion then switches the device back to Free.
* If the server cannot be reached, Bastion keeps the license working for **30 days**.

### `POST /deactivate`

```json
{ "key": "BSTN-…", "deviceId": "9f3ca1e0b2c4d6e8" }
```

Free the seat. Always answer `ok: true` (also if the activation did not exist).

## Offline licenses

Without a server, create a license file and send it to the customer:

```bash
dotnet run --project tools/Bastion.KeyGen -- issue --name "Max Muster" --email max@example.com --seats 3 --days 365
```

The customer imports it on the license page (*Lizenzdatei importieren*). Offline files can be bound to one
device with `--device <Geräte-ID>` (the ID is shown at the bottom of the license page).

## Suggested server data model

```
licenses(id, key UNIQUE, plan, licensee, email, seats, issued_at, expires_at, revoked_at, notes)
activations(id, license_id, device_id, device_name, app_version, activated_at, last_seen_at, deactivated_at)
```

An admin tool needs: create license (generate key with `LicenseKey.Generate()`), list/search, revoke,
remove a device activation, and see last-seen dates.

## Security notes

* Keep the private key off the repository. `keys/` is in `.gitignore`.
* Rate-limit `activate` per IP and per key to stop key guessing (80 random bits make guessing impractical, but limits are cheap).
* Bastion is open source: anyone can remove the license check and build their own copy. Licensing
  is a way to support the project and unlock convenience features, not copy protection.
