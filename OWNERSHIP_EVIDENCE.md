# AEGIS-Preflight — Ownership & Timestamp Evidence Record

This document records authorship, release identification, and point-in-time evidence for the AEGIS-Preflight project. It is provided as **supporting evidence** and does not, on its own, constitute legal proof of copyright. Legal protection is established by the applicable copyright law and the license terms in the repository.

---

## 1. Project Identification

| Field | Value |
|-------|-------|
| **Project name** | AEGIS-Preflight |
| **GitHub repository** | https://github.com/Roshan-Mallick/aegis-preflight-cli |
| **Original author & owner** | Roshan Mallick |
| **Copyright** | Copyright (c) 2026 Roshan Mallick |
| **License** | Apache License, Version 2.0 (see `LICENSE`) |
| **Authorship** | See `AUTHORS.md` |

## 2. Release Identification

| Field | Value |
|-------|-------|
| **Version** | v1.0.0 |
| **Release tag** | `v1.0.0` (annotated) |
| **Tag object SHA** | `5070b8596ed55ff5494abf7ae7c82e2d8ac9daa0` |
| **Tagged commit SHA** | `981588a8ec0161905fcbb03f96280229d2c9fa63` |
| **Git history** | Unrewritten; authoritative commit chain preserved |
| **Remote** | `origin` → `https://github.com/Roshan-Mallick/aegis-preflight-cli.git` |

## 3. Cryptographic Signing

The release tag and all releases were created with a GPG signature:

- **Signing key fingerprint:** `8539E166C2F01491E3E770074AAFEB9AE7F74E16`
- **Signer:** Roshan Mallick (ubuntu-gpg-key) <roshanmallick2025@gmail.com>
- **Tag verification:** `git tag -v v1.0.0` → `Good signature`
- **Status:** VERIFIED (signature present and verified locally)

> For third parties to verify the signature, the public key must be uploaded to a key server and associated with the GitHub account. Verification by GitHub on the web only works if the key is registered.

## 4. Source Archive

| Field | Value |
|-------|-------|
| **Archive filename** | `AEGIS-Preflight-v1.0.0.tar.gz` |
| **SHA-256** | `3b15f9c1dff919a3f6ce26eee78d7d785903cb9e308cf51da0d581ab294f7e08` |
| **Created from** | the exact tagged commit `981588a8ec0161905fcbb03f96280229d2c9fa63` (`git archive v1.0.0`) |
| **Contents** | Clean source tree: only tracked project files (source, tests, docs, README, LICENSE, AUTHORS, go.mod/go.sum, install.sh). No build artifacts, no `.env`, no secrets, no local session data, no temporary files. |

## 5. Timestamp Proof (OpenTimestamps)

| Field | Value |
|-------|-------|
| **OTS proof file** | `AEGIS-Preflight-v1.0.0.tar.gz.ots` |
| **Proof file size** | 665 bytes |
| **Client** | `opentimestamps-client` v0.7.2 (installed in a local venv: `python3 -m venv .ots-venv && .ots-venv/bin/pip install opentimestamps-client`) |
| **Proof content hash** | `3b15f9c1dff919a3f6ce26eee78d7d785903cb9e308cf51da0d581ab294f7e08` (matches the archive SHA-256) |
| **Calendars used** | a.pool.opentimestamps.org, b.pool.opentimestamps.org, a.pool.eternitywall.com, ots.btc.catallaxy.com |
| **Timestamp status** | Registered and submitted to calendars. Verification currently shows **pending confirmation in the Bitcoin blockchain** (pending the next Bitcoin block). Once confirmed, `ots verify` will report the proof as verified with the anchoring block. |
| **Verification command** | `ots verify AEGIS-Preflight-v1.0.0.tar.gz.ots` |

The archive hash `/ SHA-256` above is the value anchored by this OpenTimestamps proof. A timestamp anchors the existence of the exact archive content at a point in time; it does not by itself establish authorship.

> **PENDING / REQUIRES MANUAL ACTION:** To complete verification, run `ots verify AEGIS-Preflight-v1.0.0.tar.gz.ots` again after the next Bitcoin block confirms (typically confirmable within minutes to a day). Do not claim the timestamp is fully verified until it reports success.

## 6. Timeline Summary

| Event | Time (UTC) |
|-------|-----------|
| Tagged commit authored | 2026-08-28T08:55:33Z |
| Annotated tag `v1.0.0` created | 2026-08-28T08:55:38Z (14:25:38 +0530) |

---

*Generated for the record on 2026-08-28T08:56:34Z by the author.*
