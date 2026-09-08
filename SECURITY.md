# Security policy

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's private vulnerability reporting for this repository: open the **Security** tab and choose **Report a vulnerability**. The report stays private until an advisory is published.

Include what you can of: the affected crate and version or commit, how to reproduce, and what an attacker gains.

## Scope

This repository holds the daemonseed protocol, its clients, and its DHT transport. The cryptographic primitives (ML-KEM, ML-DSA, AES-GCM, SHA-2, HKDF) come from the `oxicrypt` crates, which have their own repository at <https://github.com/oxiforge/oxicrypt>; report a defect in a primitive there.

## Supported versions

daemonseed is alpha software. Only the current release, named in `README.md` under **Status**, receives fixes.
