# SNMP read-tier arm

This stdlib-only arm sends bounded SNMP identity GETs containing one to three allowlisted OIDs: `sysDescr.0`, `sysUpTime.0`, and `sysName.0`. It supports SNMPv2c and SNMPv3 USM (`noAuthNoPriv`, authentication with MD5/SHA-1/SHA-256, and DES-CBC or AES-128-CFB privacy). It performs no walk, set, retry, subprocess, or follow-on request beyond the SNMPv3 authoritative-engine discovery exchange. The target must be explicitly authorized with `SNMP_READTIER_SCOPE`.

`probe` always requires explicit `host`, `oids`, and `timeout_ms`; `port` defaults to 161. Without `user`, it uses SNMPv2c and requires an explicit `community`. With `user`, it uses SNMPv3; authentication and privacy default to `none`, and enabled protocols require their corresponding passwords. Receipts hash rather than echo communities, usernames, or passwords.

A timeout is reported as `udp_no_response`, not as proof that the service is absent or that credentials are wrong. A response carrying a different v2c community, a v3 response with a bad USM authenticator, and malformed packets are separately recorded. Each OID row carries status, decoded value when available, and the SHA-256 digest of the shared raw response. The receipt binds the protocol version, normalized arguments, final GET bytes, and result envelope.

`data/demo-response.hex` is a tiny deterministic v2c parser/demo fixture and is not live service data.
