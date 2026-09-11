# SNMP read-tier arm

This stdlib-only arm sends one SNMPv2c GET datagram containing one to three allowlisted identity OIDs: `sysDescr.0`, `sysUpTime.0`, and `sysName.0`. It performs no walk, set, retry, subprocess, or follow-on request. The target must be explicitly authorized with `SNMP_READTIER_SCOPE`.

`probe` requires explicit `host`, `community`, `oids`, and `timeout_ms`; `port` defaults to 161. `DEFAULT_COMMUNITY` is `public` because that is the documented lab example, but the value is never silently inserted for a probe: callers must pass it. Receipts hash rather than echo the community.

A timeout is reported as `udp_no_response`, not as proof that the service is absent or that a community is wrong. Agents commonly drop wrong-community requests, so those cases are observationally identical. A response carrying a different community and malformed packets are separately recorded. Each OID row carries status, decoded value when available, and the SHA-256 digest of the shared raw response. The receipt also binds normalized arguments, request bytes, and the result envelope.

`data/demo-response.hex` is a tiny deterministic parser/demo fixture and is not live service data.
