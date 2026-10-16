# IKE read-tier arm

This stdlib-only arm sends one fixed IKEv1 main-mode SA proposal to UDP 500 and, only when explicitly requested, UDP 4500 with the NAT-T non-ESP marker. The proposal is AES-256, SHA-1, pre-shared-key authentication, and MODP-2048. `IKE_READTIER_SCOPE` must explicitly authorize the target.

The initiator cookie is generated locally with `secrets` and is bounded to eight bytes. The packet contains no key, nonce, identity, vendor, certificate, or KE payload. This MVP can prove responder presence and report an exact negotiated-capability echo; it cannot establish keys or authenticate either party. There is one datagram and no retry per selected port.

A timeout is `udp_no_response`, never evidence of absence. Connection refusal, malformed replies, responder cookies, request/reply digests, and per-port outcomes are recorded honestly. The custody receipt binds normalized arguments and the result envelope.

`ports` may only be `[500]` or `[500, 4500]` and defaults to `[500]`; `timeout_ms` is bounded. `data/demo-reply.hex` contains deterministic fake parser/demo bytes.

The reply parser tolerates benign trailing payloads (Notify / Vendor ID) that real responders append: it records their types in `trailing_payload_types` rather than rejecting a live responder, and a reply without an exact SA echo still proves presence while reporting `negotiation_complete=false`.
