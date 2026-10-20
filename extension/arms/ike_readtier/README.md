# IKE read-tier arm

This stdlib-only arm sends one fixed IKEv1 main-mode SA proposal to operator-selected UDP ports (default 500). Port 4500 uses the NAT-T non-ESP marker. The proposal is AES-256, SHA-1, pre-shared-key authentication, and MODP-2048.

The initiator cookie is generated locally with `secrets` and is bounded to eight bytes. The packet contains no key, nonce, identity, vendor, certificate, or KE payload. This MVP can prove responder presence and report an exact negotiated-capability echo; it cannot establish keys or authenticate either party. There is one datagram and no retry per selected port.

A timeout is `udp_no_response`, never evidence of absence. The result reports connection refusal, malformed replies, responder cookies, request/reply digests, and per-port outcomes.

`ports` accepts operator-selected UDP ports and defaults to `[500]`; `timeout_ms` bounds each probe. `data/demo-reply.hex` contains deterministic fake parser/demo bytes.

The reply parser tolerates benign trailing payloads (Notify / Vendor ID) that real responders append: it records their types in `trailing_payload_types` rather than rejecting a live responder, and a reply without an exact SA echo still proves presence while reporting `negotiation_complete=false`.
