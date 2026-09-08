# NOTICE — rpz-decoder

This arm ships **no zone data**. It decodes Response Policy Zone
(ThreatStop) AXFR dumps supplied by the operator at invocation time.

- Zone content originates from the operator's licensed ThreatStop
  subscription (device credential). The upstream Terms of Service on
  redistribution were not verified this session; the arm is designed
  for the operator's own consumption, not republication.
- The decoder implements the public RPZ trigger layout
  (draft-vixie-dnsop-dns-rpz-00) plus the modern nibble form for
  IPv6; it carries no vendor code.
- The repo holds no account identifiers, zone names, or TSIG
  material: the zone and master come from invocation args or the
  RPZDECODER_ZONE / RPZDECODER_MASTER environment variables, and the
  TSIG key pair is read at fetch time from a 0600 key file.
