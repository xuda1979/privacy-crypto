# Privacy & Censorship Resistance

This document summarises how the system maintains on-chain privacy and how the
new P2P relay improves metadata protection and anti-censorship properties.

## On-chain privacy (already present in the prototype)

1. **Stealth Addresses.** Recipients use one-time addresses, unlinking payments
   from long-lived public identifiers.
2. **Pedersen Commitments + Range Proofs.** Amounts remain hidden while value
   conservation holds (inputs = outputs + fee).
3. **Linkable Ring Signatures with Key Images.** The spender is computationally
   indistinguishable within a ring; key images prevent double-spends.

> These mechanisms are implemented in the existing codebase and remain unchanged.

## Network-layer privacy (added)

### Dandelion++

Each transaction is first forwarded along a *stem* path comprised of randomly
chosen peers for a small number of hops, then *fluffed* (broadcast) to the
network. This reduces the reliability of “first-spotted-by” heuristics which
attempt to deanonymise the origin node.

### Encrypted Peer Pipes

All WebSocket peer channels are wrapped in a NaCl `Box` (X25519 + XSalsa20-Poly1305).
The handshake exchanges ephemeral public keys before switching to encrypted frames.

## Censorship resistance

* **No admin keys.** The consensus rules depend only on cryptographic validity;
  there is no privileged key capable of freezing outputs or rejecting valid transactions.
* **Mempool admission policy.** The relay only considers (a) validity checks and
  (b) minimal fee-rate thresholds. There is no address blocklist/allowlist logic.
* **Randomised routing.** Dandelion++ limits targeted blocking by making origin
  inference and transaction interception harder.

## Threat model and limitations

* Dandelion++ reduces but does not eliminate network-layer correlation attacks.
* Availability depends on node diversity; if most peers are adversarial, censorship
  is still possible in practice despite the protocol not supporting freezes.
* This is a prototype. No third-party audits have been performed.
