# Innovations introduced in this PR

1. **Dandelion++ Relay.** Transaction propagation with stem/fluff phases to
   reduce origin leakage and frustrate targeted mempool blocking.
2. **Address-agnostic Mempool Policy.** Admission is based only on validity and
   fee rate; there are no lists tied to addresses or scripts.
3. **Compact Serialization.** Simple varint encoder/decoder for network frames,
   reducing overhead compared to naive JSON where applicable.
4. **Performance knobs.** `orjson` when available (fallback to stdlib), optional
   `uvloop` to accelerate asyncio loops on Linux/macOS.
5. **Ops quality.** First-class Dockerfile, `docker-compose.yml`, and `devnet.sh`
   for one-command local multi-node networks.

## Future work

* SOCKS5/Tor/I2P support in the P2P dialer.
* Batch verification and signature aggregation where cryptographically sound.
* Better peer scoring and compact-block announcements.
