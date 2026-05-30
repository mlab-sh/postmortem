# Fixtures

These fixtures emulate **real public supply-chain attacks** with INERT payloads — the
patterns trip postmortem's detectors but execute nothing. No real malicious bytecode is
included; the strings/structures are reproductions of publicly documented incidents.

| Fixture | Models | Reference |
|---|---|---|
| `malicious-node/` | `event-stream@3.3.6` → `flatmap-stream@0.1.1` (Nov 2018 npm compromise targeting Copay BTC wallet) | https://github.com/dominictarr/event-stream/issues/116 |
| `malicious-python/` | `ctx@0.2.6` (May 2022 PyPI takeover — exfiltrated AWS creds via `setup.py`) | https://blog.sonatype.com/pypi-ctx-and-php-phpass-libraries-hijacked-in-supply-chain-attack |
| `malicious-rust/` | `rustdecimal` (May 2022 typosquat of `rust_decimal`) | https://blog.rust-lang.org/2022/05/10/malicious-crate-rustdecimal.html |
| `clean-node/` | benign sanity baseline | — |
