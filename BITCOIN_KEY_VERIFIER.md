# Offline Bitcoin Private-Key Verifier

This is a separate, local-only verifier for Bitcoin private keys that you already own.

## Safety model

- Accepts one key interactively using hidden terminal input (WIF or 32-byte hex).
- Derives Bitcoin addresses locally for mainnet or testnet.
- Optionally compares the derived addresses with an address you provide.
- Supports P2PKH, P2SH-P2WPKH, and P2WPKH for compressed public keys.
- Makes **no network requests**, does not query balances, and does not broadcast transactions.
- Does not write keys, addresses, or results to files or logs.
- Does not accept keys as command-line arguments.

Run locally:

```bash
python3 bitcoin_key_verify.py
```

Python 3.9+ is recommended. Only the Python standard library is used.

## Important limitations

- This is an address derivation and comparison utility, not a wallet recovery or balance scanner.
- A hex key has no embedded compression flag, so the program asks which public-key encoding to use.
- WIF carries its compression flag and network prefix; the selected network must match.
- It cannot guarantee secure erasure of immutable Python strings/bytes from process memory. Use a trusted, offline machine and do not paste keys into chat, GitHub, issue trackers, or logs.
- Never upload a real private key to this repository or deploy this tool as a hosted web service.

The existing repository's public-key scanning monitor is separate and is not used by this verifier. This branch adds only the standalone local verifier and documentation; it does not modify or deploy the existing scanner.
