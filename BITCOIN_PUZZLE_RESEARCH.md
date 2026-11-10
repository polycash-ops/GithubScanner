# Bitcoin Puzzle Public-Progress Research

This isolated module adds read-only public-data research for Bitcoin Puzzle #71. It does not change the existing GitHub secret scanner.

## Scope

- Validate the target's mainnet P2PKH Base58Check encoding and extract its HASH160.
- Reconcile inclusive progress intervals supplied in JSON, merging overlap and adjacency.
- Report total *claimed* coverage and unreported intervals.
- Reject malformed, reversed, and out-of-puzzle-range interval records.

## Explicit safety boundary

This is **not a private-key scanner**. It does not generate, derive, enumerate, test, save, or display private-key candidates. It does not call blockchain APIs or submit data to third parties. It cannot prove that a reported interval was actually searched; it only audits arithmetic and provenance supplied by the user. Never enter wallet seeds or private keys.

## Run

Python 3.9+; standard library only.

```bash
python bitcoin_puzzle_research.py
python bitcoin_puzzle_research.py --ranges progress.json
python -m unittest discover -s tests -v
```

Example `progress.json`:

```json
{
  "ranges": [
    {
      "start": "400000000000000000",
      "end": "4000000000000000ff",
      "source": "publisher or pool name",
      "evidence_url": "https://example.invalid/progress",
      "checked_at": "2026-11-09T00:00:00Z"
    }
  ]
}
```

The `source`, `evidence_url`, and `checked_at` fields are provenance notes; they are not authenticated by the tool. Range endpoints are inclusive hexadecimal integers. The tool reports both merged claimed intervals and the gaps not represented in the input.

## Puzzle #71 constants

- Address: `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`
- Inclusive interval: `0x400000000000000000` through `0x7fffffffffffffffff`

No progress records are bundled because unverified percentages should not be presented as measured facts.
