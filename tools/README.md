# trustworthy-ai-core — WAL audit tools

Open, zero-dependency tools for **independently verifying** Trustworthy-AI
Gateway audit logs. They re-declare the WAL byte format (published in
`trustworthy-ai-ir-spec`) and do **not** import the closed-source platform — so a
customer can validate audit integrity without trusting, or even possessing, the
Gateway code. Run them against a read-only WAL mount or an archived segment.

## Tools (`tools/`)

- **`wal_verify.py`** — integrity verifier. Checks the SHA-256 hash chain, CRC
  (`--full`), sequence continuity, and cross-segment linkage.
  ```bash
  python tools/wal_verify.py /path/to/wal --full        # exit 0 ok / 2 tampered / 3 io
  python tools/wal_verify.py /path/to/segment.wal --json # single archived segment
  ```
  A record tampered after the fact breaks the chain even if its CRC is
  recomputed — CRC catches corruption, the chain catches tampering.

- **`wal_dump.py`** — human-readable dump (`--from/--to/--hex/--summary`).
  Shows each record's `seq`, `bytes`, `hash`, and payload preview.

- **`_wal_format.py`** — shared zero-dependency v1/v2 parser (the executable
  reference for the format spec).

## Tests

```bash
PYTHONPATH=tools:. pytest tests/ -q
```

`tests/walgen.py` builds WAL fixtures directly from the format (the inverse of
the verifier), so the test suite stays independent of the platform.