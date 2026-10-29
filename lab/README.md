# LightUp local lab

The local lab is for integration testing LightUp itself. It must not expose services beyond loopback by default.

Current fixture:

```bash
python3 http_fixture.py
```

It binds to `127.0.0.1:18080` and returns a deterministic JSON response. Future lab components should remain disposable, resettable and isolated from production credentials and data.

## Reproducible evidence → remediation → retest replay

Run the built-in fixture lifecycle without supplying a URL or reaching an external target:

```bash
PYTHONPATH=src python -m lightup.lab_replay --store-dir ~/.local/state/lightup/lab-fixture-replays
```

The runner binds an ephemeral port on `127.0.0.1` and replays the `exposed`, `partially-hardened`, and `hardened` profiles against hand-maintained ground truth. It persists canonical baseline/retest evidence through `StateStore`, stores the exposed findings and final retest status through `DomainStore`, and records content-addressed baseline, synthetic-remediation, and retest events in a replay ledger. The receipt excludes run IDs, timestamps, and ephemeral ports; identical fixture/catalog behavior yields the same receipt SHA-256 and an immutable bundle directory. The ledger also retains the normalized response payloads themselves, deduplicated by SHA-256, and verifies event hashes plus the StateStore → evidence payload → DomainStore finding/retest links before publishing or reusing a bundle.

Each bundle contains `receipt.json`, `receipt.sha256`, `state.sqlite3`, `domain.sqlite3`, and `replay-ledger.sqlite3`; files are owner-private and the bundle directory is private. The remediation step is only a synthetic switch of the in-process fixture from `exposed` to `hardened`. `SIMULATED_APPLIED` does not mean a real system was changed or a live security fix was verified. The receipt explicitly records that external targets, model gateways, production authority, and live remediation were not used.


### Replay bundle privacy and reuse

A content-addressed bundle is reused only when its directory is owned by the current effective user and grants no group/other access. The receipt, checksum, and each SQLite database must be owner-private regular files with one hard link; symlinks, permissive modes, unexpected ownership, and linked files fail closed. Changing permissions on an existing bundle is an integrity/custody failure, not a reason to repair permissions silently or trust the receipt. Keep the replay store on an owner-controlled local filesystem.
