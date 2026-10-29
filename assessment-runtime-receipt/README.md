# Offline lab comparison receipt

This is a **non-authorizing, read-only byte receipt**, not a validator of the original comparison schema. The single-source output is versioned as lightup-offline-receipt-v2 so downstream offline consumers can reject unknown receipt shapes.

Run `python3 assessment-runtime-receipt/receipt.py PRIVATE_COMPARISON.json` on an already-exported local file. To compare the bytes against an **independently held** expected digest, optionally provide it as a second argument: `python3 assessment-runtime-receipt/receipt.py PRIVATE_COMPARISON.json LOWERCASE_SHA256`. Only exact 64-character lowercase hexadecimal digests are admitted; invalid expectations produce a generic HOLD. `byte_identity_matches` is present only after successfully admitting the private JSON source. When false, the output suppresses all source metadata (status, source hash and byte count) and remains HOLD; when true, metadata may be included. Equality means only a match with the supplied expectation, **not** trusted origin or authorized release. It always exits **3 (HOLD)**. Accepted inputs reveal only the original *unverified* source-reported status, byte count and SHA-256. The receipt itself stays HOLD with `source_authenticated=false`, `source_schema_verified=false` and all four authority flags false. Even a source-reported REVIEW_ONLY can never become a security or release verdict.

Intake constraints: regular file owned by the invoking effective user ID, single hard link, no symlink in any path component, private mode (no group/other permission), nonempty and at most 256 KiB, path at most 4096 characters, file descriptor checked before and after reading; strict UTF-8 JSON, no duplicate keys, nonfinite constants or partial/invalid authority fields. Malformed inputs produce an anonymous, source-minimal HOLD without echoing private paths, contents or hashes.

**Limitations:** all path components are opened through pinned directory descriptors with no-follow semantics, rejecting `.` / `..`, empty components and symlinked directory ancestors. Use owner-controlled directories anyway: a separate privileged or malicious actor can mutate contents or move directories, and an unchanged descriptor does not prove trustworthy origin. A locally computed digest proves equality to separately held bytes, **not** sender identity, schema/ground-truth truthfulness, genuine consent or authorization.

**INCUBATE · PLAN/LAB ONLY · HOLD.** No active target, scan, grant, dispatch, merge or deployment without original project gates, exact-head CI, source-owner review and independent security/privacy authorization.


## Bounded multi-source batch (offline)

For a 2–8-source review, use `batch.py` with an owner-private manifest containing only canonical **absolute** local paths and separately recorded lowercase SHA-256 byte expectations. The input shape is described by `batch-manifest.schema.json` and the output envelope by `batch-receipt.schema.json`; the runtime remains stricter about path components, ownership, file mode, links, stable reads, duplicate paths/digests and actual byte identity. Schema validity is not source validation or authorization. Example (replace paths and digests with your own private lab artifacts):

```json
{
  "format": "lightup-offline-receipt-batch-v2",
  "sources": [
    {"path": "/private/lab/first.json", "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    {"path": "/private/lab/second.json", "expected_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}
```

Keep the manifest itself owner-private (mode 0600, one hard link), and store its expected SHA-256 separately from the file. After computing or retrieving that independently held value, run:

```sh
python3 assessment-runtime-receipt/batch.py /private/lab/manifest.json EXPECTED_MANIFEST_SHA256
```

The batch CLI **always exits 3 and reports HOLD** and emits receipt_format: lightup-offline-receipt-batch-receipt-v2, including on rejected input. It requires a valid supplied manifest digest, an exact-format manifest, 2–8 distinct original source contents, exact per-source digest matches, and every original file to pass the single-source private-file/strict-JSON admission gates. A malformed or changed manifest, duplicate source, non-absolute path, invalid expected digest, or a single failed source yields the same anonymous HOLD structure: no paths, per-source hashes, counts, or partial results.

Only if *every* admission succeeds does the response include ordinal-only source-reported status, byte counts and digests, an aggregate byte count and an ordered receipt digest. The v2 digest uses a distinct domain separator, binds the exact manifest digest, and then commits to each ordered source ordinal, byte count, digest and status with explicit delimiters. These fields are private custody metadata, **not** a signature or proof of chronology, scenario lineage, sender identity, ground truth or an atomic snapshot. Sources are read sequentially; files could change between reads. A manifest digest recorded from the manifest itself is only self-consistency unless anchored independently. Never publish the manifest or custody metadata without a separate privacy review.

The single-source receipt additionally compares descriptor ownership, permission bits and link count before and after reading, in addition to inode/size/timestamps. Both receipt readers reject paths longer than 4096 characters before opening path components. Both commands remain isolated, read-only and non-authorizing, with no target or network access. The project-wide source-owner, security/privacy, original CI and explicit HUMAN GO gates remain unchanged.
