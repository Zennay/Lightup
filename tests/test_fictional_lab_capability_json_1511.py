"""Shared strict JSON parser regression contract for both fictional #1511 CLIs."""
import builtins
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fictional_lab_capability_json_1511 import parse_fictional_envelope_1511 as parse
from fictional_lab_capability_cli_1511 import decide_stdin_bytes_1511
from fictional_lab_capability_batch_cli_1511 import decide_batch_stdin_bytes_1511

_S1 = "fictional_lab_capability_v1"
_S2 = "fictional_lab_capability_batch_v1"
_SINGLE = b'{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"]}'
_BATCH = b'{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline"],"allowlist":["web-baseline"]}'


class _PoisonedType:
    def __eq__(self, other):
        raise AssertionError("caller-owned equality unexpectedly invoked")


class _StrSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class FictionalLabCapabilityCanonicalJSON1511Tests(unittest.TestCase):
    def test_single_and_batch_have_distinct_fixed_schemas(self):
        self.assertEqual(parse(_SINGLE, expected_schema=_S1, requested_type=str)["requested"],
                         "web-baseline")
        self.assertEqual(parse(_BATCH, expected_schema=_S2, requested_type=list)["requested"],
                         ["web-baseline"])
        self.assertIsNone(parse(_SINGLE, expected_schema=_S2, requested_type=list))
        self.assertIsNone(parse(_BATCH, expected_schema=_S1, requested_type=str))
        self.assertEqual(decide_stdin_bytes_1511(_BATCH), "HOLD")
        self.assertEqual(decide_batch_stdin_bytes_1511(_SINGLE), "HOLD")

    def test_parser_enforces_builtin_metadata_and_bytes_without_spoof_calls(self):
        for data, schema, kind in (
            (_BytesSubclass(_SINGLE), _S1, str),
            (_SINGLE, _StrSubclass(_S1), str),
            (_SINGLE, _S1, _PoisonedType()),
            (_SINGLE, _S1, str),
            (_BATCH, _S2, list),
        ):
            with self.subTest(kind=type(kind).__name__):
                parsed = parse(data, expected_schema=schema, requested_type=kind)
                if type(data) is bytes and type(schema) is str and (kind is str or kind is list):
                    self.assertIsNotNone(parsed)
                else:
                    self.assertIsNone(parsed)

    def test_not_real_authority_even_when_json_is_well_formed(self):
        s = parse(_SINGLE, expected_schema=_S1, requested_type=str)
        b = parse(_BATCH, expected_schema=_S2, requested_type=list)
        self.assertIs(type(s), dict)
        self.assertIs(type(b), dict)
        self.assertEqual(tuple(s), ("schema", "requested", "allowlist"))
        self.assertEqual(tuple(b), ("schema", "requested", "allowlist"))
        self.assertNotIn("authorized", s)
        self.assertNotIn("dispatch_allowed", b)

    def test_nonstandard_json_number_constants_rejected_immediately(self):
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            sample = _BATCH.replace(b'["web-baseline"]', b'["web-baseline",' + token + b"]", 1)
            self.assertIsNone(parse(sample, expected_schema=_S2, requested_type=list))
            self.assertEqual(decide_batch_stdin_bytes_1511(sample), "HOLD")

    def test_extra_whitespace_alias_duplicate_unicode_and_order_rejected(self):
        variations = (
            _SINGLE + b" ", _SINGLE + b"\n", _SINGLE + b"{}",
            _SINGLE.replace(b',"requested":', b', "requested":'),
            _SINGLE.replace(b'"schema":', b'"schema":"fictional_lab_capability_v1","schema":'),
            _SINGLE.replace(b'"schema":', b'"\\u0073chema":"fictional_lab_capability_v1","schema":'),
            _SINGLE.replace(b'"web-baseline"', b'"web\\u002dbaseline"'),
            b'{"requested":"web-baseline","schema":"fictional_lab_capability_v1","allowlist":["web-baseline"]}',
        )
        for sample in variations:
            self.assertIsNone(parse(sample, expected_schema=_S1, requested_type=str))

    def test_fixed_ascii_max_size_and_bad_depth_rejected(self):
        for sample in (
            b"", b"\xff", b"null", b"{}", b"[]",
            _BATCH + b" " * (4096 - len(_BATCH)),
            _BATCH + b"x" * 4097,
            b"[" * 1500 + b"0" + b"]" * 1500,
        ):
            self.assertIsNone(parse(sample, expected_schema=_S2, requested_type=list))

    def test_all_positive_fixture_prefixes_and_corrupt_bytes_rejected(self):
        for sample, schema, kind in ((_SINGLE, _S1, str), (_BATCH, _S2, list)):
            self.assertIsNotNone(parse(sample, expected_schema=schema, requested_type=kind))
            for offset in range(len(sample)):
                self.assertIsNone(parse(sample[:offset], expected_schema=schema, requested_type=kind))
                corrupted = sample[:offset] + b"\x00" + sample[offset + 1:]
                self.assertIsNone(parse(corrupted, expected_schema=schema, requested_type=kind))

    def test_malformed_envelope_cannot_trigger_io(self):
        with (
            patch.object(builtins, "open", side_effect=AssertionError("no file open")),
            patch.object(os, "open", side_effect=AssertionError("no os.open")),
            patch.object(socket, "socket", side_effect=AssertionError("no socket")),
        ):
            self.assertIsNotNone(parse(_SINGLE, expected_schema=_S1, requested_type=str))
            self.assertIsNone(parse(b"\xff", expected_schema=_S1, requested_type=str))
            self.assertIsNone(parse(_BATCH[:-1], expected_schema=_S2, requested_type=list))


if __name__ == "__main__":
    unittest.main()
