import io
import unittest

from lightup.webapp.forms import FormError, MAX_FORM_BYTES, read_form


class Unreadable:
    def read(self, *args):
        raise AssertionError("rejected framing must not read the stream")


class WebFormTest(unittest.TestCase):
    def env(self, raw=b"name=Alice", **overrides):
        return {"CONTENT_LENGTH": str(len(raw)),
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
                "wsgi.input": io.BytesIO(raw), **overrides}

    def test_browser_form_and_blank_optional_field(self):
        self.assertEqual(read_form(self.env(b"name=Alice+Smith&notes=&city=Leiden")),
                         {"name": "Alice Smith", "notes": "", "city": "Leiden"})
        self.assertEqual(read_form(self.env(b"name=%C3%A9")), {"name": "é"})
        self.assertEqual(read_form(self.env(b"")), {})

    def test_invalid_framing_never_reads(self):
        for length in ("", "-1", "+5", "1.0", "nope", " 5", "999999999999", None):
            with self.subTest(length=length), self.assertRaises(FormError):
                read_form(self.env(CONTENT_LENGTH=length, **{"wsgi.input": Unreadable()}))

    def test_oversized_body_never_reads(self):
        with self.assertRaises(FormError) as raised:
            read_form(self.env(CONTENT_LENGTH=str(MAX_FORM_BYTES + 1),
                               **{"wsgi.input": Unreadable()}))
        self.assertEqual(raised.exception.status, "413 Payload Too Large")

    def test_transfer_encoding_never_reads(self):
        with self.assertRaises(FormError):
            read_form(self.env(HTTP_TRANSFER_ENCODING="chunked",
                               **{"wsgi.input": Unreadable()}))

    def test_wrong_content_type_never_reads(self):
        for value in ("", "application/json", "multipart/form-data", "text/plain"):
            with self.subTest(value=value), self.assertRaises(FormError) as raised:
                read_form(self.env(CONTENT_TYPE=value, **{"wsgi.input": Unreadable()}))
            self.assertEqual(raised.exception.status, "415 Unsupported Media Type")

    def test_exact_limit_and_bounded_read(self):
        raw = b"name=" + b"x" * (MAX_FORM_BYTES - 5)
        self.assertEqual(len(read_form(self.env(raw))["name"]), MAX_FORM_BYTES - 5)
        stream = io.BytesIO(b"name=Aignored")
        self.assertEqual(read_form(self.env(CONTENT_LENGTH="6",
                                           **{"wsgi.input": stream})), {"name": "A"})
        self.assertEqual(stream.tell(), 6)

    def test_truncated_body_rejected(self):
        with self.assertRaises(FormError):
            read_form(self.env(b"name=A", CONTENT_LENGTH="10"))

    def test_ambiguous_and_malformed_fields_rejected(self):
        for raw in (b"csrf=a&csrf=b", b"name=a&%6eame=b", b"=value", b"name",
                    b"name=%", b"name=%GG", b"name=%FF", b"name=\xff"):
            with self.subTest(raw=raw), self.assertRaises(FormError):
                read_form(self.env(raw))

    def test_field_limit(self):
        with self.assertRaises(FormError):
            read_form(self.env("&".join(f"n{i}=x" for i in range(65)).encode()))


if __name__ == "__main__":
    unittest.main()
