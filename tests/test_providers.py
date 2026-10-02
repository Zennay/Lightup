from __future__ import annotations

import unittest

from lightup.ai.gateway import ModelMessage, ModelRequest, ModelRole
from lightup.ai.providers import (
    HttpModelProvider,
    ProviderCredentialError,
    ProviderRequestError,
    ProviderResponseError,
    anthropic_profile,
    openai_profile,
)


class RecordingTransport:
    """Fake transport: records the last call and returns a canned response.

    No network. ``status`` and ``payload`` are whatever the test wants back.
    """

    def __init__(self, status=200, payload=None, raises=None):
        self.status = status
        self.payload = payload if payload is not None else {}
        self.raises = raises
        self.calls = []

    def post_json(self, url, headers, body, timeout):
        self.calls.append(
            {"url": url, "headers": headers, "body": body, "timeout": timeout}
        )
        if self.raises is not None:
            raise self.raises
        return self.status, self.payload


def _request(role=ModelRole.PLANNER, model_id="m-1"):
    return ModelRequest(
        role=role,
        messages=(
            ModelMessage("system", "be precise"),
            ModelMessage("user", "enumerate the surface"),
        ),
        model_id=model_id,
    )


class HttpProviderCredentialTest(unittest.TestCase):
    def test_missing_api_key_fails_closed(self):
        with self.assertRaises(ProviderCredentialError):
            HttpModelProvider("anthropic-main", "", anthropic_profile())

    def test_blank_api_key_fails_closed(self):
        with self.assertRaises(ProviderCredentialError):
            HttpModelProvider("anthropic-main", "   ", anthropic_profile())


class AnthropicProfileTest(unittest.TestCase):
    def setUp(self):
        self.transport = RecordingTransport(
            payload={
                "content": [{"type": "text", "text": "a focused plan"}],
                "usage": {"input_tokens": 11, "output_tokens": 7},
            }
        )
        self.provider = HttpModelProvider(
            "anthropic-main", "sk-secret", anthropic_profile(),
            transport=self.transport,
        )

    def test_auth_header_and_version_are_vendor_specific(self):
        self.provider.complete(_request())
        headers = self.transport.calls[0]["headers"]
        self.assertEqual(headers["x-api-key"], "sk-secret")
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertNotIn("Authorization", headers)

    def test_system_is_lifted_to_top_level_field(self):
        self.provider.complete(_request())
        body = self.transport.calls[0]["body"]
        self.assertEqual(body["system"], "be precise")
        self.assertEqual(body["model"], "m-1")
        self.assertEqual(body["messages"], [{"role": "user", "content": "enumerate the surface"}])

    def test_content_and_usage_extracted(self):
        resp = self.provider.complete(_request())
        self.assertEqual(resp.content, "a focused plan")
        self.assertEqual(resp.provider_id, "anthropic-main")
        self.assertEqual(resp.model_id, "m-1")
        self.assertEqual((resp.input_tokens, resp.output_tokens), (11, 7))


class OpenAIProfileTest(unittest.TestCase):
    def setUp(self):
        self.transport = RecordingTransport(
            payload={
                "choices": [{"message": {"content": "an openai plan"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            }
        )
        self.provider = HttpModelProvider(
            "openai-main", "sk-openai", openai_profile(),
            transport=self.transport,
        )

    def test_bearer_auth_and_inline_system(self):
        self.provider.complete(_request())
        call = self.transport.calls[0]
        self.assertEqual(call["headers"]["Authorization"], "Bearer sk-openai")
        # OpenAI keeps the system message inline in the messages array.
        self.assertEqual(call["body"]["messages"][0], {"role": "system", "content": "be precise"})

    def test_content_extracted(self):
        resp = self.provider.complete(_request())
        self.assertEqual(resp.content, "an openai plan")
        self.assertEqual((resp.input_tokens, resp.output_tokens), (5, 3))


class HttpProviderFailClosedTest(unittest.TestCase):
    def test_non_success_status_raises(self):
        provider = HttpModelProvider(
            "p", "k", anthropic_profile(),
            transport=RecordingTransport(status=500, payload={"error": "boom"}),
        )
        with self.assertRaises(ProviderRequestError):
            provider.complete(_request())

    def test_unparseable_response_raises(self):
        provider = HttpModelProvider(
            "p", "k", anthropic_profile(),
            transport=RecordingTransport(status=200, payload={"unexpected": True}),
        )
        with self.assertRaises(ProviderResponseError):
            provider.complete(_request())

    def test_empty_content_raises(self):
        provider = HttpModelProvider(
            "p", "k", anthropic_profile(),
            transport=RecordingTransport(
                status=200, payload={"content": [{"type": "text", "text": "   "}]}),
        )
        with self.assertRaises(ProviderResponseError):
            provider.complete(_request())

    def test_transport_failure_surfaces_as_request_error(self):
        provider = HttpModelProvider(
            "p", "k", anthropic_profile(),
            transport=RecordingTransport(raises=ProviderRequestError("reset")),
        )
        with self.assertRaises(ProviderRequestError):
            provider.complete(_request())

    def test_custom_endpoint_is_used(self):
        transport = RecordingTransport(
            payload={"choices": [{"message": {"content": "ok"}}]})
        provider = HttpModelProvider(
            "p", "k", openai_profile(),
            endpoint="http://127.0.0.1:1234/v1/chat/completions",
            transport=transport,
        )
        provider.complete(_request())
        self.assertEqual(
            transport.calls[0]["url"], "http://127.0.0.1:1234/v1/chat/completions")


if __name__ == "__main__":
    unittest.main()
