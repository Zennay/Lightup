# LightUp local lab

The local lab is for integration testing LightUp itself. It must not expose services beyond loopback by default.

Current fixture:

```bash
python3 http_fixture.py
```

It binds to `127.0.0.1:18080` and returns a deterministic JSON response. Future lab components should remain disposable, resettable and isolated from production credentials and data.

## Leaky web app profile

```bash
python lab/vuln_fixture.py --profile leaky-webapp --port 18082 &
PYTHONPATH=src python -m lightup.cli lab-assess http://127.0.0.1:18082/ --profile leaky-webapp
```

Plants readable `.git/HEAD`, `.env` and `backup.sql`, directory listing on
`/`, credentialed CORS origin reflection and a flagless session cookie. All
planted bodies are synthetic; the web exposure worker stores only hashes and
signature names, never the leaked content.
