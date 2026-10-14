# LightUp local lab

The local lab is for integration testing LightUp itself. It must not expose services beyond loopback by default.

## Basic deterministic fixture

```bash
python3 http_fixture.py
```

It binds to `127.0.0.1:18080` and returns a deterministic JSON response.

## Planted-weakness fixture

```bash
PYTHONPATH=../src python3 vuln_fixture.py --profile exposed --port 18081
```

`vuln_fixture.py` also binds only to `127.0.0.1`. Its profiles provide hand-maintained planted ground truth for the HTTP baseline evaluator:

- `exposed`: all five baseline findings are planted;
- `partially-hardened`: three findings are planted;
- `hardened`: zero findings are planted;
- `single-*`: one calibration profile per baseline check, with exactly one planted finding.

The single-signal profiles are intended for calibration: they prove each baseline check can fire independently without another planted weakness masking the result. Run the matching assessment with the same profile name to score against that exact ground truth, for example:

```bash
PYTHONPATH=../src python3 vuln_fixture.py \
  --profile single-missing-content-security-policy --port 18081

PYTHONPATH=../src python3 -m lightup.cli lab-assess \
  http://127.0.0.1:18081/ \
  --profile single-missing-content-security-policy \
  --no-review
```

Future lab components should remain disposable, resettable, loopback/private-lab scoped, and isolated from production credentials and data.
