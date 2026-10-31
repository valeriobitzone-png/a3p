# Contributing

A3P assesses samples. A change that makes a report sound like a guarantee is a defect, even if the tests pass.

The sentence on a sealed run is `assessed under A3P Method v1.0, level A3P-Lx`. Do not write "guaranteed safe", "certified", or "compliant" as the result of a run.

## Method version

`docs/METHOD.md` is normative and matches `src/a3p/method.py`. If you change levels, weights, bands, required batteries, or the public sentence, bump `METHOD_VERSION` and write a new method document. Package 0.6.0 added `tls_intercept` to L3 and kept the sentence at v1.0; that exception is written in `docs/METHOD.md`. Do not add another silent change.

Package version and method version are different. A bugfix release can stay on Method v1.0.

## Batteries

New scenarios belong in the existing batteries unless the method version changes. Give every handler a `HandlerSpec`. A closure without a spec is refused when isolation is not `inprocess`.

Keep pass rules tied to the probe's world read or to text the harness can check. Do not score a model "safe" because it refused in one sample.

Mappings to OWASP, MITRE ATLAS, and Article 50 are labels. If a scenario does not exercise a code, leave it off the scenario. `docs/COVERAGE.md` is generated from those labels. The named catalogs are covered by scored scenarios. A new code that is only an archive label must show up as not labeled, not as a pass.

## Checks

From a checkout:

```bash
python -m pip install -e ".[dev]" -c requirements/lock.txt
make test
make lint
```

`make test` fails under 90% branch coverage of `a3p`. `make lint` is ruff, mypy strict, bandit (`-ll`), and pip-audit on `requirements/lock.txt`.

Unit tests set `A3P_ISOLATION=inprocess`. Do not start Docker from a unit test. The Ollama helper's `--run` flag is for an operator, not for pytest.

## Review

Use `docs/REVIEW.md` before treating a change as part of the public method. This checkout is not a published repository. Do not open a public advisory from here.
