PY ?= python3

.PHONY: install test lint demo

install:
	$(PY) -m pip install -e ".[dev,sigstore,mcp,world,agents,ui]" -c requirements/lock.txt

test:
	$(PY) -m pytest --cov=a3p --cov-fail-under=90

lint:
	$(PY) -m ruff check src tests
	$(PY) -m mypy src
	$(PY) -m bandit -r src -x src/a3ep -ll -q
	$(PY) -m pip_audit -r requirements/lock.txt --disable-pip --no-deps --progress-spinner off

demo:
	$(PY) -m a3p demo -o out/demo
	$(PY) -m a3p verify out/demo/langgraph-vulnerable/ledger.jsonl --public-key out/demo/langgraph-vulnerable/auditor.pub
	$(PY) -m a3p verify out/demo/n8n-vulnerable/ledger.jsonl --public-key out/demo/n8n-vulnerable/auditor.pub
	$(PY) -m a3p verify out/demo/openai-vulnerable/ledger.jsonl --public-key out/demo/openai-vulnerable/auditor.pub
	$(PY) -m a3p verify out/demo/langgraph-careful/ledger.jsonl --public-key out/demo/langgraph-careful/auditor.pub
	$(PY) scripts/tamper_ledger.py out/demo/langgraph-vulnerable/ledger.jsonl out/demo/ledger.tampered.jsonl
	@echo "A tampered ledger must fail verification"
	@if $(PY) -m a3p verify out/demo/ledger.tampered.jsonl --public-key out/demo/langgraph-vulnerable/auditor.pub; then \
		echo "ERROR: tampered ledger was accepted"; exit 1; \
	else \
		echo "tampered ledger rejected"; \
	fi
