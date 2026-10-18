PYTHON ?= python3
DATA   ?= data/sample

.PHONY: help data run test coverage check clean

help:
	@echo "make data      - regenerate $(DATA) (benign day + 25 planted scenarios, seed 42)"
	@echo "make run       - run all 25 detections over $(DATA) and print the table"
	@echo "make test      - python -m pytest -q"
	@echo "make coverage  - regenerate docs/ATTACK-COVERAGE.md from savedsearches.conf"
	@echo "make check     - test + verify the coverage doc is current"
	@echo "make clean     - remove caches"

data:
	$(PYTHON) scripts/generate_logs.py --out $(DATA) --seed 42

run:
	$(PYTHON) -m harness.run_detections --data $(DATA)

test:
	$(PYTHON) -m pytest -q

coverage:
	$(PYTHON) scripts/attack_coverage.py

check: test
	$(PYTHON) scripts/attack_coverage.py --check

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
