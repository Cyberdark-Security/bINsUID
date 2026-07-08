BINARY=binsuid
VERSION=$(shell python3 -c "from binsuid import __version__; print(__version__)")
VENV=.venv
PY=$(VENV)/bin/python
PIP=$(VENV)/bin/pip

.PHONY: all install dev test test-short build build-deb build-rpm clean man update-gtfobins version

all: test build

install:
	$(PIP) install -e .

$(VENV)/bin/python:
	python3 -m venv $(VENV)
	$(PIP) install -e ".[dev]"

dev: $(VENV)/bin/python

test: dev
	$(VENV)/bin/pytest -v

test-short: dev
	$(VENV)/bin/pytest -v -m "not linux"

version:
	@echo $(VERSION)

build: build-sdist

build-sdist: dev
	$(PY) -m build

build-deb:
	BINSUID_VERSION=$(VERSION) nfpm package -f nfpm.yaml --target dist/ --packager deb

build-rpm:
	BINSUID_VERSION=$(VERSION) nfpm package -f nfpm.yaml --target dist/ --packager rpm

build-packages: build-deb build-rpm

man:
	man ./man/binsuid.1

update-gtfobins:
	python3 scripts/update-gtfobins.py

clean:
	rm -rf dist/ build/ *.egg-info binsuid.egg-info .pytest_cache $(VENV)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
