.PHONY: aw-webui build install test typecheck package clean

build: aw-webui
	poetry install


install:
	cp misc/aw-server.service /usr/lib/systemd/user/aw-server.service

test:
	@# Note that extensive integration tests are also run in the bundle repo,
	@# for both aw-server and aw-server-rust, but without code coverage.
	python -c 'import aw_server'
	python -m pytest tests/test_server.py

typecheck:
	python -m mypy aw_server tests --ignore-missing-imports

package:
	python -m aw_server.__about__
	pyinstaller aw-server.spec --clean --noconfirm

PYFILES=$(shell find . -name '*.py')

lint:
	ruff check .

lint-fix:
	poetry run pyupgrade --py38-plus --exit-zero-even-if-changed $(PYFILES)
	ruff check --fix .

format:
	black .

clean:
	rm -rf build dist
	rm -rf aw_server/__pycache__
	rm -rf aw_server/static/*
	pip3 uninstall -y aw_server
	make --directory=aw-webui clean
