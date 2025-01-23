.PHONY: clean install test lint build publish-test publish

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

install:
	pip install -e ".[dev]"

test: install
	pytest tests/ --cov=cve_query --cov-report=term-missing

lint:
	black .
	isort .
	flake8 .

build: clean
	python -m build

publish-test: build
	python -m twine upload --repository testpypi dist/*

publish: build
	python -m twine upload dist/* 