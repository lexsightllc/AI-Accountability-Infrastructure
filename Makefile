.PHONY: install test lint format typecheck clean

install:
	pip install -e '.[dev,server,crypto]'
	pre-commit install

test:
	pytest -v --cov=ai_trust --cov-report=term-missing

lint:
	black --check .
	isort --check-only .
	ruff check .

format:
	black .
	isort .

typecheck:
	mypy .

clean:
	find . -type d -name '__pycache__' -exec rm -r {} +
	find . -type d -name '*.egg-info' -exec rm -r {} +
	find . -type d -name '.pytest_cache' -exec rm -r {} +
	find . -type d -name '.mypy_cache' -exec rm -r {} +
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/ .ruff_cache/
