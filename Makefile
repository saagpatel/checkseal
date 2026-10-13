.PHONY: check

check:
	@command -v uv >/dev/null || { echo "Install uv 0.13.0." >&2; exit 127; }
	@command -v node >/dev/null || { echo "Install Node.js 26.11.1 or compatible." >&2; exit 127; }
	@UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv sync --frozen --all-extras
	@UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv run ruff check src tests
	@UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv run ruff format --check src tests
	@UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv run mypy --strict src
	@tmp=$$(mktemp -d .pytest-tmp.XXXXXX); trap 'rm -rf "$$tmp"' EXIT; UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv run pytest -q --basetemp="$$tmp"
	@PATH="$(CURDIR)/.venv/bin:$$PATH" node --test js/
	@UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv build
	@tmp=$$(mktemp -d .checkseal-smoke.XXXXXX); trap 'rm -rf "$$tmp"' EXIT; UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv venv "$$tmp/venv"; UV_CACHE_DIR="$(CURDIR)/.uv-cache" uv pip install --python "$$tmp/venv/bin/python" dist/*.whl; "$$tmp/venv/bin/checkseal" --help >/dev/null
