# Purpose

CheckSeal emits and verifies signed check receipts for artifact verification
results. Keep the VCR v0.2 and in-toto Statement v1 contracts stable.

# Layout

- `src/checkseal/`: Python model, producers, stores, CLI, signing, and verifier.
- `js/`: browser and Node honest-subset verifier.
- `schemas/` and `tests/fixtures/schema/`: schema contract and shared fixtures.
- `examples/`: runnable examples and browser receipt preview.
- `.github/`: CI, dependency updates, and manual signing workflow.

# Setup

Use `.python-version`, `.node-version`, and the committed `uv.lock`.
Install the complete development environment with `uv sync --frozen --all-extras`.

# Checks

Run `make check` before handing off changes. It includes lint, formatting,
strict mypy, Python and Node tests, and a wheel install smoke check.

# Boundaries

- Treat seals and proof reports as untrusted input.
- Run external proof loading and re-execution only after signature, subject, and
  requested freshness checks pass.
- Proof resolution needs an explicit proof root or resolver.
- Evidence digests are producer assertions; verification does not recompute
  evidence bytes.
- Never claim live Sigstore, Rekor, hosted receipt, or deployment behavior from
  local tests.

# Delivery

Keep changes scoped to the requested behavior. Do not publish or deploy from
local development. CI is the repository verification gate.
