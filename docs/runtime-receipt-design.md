# Runtime-behavior receipts (agent-tooling profile v0.2) — design

Status: DESIGN, not shipped. Phase 3 of the agent-tooling initiative. This document specifies
the reserved `runtime/` check namespace and states its containment model honestly, so that an
implementation cannot over-claim. No runtime receipt is minted until this design ships as code
with the sandbox it names.

## The claim, and its honest boundary

The initiative's thesis: review-time inspection binds at ~80% because 21% of malicious agent
tooling fetches and executes content at runtime, so the artifact reviewed at publish time is not
the artifact that runs. A runtime-behavior receipt is meant to close that gap by pinning what
actually ran.

The design tension, discovered against a real observer (MCPAudit's Proof-Before-Action, which
runs the subject in a Docker container created `--network none`): **you cannot simultaneously
network-isolate the sandbox and observe the real fetched-payload bytes.** With egress off there
are no response bytes to digest; with egress on you have executed untrusted code against the
live network, which is exactly the harm the receipt exists to warn about. Any runtime receipt
must pick a lane and grade its evidence to match. Pretending otherwise is the over-claim this
program exists to prevent.

## Two honest lanes

### Lane A — contained observation (default, network off)

Run the subject in a `--network none` sandbox; record, as evidence:

- `runtime/fetch-attempt`: the subject *attempted* egress — destination host/IP the subject
  tried to reach (from namespace counters and the resolver/connect calls it made), and the
  fact that it was blocked. This pins the *intent to fetch*, digested from the attempt evidence,
  not a payload.
- `runtime/dynamic-construct`: the fetch-and-execute construct itself, pinned by digest — the
  exact bytes of the code path (`curl … | sh`, `exec(requests.get(...))`) that would have run.
  This is static content given a runtime witness: "this construct was reached during execution,"
  which is strictly more than the static scanner's "this construct exists."
- `runtime/filesystem-attempt`, `runtime/db-attempt`: transient write / no-delta attempts, from
  the observer's existing attempt-evidence rules.

Lane A **cannot** carry a fetched-payload digest, and its spec says so. Evidence grade is B
(the observation is an immutable capsule digest); `enforced` remains forbidden unless a
HarnessBench corpus measures the sandbox config (the `enforced_proof` path, still future).

### Lane B — recorded egress (opt-in, network on, throwaway host)

Only in a disposable, monitored environment the operator explicitly designates: run with egress
through a recording proxy that digests every response body. Then `runtime/fetched-payload` pins
the actual bytes that were fetched and executed — the strong form of the claim. This lane's
receipt MUST carry, as a first-class disclosed field, that it executed untrusted code with live
network access, and MUST record the proxy/containment config by digest so a reader can judge the
containment. Grade B; never rendered as "safe," only as "here is what it fetched."

The profile ships Lane A first. Lane B is a separate, later, explicitly operator-gated addition
because its containment model is a security decision, not a code decision.

## Schema shape (reserved namespace, v0.2)

`runtime/` checks are `check.kind = "review"` (they review observed behavior), consuming the same
VCR predicate. Additions over v0.1:

- `check.id` in `runtime/` unlocks: `runtime/fetch-attempt`, `runtime/dynamic-construct`,
  `runtime/filesystem-attempt`, `runtime/db-attempt` (Lane A); `runtime/fetched-payload`
  (Lane B only).
- `evidence.kind`: a new `capsule-digest` value (the sha256 of the observation capsule) plus,
  for `runtime/fetched-payload`, the payload digest carried in the evidence `uri`+`digest`.
- `runtime.env_digest`: **mandatory** for every `runtime/` check — it pins the sandbox
  configuration (image id, network mode, isolation flags) the observation ran under. A runtime
  receipt with no pinned containment config is unmintable: the reader must be able to see what
  contained the execution.
- A `containment` block on the check (Lane, network mode, image id) rendered by the verifier
  alongside `trust_floor`, so "network off, attempt only" is never silently read as
  "fetched-payload proven."

These are additive to VCR core (a new `evidence.kind` value + an optional `containment` object);
they require a home-base schema-delta sign-off exactly like the `subject.kind` delta, drafted
when Lane A is built, not now.

## Why this is not shipped here

1. **No sandbox on this host.** The reference observer requires Docker; this machine has none, so
   a Lane A receipt cannot be produced or byte-verified here. Shipping the code without the
   ability to run it against a real subject would violate the program's "no claim without a live,
   byte-verified example" rule.
2. **The containment model is the hard part.** Lane A's soundness depends on the sandbox actually
   isolating; an unsound sandbox makes the receipt over-claim. This is where HarnessBench's rigor
   transfers (a future corpus measuring the sandbox config), and it is deliberately sequenced
   after the review-time path has adoption.

Phase 3 implementation begins by building Lane A against MCPAudit's `observe_command` on a host
with Docker, emitting `runtime/` checks into a `skillscan`-shaped report, and sealing them
through the existing agent-tooling profile once the reserved namespace is unlocked.
