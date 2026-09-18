# Verified Smart Contract Auditor

A [GenLayer](https://docs.genlayer.com/) **Intelligent Contract** that lets anyone submit smart contract source code (Solidity, Vyper, etc.) and receive an AI-powered security audit — a plain-English summary, a list of concrete risks/vulnerabilities, recommended fixes, and a 0–100 risk score — all reached through GenLayer's validator consensus, with a deterministic static-analysis layer and an on-chain source-code commitment to keep the LLM's judgment honest.

> GenLayer is the Adjudication Layer for the Agentic Economy: a blockchain protocol whose Intelligent Contracts can call LLMs and fetch web data inside smart contract logic, with disagreement between validators resolved through **Optimistic Democracy** and the **Equivalence Principle**. See the [GenLayer docs](https://docs.genlayer.com/) for the underlying concepts (Intelligent Contracts, GenVM, Leader/Validator pattern, Equivalence Principle) referenced throughout this README.

---

## What it does

1. A user calls `analyze_contract(title, language, code)` with the source code they want reviewed.
2. A **leader** validator sends the code to an LLM with a security-auditing prompt and gets back a summary, a list of risks, a list of recommendations, and a risk score.
3. Other validators **independently reproduce** the audit. The network only needs to agree on the **decision fields** — `risk_score` (within a tolerance) and the `risk_level` bucket derived from it — not on the exact wording of the free-text fields, since two LLMs will phrase the same finding differently.
4. The result, including a hash of the exact source that was audited, is stored on-chain and can be read back by anyone.

## Why this needs GenLayer

An LLM security review is inherently non-deterministic free text plus a subjective numeric score — two validators asking the same question will never produce byte-identical output. A traditional smart contract can't reach consensus on that. GenLayer's [Equivalence Principle](https://docs.genlayer.com/) is built exactly for this: instead of requiring exact equality (`strict_eq`), this contract defines its own **leader/validator comparison function** via `gl.vm.run_nondet_unsafe`, which lets validators agree on *outcome equivalence* (same risk bucket, score within tolerance, same confirmed findings) rather than on identical text.

---

## Contract interface

| Method | Type | Description |
|---|---|---|
| `analyze_contract(title, language, code)` | `write` | Submits source code for audit. Runs the LLM leader/validator flow and stores a new `Audit` record. Returns the new audit's `id`. |
| `get_analysis(audit_id)` | `view` | Returns the full audit record for a given id. |
| `verify_source(audit_id, code)` | `view` | Returns `True` iff `code` is exactly the source that was audited for `audit_id` (compared via `sha256`). Lets anyone confirm a stored result actually corresponds to a specific piece of source. |
| `get_all_analyses()` | `view` | Returns every stored audit. |
| `get_my_analyses(owner_address)` | `view` | Returns every audit submitted by a given address. |
| `get_stats()` | `view` | Returns totals and a breakdown of audits by `High` / `Medium` / `Low` risk. |

### Stored record (`Audit`)

| Field | Description |
|---|---|
| `id` | Sequential audit id. |
| `owner` | Address that submitted the code. |
| `title`, `language` | User-supplied metadata (language defaults to `"Solidity"`). |
| `risk_level` | `"Low"` / `"Medium"` / `"High"` — **always derived from `risk_score`**, never taken directly from the LLM (see [Design decisions](#design-decisions)). |
| `risk_score` | Integer 0–100, from the LLM, floored by the static scan when applicable. |
| `summary` | Plain-English description of what the contract does. |
| `recommendations` | List of suggested fixes / best practices. |
| `risks` | List of identified vulnerabilities or red flags, including any confirmed static-scan findings. |
| `code_hash` | `sha256` of the exact audited source — the on-chain source commitment. |
| `static_findings` | Names of the deterministic static-scan patterns matched in the source. |
| `created_at` | UTC timestamp. |

---

## How consensus is reached

This contract does **not** use `strict_eq`. It defines a custom leader/validator pair passed to `gl.vm.run_nondet_unsafe`:

- **Leader** — calls `gl.nondet.exec_prompt(prompt, response_format="json")` and normalizes the response.
- **Validator** — re-runs the same audit independently, then checks the leader's *claimed* result against its own:
  - `risk_level` must match exactly (it's a discrete bucket derived from the score, not free text).
  - `risk_score` must be within `RISK_SCORE_TOLERANCE` (12 points) of the validator's own score.
  - Every static-scan finding confirmed for this source must be present, verbatim, in the leader's claimed `risks` list.

Errors raised inside the non-deterministic block carry a deterministic prefix so validators can classify them consistently instead of trusting the leader's formatting:

| Prefix | Meaning | Agreement rule |
|---|---|---|
| `[EXPECTED]` | Business-logic error (bad input, missing field) | Must match exactly |
| `[EXTERNAL]` | External/API error | Must match exactly |
| `[TRANSIENT]` | Timeout-style error | Agree if both sides hit one |
| `[LLM_ERROR]` | Malformed / garbage model output | Always disagree, forcing a new leader |

## Design decisions

**Why `risk_level` is never trusted from the LLM.** An earlier version let the LLM self-report `risk_level` and only derived it as a fallback. That allowed internally contradictory records — e.g. `risk_level="High"` alongside `risk_score=20` — because a valid-looking label was accepted even when it disagreed with the model's own score. `risk_level` is now **always** computed by fixed breakpoints (`_derive_risk_level`) from `risk_score`, and the prompt doesn't even ask the model for it. This also makes the validator's exact-match check on `risk_level` meaningful: it's really an exact-match check on a discrete risk bucket, with the numeric tolerance acting as a tighter secondary constraint.

**Deterministic static scan as a cross-check.** GenVM has no primitive for running an actual compiler or static-analysis tool — `gl.nondet` only covers LLM calls and web fetches, not arbitrary binary execution — so this contract doesn't claim to integrate one. Instead, `_static_scan` is a small, fully deterministic, pure-text scan for a short, low-false-positive list of well-established Solidity risk patterns:

| Pattern | Flags |
|---|---|
| `selfdestruct` / `suicide` | Contract can be destroyed |
| `delegatecall` | Proxy / code-injection risk if target is untrusted |
| `tx.origin` | Phishing-vector anti-pattern for authorization |
| Low-level `.call` with value | Reentrancy risk if unguarded |

Because every validator computes the identical findings from the identical source, this signal needs no consensus check of its own. When it fires:
1. `risk_score` is floored to at least `STATIC_FINDING_SCORE_FLOOR` (34 — out of the "Low" bucket), so an LLM materially underrating a contract with a known-dangerous pattern can't produce an uncontested "Low" verdict.
2. The finding's fixed description is appended to the stored `risks` list if the LLM didn't already mention it, so a confirmed pattern can't be silently absent from the record regardless of what the model chose to write.

This is explicitly **not** a replacement for a real compiler or static-analysis tool, and doesn't claim to catch anything beyond its narrow pattern list — it's an honest, always-agreeing objective signal layered on top of the LLM's judgment, not a substitute for one.

**Source commitment.** `code_hash = sha256(code.strip())` is computed once, deterministically, and stored on every record. `verify_source(audit_id, code)` lets anyone check whether a given piece of source is exactly what was audited, closing the gap between "an audit exists" and "this audit is actually about this code."

**Domain-specific prompt.** The prompt (`_build_audit_prompt`) is written specifically for code security auditing — not adapted from a legal-document review template — to avoid prompt ambiguity across LLM providers (an earlier legal-prose-oriented prompt applied to Solidity source caused inconsistent `MAJORITY_DISAGREE` / `UNDETERMINED` results in production, since different providers guessed differently at what kind of document they were reviewing).

**Flattened storage.** Records are stored as a `TreeMap` of primitives plus a `DynArray[Audit]`, with `recommendations`/`risks` persisted as compact JSON strings, rather than nesting generic containers inside the stored dataclass — avoiding the `gl.storage.inmem_allocate` handling that generic-in-generic storage fields would otherwise require.

## Limitations

- The static scan is intentionally narrow (4 patterns) and low-false-positive by design — it is not a substitute for a real linter, static-analysis tool, or compiler, and passing it is not a guarantee of safety.
- `summary`, `recommendations`, and `risks` wording comes from the LLM and is not required to match byte-for-byte across validators; only the risk bucket, score (within tolerance), and confirmed static findings are consensus-checked.
- Audits reflect a snapshot of the submitted source; if the deployed contract differs from what was audited, use `verify_source` to detect that.

## Deployment note

The contract declares its GenVM runtime dependency in its header comment:

```python
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
```

It can be deployed like any other [Intelligent Contract](https://docs.genlayer.com/) — e.g. via GenLayer Studio or the GenLayer CLI/SDK against a GenLayer network (StudioNet, TestNet, etc.).

## Related work

This contract's structure (leader/validator prompt pattern, deterministic error tagging, score-floor pattern) follows conventions documented in GenLayer's own [Equivalence Principle](https://docs.genlayer.com/) guide, and reuses patterns from a similar community project, the [AI URL Reputation Oracle](https://docs.genlayer.com/), for score-clamping on confirmed findings and error classification.
