# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
Verified Smart Contract Auditor (Intelligent Contract)

Lets anyone submit smart contract source code (Solidity, Vyper, etc.) for
AI-powered security audit. A leader validator asks an LLM to summarize what
the code does, list concrete vulnerabilities/risks and recommended fixes,
and assign a risk score. Other validators independently reproduce the audit
and the network reaches consensus on the *decision* fields (risk_level,
risk_score) via a custom Equivalence Principle validator - free-text fields
(summary, recommendations, risks wording) are stored from the leader's
answer but are not required to match byte-for-byte, since two LLMs will
phrase the same finding differently.

IMPORTANT - domain correction: an earlier version of this contract was
written as a *legal document* reviewer ("helping a non-lawyer understand a
{contract_type} agreement", extracting "obligations" between parties). That
doesn't match this project's actual purpose, which is auditing smart
contract *code*, not legal prose. Feeding real Solidity source through that
legal-agreement prompt caused persistent MAJORITY_DISAGREE / UNDETERMINED
results in production: different LLM providers guessed differently at
whether they were supposed to review it as a legal document or as code
(one provider correctly produced a code-security-style analysis anyway;
several others visibly did not agree with it), the same class of prompt-
ambiguity failure documented in the AI URL Reputation Oracle project for
off-topic inputs. This version's prompt, field names, and parameter names
are all rewritten for code security auditing specifically. See
`analyze_contract` / `_build_audit_prompt`.

Design notes (see README for the full write-up):
- Storage is flattened (TreeMap of primitives + DynArray[Audit]) rather
  than nesting DynArray/TreeMap fields inside the stored dataclass, to avoid
  the gl.storage.inmem_allocate dance required for generic-in-generic storage
  fields. recommendations/risks lists are persisted as compact JSON strings.
- Equivalence: gl.vm.run_nondet_unsafe with a hand-written leader/validator
  pair (Pattern 1 + numeric tolerance from the Equivalence Principle docs),
  not strict_eq, because LLM output here is inherently non-deterministic free
  text plus a subjective score.
- Errors raised inside the non-deterministic block are tagged with
  deterministic prefixes ([EXPECTED]/[EXTERNAL]/[TRANSIENT]/[LLM_ERROR]) so
  the validator can classify and decide agreement without re-trusting the
  leader's formatting alone. `get_my_audits` applies the same
  [EXPECTED]-tagged convention to a malformed `owner_address` argument
  (constructing `Address(owner_address)` directly would otherwise raise an
  untagged, generic exception, inconsistent with every other input
  validation error in this contract).
- `risk_level` ("Low"/"Medium"/"High") is ALWAYS derived deterministically
  from `risk_score` (see `_derive_risk_level`) and is never taken directly
  from the LLM. The prompt doesn't even ask for it. An earlier version let
  the LLM self-report `risk_level` and only fell back to deriving it when
  the label was missing/invalid - that allowed an internally contradictory
  stored record (e.g. risk_level="High" alongside risk_score=20), since a
  valid-looking label was trusted even when it disagreed with the model's
  own score. Two consumers reading different fields off the same record
  (a UI's risk badge vs. its score ring; two different downstream
  contracts) would then disagree with each other. Deriving one field from
  the other by fixed breakpoints makes that impossible by construction,
  and also makes the validator's exact-match check on `risk_level`
  meaningful: it's really an exact-match check on a discrete risk bucket,
  with the numeric `risk_score` tolerance as a tighter secondary
  constraint on top of it.
- Review feedback: "Consensus checks only score proximity and risk bucket
  while the actionable findings remain unchecked and the record has no
  source commitment. ... store a hash of the exact audited source and
  have validators compare vulnerability findings against compiler or
  static-analysis evidence." Addressed as two separate, verifiable pieces:
    1. Source commitment: `code_hash` is `sha256(clean_code)`, computed
       once and stored on every `Audit` record. `verify_source(audit_id,
       code)` lets anyone check whether a piece of source is exactly what
       was audited. This is deterministic and needs no consensus check of
       its own -- every node computes the identical hash from the
       identical input string.
    2. Findings cross-check: GenVM contracts have no primitive for
       running an actual compiler or a real static-analysis tool
       (gl.nondet only covers LLM calls and web fetches, not arbitrary
       binary execution), so claiming to integrate one would be
       dishonest. What's actually implemented is `_static_scan`: a small,
       fully deterministic, pure-text scan for a short list of
       well-established, low-false-positive Solidity risk patterns
       (selfdestruct, delegatecall, tx.origin, low-level .call with
       value). Because it's deterministic, every validator computes the
       identical findings from the identical source with no risk of
       disagreement -- unlike the LLM's own `risks`/`recommendations`
       prose, this signal needs no exact-match consensus check at all.
       If the scan finds any of these patterns, two things happen in
       `_normalize_audit_response`, both on leader and validator alike:
         - `risk_score` is floored to at least `STATIC_FINDING_SCORE_FLOOR`
           (the same clamp pattern already used for phishing/malware in
           the AI URL Reputation Oracle project), so an LLM materially
           underrating a contract with a known-dangerous pattern can no
           longer produce a "Low" verdict uncontested.
         - The finding's fixed, deterministic description
           (STATIC_FINDING_DESCRIPTIONS) is appended to the stored
           `risks` list if the LLM's own list doesn't already contain it.
           A score floor alone only adjusts a number; it doesn't stop the
           *findings themselves* from staying unchecked free text an LLM
           could omit while still satisfying the floor with an unrelated
           high score. Guaranteeing the finding's own description is
           present in the record closes that gap specifically -- a
           confirmed pattern can no longer be silently absent from what's
           stored, regardless of what the LLM chose to write.
       This is explicitly NOT a replacement for a real compiler/static-
       analysis tool and does not claim to catch vulnerabilities beyond
       its narrow pattern list -- it's a small, honest, always-agreeing
       objective signal layered on top of the LLM's judgment (both in the
       score and in the stored findings text), not a substitute for one.
"""

import hashlib
import json
import re
import typing
from dataclasses import dataclass
from datetime import datetime, timezone

from genlayer import *

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

MAX_CODE_CHARS = 20_000
MAX_TITLE_CHARS = 160
MAX_LANGUAGE_CHARS = 160
MAX_LIST_ITEMS = 6
MAX_ITEM_CHARS = 160
MAX_SUMMARY_CHARS = 1200

# If the deterministic static scan (see _static_scan) finds any of the
# patterns below, risk_score is floored to at least this value, moving it
# out of the "Low" bucket (>= 34) regardless of what the LLM itself
# reported. See the module docstring's "Findings cross-check" note.
STATIC_FINDING_SCORE_FLOOR = 34

# Small, deliberately narrow set of well-established, low-false-positive
# Solidity risk indicators, matched as plain text/regex against the raw
# source. This is NOT a compiler or a real static-analysis tool (GenVM has
# no primitive for running one) -- it's a fully deterministic, always-
# agrees-across-every-node signal, intentionally limited to patterns that
# are almost never present by accident and almost always worth a second
# look, to keep the false-positive rate low.
STATIC_RISK_PATTERNS = (
    ("uses_selfdestruct", re.compile(r"\b(selfdestruct|suicide)\s*\(")),
    ("uses_delegatecall", re.compile(r"\bdelegatecall\s*\(")),
    ("uses_tx_origin", re.compile(r"\btx\.origin\b")),
    ("uses_low_level_call_with_value", re.compile(r"\.call\s*\{\s*value\s*:|\.call\.value\s*\(")),
)

# Fixed, deterministic wording for each static finding, used to guarantee
# every finding the scan confirms is actually reflected in the stored
# `risks` list (see _normalize_audit_response) -- not just folded into a
# score adjustment nobody can see the reason for.
STATIC_FINDING_DESCRIPTIONS = {
    "uses_selfdestruct": "Static scan: contains selfdestruct/suicide (contract can be destroyed)",
    "uses_delegatecall": "Static scan: uses delegatecall (proxy/code-injection risk if target is untrusted)",
    "uses_tx_origin": "Static scan: uses tx.origin (phishing-vector anti-pattern for authorization)",
    "uses_low_level_call_with_value": "Static scan: uses a low-level .call with value (reentrancy risk if unguarded)",
}

# How far a validator's independently-computed risk_score may drift from the
# leader's before the validator disagrees. LLM scoring is subjective, so an
# exact match is unrealistic; a wide gap should still force a re-vote.
RISK_SCORE_TOLERANCE = 12

ERR_EXPECTED = "[EXPECTED]"   # business-logic errors -> must match exactly
ERR_EXTERNAL = "[EXTERNAL]"   # external/API errors -> must match exactly
ERR_TRANSIENT = "[TRANSIENT]"  # timeouts etc -> agree if both see one
ERR_LLM = "[LLM_ERROR]"       # malformed/garbage model output -> always disagree


# --------------------------------------------------------------------------
# Storage type
# --------------------------------------------------------------------------


@allow_storage
@dataclass
class Audit:
    id: str
    owner: Address
    title: str
    language: str
    risk_level: str
    risk_score: u32
    summary: str
    recommendations_json: str
    risks_json: str
    code_hash: str               # sha256 hex digest of the exact audited source
    static_findings_json: str    # JSON list of deterministic static-scan finding names
    created_at: str


def _audit_to_dict(a: Audit) -> dict:
    return {
        "id": a.id,
        "owner": a.owner.as_hex,
        "title": a.title,
        "language": a.language,
        "risk_level": a.risk_level,
        "risk_score": int(a.risk_score),
        "summary": a.summary,
        "recommendations": json.loads(a.recommendations_json),
        "risks": json.loads(a.risks_json),
        "code_hash": a.code_hash,
        "static_findings": json.loads(a.static_findings_json),
        "created_at": a.created_at,
    }


def _static_scan(code: str) -> list[str]:
    """Fully deterministic, pure-text scan for a short list of
    well-established Solidity risk patterns (see STATIC_RISK_PATTERNS).
    Every node computes the identical result from the identical source,
    so this needs no consensus check of its own. NOT a substitute for a
    real compiler or static-analysis tool -- see the module docstring's
    "Findings cross-check" note for what this can and can't catch."""
    return [name for name, pattern in STATIC_RISK_PATTERNS if pattern.search(code)]


# --------------------------------------------------------------------------
# Prompt construction (deterministic - safe to call outside and inside the
# non-deterministic block)
# --------------------------------------------------------------------------


def _build_audit_prompt(language: str, code: str) -> str:
    return f"""You are an expert smart contract security auditor reviewing {language} source code before it is deployed or trusted with user funds.

Read the contract source code below and produce a careful, balanced security assessment. This is CODE, not a legal document -- evaluate it purely as a software security auditor would, not as a legal or contract-law reviewer.

CONTRACT SOURCE CODE:
\"\"\"
{code}
\"\"\"

Respond with ONLY a single JSON object (no markdown fences, no extra commentary) using exactly this shape:
{{
  "summary": "2-4 sentence plain-English summary of what this contract does and its main entry points",
  "recommendations": ["short recommended fix or best practice", "..."],
  "risks": ["short vulnerability or red-flag phrase", "..."],
  "risk_score": <integer 0-100, where 0 is no security risk and 100 is a severe, exploitable vulnerability>
}}

List at most {MAX_LIST_ITEMS} recommendations and at most {MAX_LIST_ITEMS} risks, each a short phrase under 20 words.
Base risk_score on concrete issues you find in the code (for example: missing access control, reentrancy,
unchecked external calls or low-level calls, integer overflow/underflow, front-running or MEV exposure,
missing input validation, denial-of-service vectors, unprotected selfdestruct or delegatecall, tx.origin misuse,
missing events for state changes, centralization/single-owner risk, unbounded loops, insufficient testing surface).
It is mandatory to respond with valid JSON matching the shape above and nothing else."""


# --------------------------------------------------------------------------
# Defensive parsing of the LLM response (used by both leader and validator)
# --------------------------------------------------------------------------


def _coerce_str_list(value: typing.Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise gl.vm.UserError(f"{ERR_LLM} expected a list, got {type(value).__name__}")
    out: list[str] = []
    for item in value:
        s = str(item).strip()
        if not s:
            continue
        out.append(s[:MAX_ITEM_CHARS])
        if len(out) >= MAX_LIST_ITEMS:
            break
    return out


def _coerce_risk_score(raw: typing.Any) -> int:
    try:
        score = int(round(float(str(raw).strip())))
    except (TypeError, ValueError):
        raise gl.vm.UserError(f"{ERR_LLM} non-numeric risk_score: {raw!r}")
    return max(0, min(100, score))


def _derive_risk_level(score: int) -> str:
    """Always derive risk_level from risk_score deterministically. The LLM
    is intentionally NOT asked to self-report risk_level (see the prompt):
    if it were, its label and its own score could disagree (e.g. "High"
    with a score of 20), producing an internally self-contradictory
    on-chain record that a UI showing both the score and the label would
    display as two conflicting signals. Deriving one field from the other
    makes that impossible by construction."""
    if score >= 67:
        return "High"
    if score >= 34:
        return "Medium"
    return "Low"


def _first_present(raw: dict, keys: tuple) -> typing.Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def _normalize_audit_response(raw: typing.Any, static_findings: list[str]) -> dict:
    """Validate + clean the LLM's JSON response. Raises gl.vm.UserError
    (tagged ERR_LLM) on anything that cannot be salvaged.

    `static_findings` comes from the fully deterministic `_static_scan`
    (same input, same output on every node) and is used two ways here:
    1. Floors `risk_score` -- it never widens or loosens what the LLM
       reported, only raises it when the LLM's own score would otherwise
       undercut a pattern the scan already confirmed is present.
    2. Guarantees every static finding appears in the stored `risks`
       list, using fixed wording from STATIC_FINDING_DESCRIPTIONS. A
       score floor alone leaves the *findings themselves* still fully
       unchecked free text -- an LLM could satisfy the floor with an
       unrelated high score while never mentioning the actual pattern
       the scan found. Appending the deterministic description whenever
       it's missing means a confirmed finding can no longer be silently
       absent from the record, regardless of what the LLM chose to
       write. This still isn't the same as validators comparing prose
       against a compiler/static-analysis tool (no such primitive exists
       in GenVM -- see the module docstring), but it closes the gap
       between "the scan influenced a number" and "the scan's finding is
       actually present in the record" for the specific patterns it
       checks."""
    if not isinstance(raw, dict):
        raise gl.vm.UserError(f"{ERR_LLM} model did not return a JSON object, got {type(raw).__name__}")

    summary = _first_present(raw, ("summary", "analysis", "overview", "description"))
    summary = str(summary or "").strip()
    if not summary:
        raise gl.vm.UserError(f"{ERR_LLM} missing 'summary' in model response")
    summary = summary[:MAX_SUMMARY_CHARS]

    recommendations = _coerce_str_list(
        _first_present(raw, ("recommendations", "recommended_fixes", "fixes"))
    )
    risks = _coerce_str_list(_first_present(raw, ("risks", "vulnerabilities", "risks_identified", "red_flags")))

    score_raw = _first_present(raw, ("risk_score", "score", "riskScore", "risk"))
    if score_raw is None:
        raise gl.vm.UserError(f"{ERR_LLM} missing 'risk_score' in model response")
    score = _coerce_risk_score(score_raw)

    if static_findings:
        score = max(score, STATIC_FINDING_SCORE_FLOOR)
        for finding in static_findings:
            description = STATIC_FINDING_DESCRIPTIONS[finding]
            if description not in risks:
                risks.append(description)

    level = _derive_risk_level(score)

    return {
        "summary": summary,
        "recommendations": recommendations,
        "risks": risks,
        "risk_score": score,
        "risk_level": level,
    }


def _validator_agrees_with_error(leaders_res: "gl.vm.Result", leader_fn: typing.Callable) -> bool:
    """The leader errored. Re-run independently and classify before agreeing.

    Mirrors the error-classification pattern from the Equivalence Principle
    docs: deterministic errors must match exactly, transient errors agree if
    both sides hit one, anything LLM-related or unclassified disagrees so the
    network rotates to a new leader instead of freezing on bad output.
    """
    leader_msg = getattr(leaders_res, "message", "") or ""
    try:
        leader_fn()
        # We produced a result where the leader failed -> genuine disagreement.
        return False
    except gl.vm.UserError as e:
        validator_msg = getattr(e, "message", str(e))
        if validator_msg.startswith(ERR_EXPECTED) or validator_msg.startswith(ERR_EXTERNAL):
            return validator_msg == leader_msg
        if validator_msg.startswith(ERR_TRANSIENT) and leader_msg.startswith(ERR_TRANSIENT):
            return True
        # ERR_LLM or anything unclassified: force a retry with a new leader.
        return False
    except Exception:
        return False


# --------------------------------------------------------------------------
# Contract
# --------------------------------------------------------------------------


class VerifiedSmartContractAuditor(gl.Contract):
    audits: DynArray[Audit]
    audit_index: TreeMap[str, u32]
    user_audit_ids: TreeMap[Address, str]
    next_id: u256

    def __init__(self):
        pass

    @gl.public.write
    def analyze_contract(self, title: str, language: str, code: str) -> str:
        """Submit smart contract source code for AI security audit. Returns
        the new audit id."""
        clean_title = title.strip()[:MAX_TITLE_CHARS]
        clean_language = (language or "").strip()[:MAX_LANGUAGE_CHARS] or "Solidity"
        clean_code = code.strip()

        if not clean_title:
            raise gl.vm.UserError(f"{ERR_EXPECTED} title is required")
        if not clean_code:
            raise gl.vm.UserError(f"{ERR_EXPECTED} contract source code is required")
        if len(clean_code) > MAX_CODE_CHARS:
            raise gl.vm.UserError(f"{ERR_EXPECTED} contract source exceeds the {MAX_CODE_CHARS} character limit")

        # Both fully deterministic (pure functions of clean_code): every
        # node computes the identical value, so neither needs to go
        # through leader/validator comparison. code_hash is the source
        # commitment; static_findings feeds the score floor below and is
        # captured into the prompt-response normalization closures.
        code_hash = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()
        static_findings = _static_scan(clean_code)

        prompt = _build_audit_prompt(clean_language, clean_code)

        def leader_fn():
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            return _normalize_audit_response(raw, static_findings)

        def validator_fn(leaders_res: "gl.vm.Result") -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return _validator_agrees_with_error(leaders_res, leader_fn)

            leader_data = leaders_res.calldata

            # Everything below reasons about `leader_data`, which is the
            # LEADER'S OWN CLAIM about what it computed -- not something
            # this node executed itself. A leader is not bound to have
            # actually run the real contract code; GenLayer's consensus
            # model exists specifically because a leader can claim
            # anything. So this whole block is wrapped defensively: if
            # `leader_data` doesn't even have the expected shape (missing
            # keys, wrong types -- whether from a malicious leader or a
            # genuine bug), that must resolve to disagreement, never to
            # an uncaught exception escaping this function.
            try:
                if not isinstance(leader_data, dict):
                    return False

                # `static_findings` is fully deterministic (same source,
                # same scan, same result on every node -- see
                # _static_scan). The fixed description for each finding
                # is NOT LLM-generated free text; it's a constant string
                # from STATIC_FINDING_DESCRIPTIONS that the leader's own
                # execution is supposed to have injected into `risks`
                # (see _normalize_audit_response). Checking that it's
                # actually present in what the leader *claims* to have
                # computed doesn't require trusting "the leader ran the
                # same code" at all -- it's a direct, independently
                # verifiable fact about the claimed data itself. Without
                # this, a leader could claim a risk_level/risk_score that
                # happens to match what validators independently compute,
                # while silently claiming an unrelated or empty `risks`
                # list, since free text was otherwise never compared.
                leader_risks = leader_data.get("risks")
                if not isinstance(leader_risks, list):
                    return False
                for finding in static_findings:
                    if STATIC_FINDING_DESCRIPTIONS[finding] not in leader_risks:
                        return False

                leader_risk_level = leader_data.get("risk_level")
                leader_risk_score = leader_data.get("risk_score")
                if not isinstance(leader_risk_score, (int, float)):
                    return False
            except Exception:
                return False

            try:
                my_result = leader_fn()
            except Exception:
                # Leader succeeded but we couldn't reproduce any usable
                # result - reject rather than agree blindly.
                return False

            # risk_level is derived purely from risk_score (see
            # _derive_risk_level), so this is really an exact-match check
            # on a discrete risk bucket, not on an LLM-chosen label. Two
            # results can only agree here if their scores land in the same
            # bucket; the numeric check below is a tighter constraint on
            # top of that, not a separate, looser fallback.
            if leader_risk_level != my_result["risk_level"]:
                return False
            return abs(leader_risk_score - my_result["risk_score"]) <= RISK_SCORE_TOLERANCE

        audit = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        new_id = str(int(self.next_id))
        self.next_id = u256(int(self.next_id) + 1)

        owner = gl.message.sender_address
        record = Audit(
            id=new_id,
            owner=owner,
            title=clean_title,
            language=clean_language,
            risk_level=audit["risk_level"],
            risk_score=u32(audit["risk_score"]),
            summary=audit["summary"],
            recommendations_json=json.dumps(audit["recommendations"]),
            risks_json=json.dumps(audit["risks"]),
            code_hash=code_hash,
            static_findings_json=json.dumps(static_findings),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.audits.append(record)
        self.audit_index[new_id] = u32(len(self.audits) - 1)

        existing_ids = json.loads(self.user_audit_ids.get(owner, "[]"))
        existing_ids.append(new_id)
        self.user_audit_ids[owner] = json.dumps(existing_ids)

        return new_id

    @gl.public.view
    def get_analysis(self, audit_id: str) -> dict:
        if audit_id not in self.audit_index:
            raise gl.vm.UserError(f"{ERR_EXPECTED} audit '{audit_id}' not found")
        idx = self.audit_index[audit_id]
        return _audit_to_dict(self.audits[idx])

    @gl.public.view
    def verify_source(self, audit_id: str, code: str) -> bool:
        """Returns True iff `code` is exactly the source that was audited
        for `audit_id` (same normalization as analyze_contract: leading/
        trailing whitespace is trimmed before hashing). Lets a caller
        confirm a stored audit result actually corresponds to a specific
        piece of source, rather than a different or modified version."""
        if audit_id not in self.audit_index:
            raise gl.vm.UserError(f"{ERR_EXPECTED} audit '{audit_id}' not found")
        idx = self.audit_index[audit_id]
        candidate_hash = hashlib.sha256(code.strip().encode("utf-8")).hexdigest()
        return candidate_hash == self.audits[idx].code_hash

    @gl.public.view
    def get_all_analyses(self) -> list[dict]:
        return [_audit_to_dict(a) for a in self.audits]

    @gl.public.view
    def get_my_analyses(self, owner_address: str) -> list[dict]:
        try:
            owner = Address(owner_address)
        except Exception:
            raise gl.vm.UserError(f"{ERR_EXPECTED} invalid owner address: {owner_address!r}")
        ids_json = self.user_audit_ids.get(owner, "[]")
        ids = json.loads(ids_json)
        out = []
        for aid in ids:
            if aid in self.audit_index:
                out.append(_audit_to_dict(self.audits[self.audit_index[aid]]))
        return out

    @gl.public.view
    def get_stats(self) -> dict:
        total = len(self.audits)
        high = 0
        medium = 0
        for a in self.audits:
            if a.risk_level == "High":
                high += 1
            elif a.risk_level == "Medium":
                medium += 1
        low = total - high - medium
        return {
            "total_analyses": total,
            "high_risk": high,
            "medium_risk": medium,
            "low_risk": low,
        }
