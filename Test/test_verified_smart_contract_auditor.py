"""
Direct-mode tests for VerifiedSmartContractAuditor, focused on the
consensus-binding fix: previously `validator_fn` only ever checked
`risk_score` (within tolerance) and the `risk_level` bucket derived from
it, plus presence of the deterministic static-scan findings -- it never
independently checked `summary`/`recommendations`/the LLM's own `risks`
at all. Two materially different security reports could reach consensus
as long as their scores shared a bucket and stayed within tolerance.

Direct mode executes only the leader path when a contract method is
called normally; the captured `validator_fn` must be run explicitly via
`direct_vm.run_validator(leader_result=...)` to exercise consensus logic
against a specific (possibly adversarial) claimed leader result.
"""

CONTRACT = "contracts/verified_smart_contract_auditor.py"

AUDIT_PROMPT_MATCH = r"expert smart contract security auditor"
EQUIVALENCE_PROMPT_MATCH = r"checking whether two independently produced"

# A simple contract with no static-scan-triggering patterns (no
# selfdestruct/delegatecall/tx.origin/low-level .call{value:...}), so
# static_findings is always [] here and doesn't interact with the tests
# below -- static-findings enforcement is tested separately.
SAFE_CODE = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

# A contract that DOES trip the static scan (low-level call with value),
# used only by the static-findings regression test.
UNSAFE_CODE = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"""

HONEST_AUDIT_JSON = (
    '{"summary": "A vault contract with a withdraw function vulnerable to '
    'reentrancy.", "risks": ["Reentrancy vulnerability in withdraw()"], '
    '"recommendations": ["Add a reentrancy guard"], "risk_score": 50}'
)


def _mock_honest_audit(direct_vm):
    direct_vm.mock_llm(AUDIT_PROMPT_MATCH, HONEST_AUDIT_JSON)


# --------------------------------------------------------------------------
# Baseline: matching audits (leader's claim == validator's own recompute)
# accept without even needing the equivalence judge to be exercised
# adversarially.
# --------------------------------------------------------------------------
def test_matching_audit_is_accepted(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    _mock_honest_audit(direct_vm)
    direct_vm.mock_llm(EQUIVALENCE_PROMPT_MATCH, '{"equivalent": true}')

    audit_id = contract.analyze_contract("Vault", "Solidity", SAFE_CODE)
    analysis = contract.get_analysis(audit_id)
    assert analysis["risk_level"] == "Medium"
    assert analysis["risk_score"] == 50

    assert direct_vm.run_validator() is True


# --------------------------------------------------------------------------
# THE FIX: same risk_score bucket, well within tolerance, but a leader
# claiming ENTIRELY DIFFERENT findings/recommendations than what the
# validator itself independently found. Before the fix this was accepted
# unconditionally (only risk_score/risk_level were ever compared). Now the
# equivalence judge call is what decides -- this test simulates a judge
# correctly recognizing the mismatch.
# --------------------------------------------------------------------------
def test_leader_lies_about_findings_same_bucket_is_rejected(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    _mock_honest_audit(direct_vm)  # validator's own independent recompute
    # A correctly functioning judge sees these are about different issues.
    direct_vm.mock_llm(EQUIVALENCE_PROMPT_MATCH, '{"equivalent": false}')
    contract.analyze_contract("Vault", "Solidity", SAFE_CODE)

    lying_leader_result = {
        "summary": "A simple token contract with standard transfer logic.",
        "risks": ["Unbounded loop may run out of gas (DoS)"],
        "recommendations": ["Add a maximum iteration bound to the loop"],
        "risk_score": 45,  # same "Medium" bucket (34-66) as the honest 50,
        "risk_level": "Medium",  # and within RISK_SCORE_TOLERANCE (12) of it
    }

    assert direct_vm.run_validator(leader_result=lying_leader_result) is False


# --------------------------------------------------------------------------
# The corresponding legitimate case that must still pass: same substantive
# findings, different wording. Simulates a judge correctly recognizing
# they're the same issue.
# --------------------------------------------------------------------------
def test_worded_differently_same_findings_is_accepted(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    _mock_honest_audit(direct_vm)
    direct_vm.mock_llm(EQUIVALENCE_PROMPT_MATCH, '{"equivalent": true}')
    contract.analyze_contract("Vault", "Solidity", SAFE_CODE)

    reworded_leader_result = {
        "summary": "This is a fund-holding contract whose withdraw method "
        "can be re-entered via a malicious fallback before the balance is "
        "updated.",
        "risks": ["withdraw() is vulnerable to reentrancy: an attacker's "
        "fallback could re-enter before state fully settles"],
        "recommendations": ["Follow checks-effects-interactions strictly, "
        "or add a nonReentrant guard to withdraw()"],
        "risk_score": 55,  # still "Medium", within tolerance of 50
        "risk_level": "Medium",
    }

    assert direct_vm.run_validator(leader_result=reworded_leader_result) is True


# --------------------------------------------------------------------------
# Regression: existing exact checks still enforced.
# --------------------------------------------------------------------------
def test_risk_score_tolerance_still_enforced(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    _mock_honest_audit(direct_vm)  # validator recomputes risk_score=50
    direct_vm.mock_llm(EQUIVALENCE_PROMPT_MATCH, '{"equivalent": true}')
    contract.analyze_contract("Vault", "Solidity", SAFE_CODE)

    far_off_score = {
        "summary": HONEST_AUDIT_JSON,
        "risks": ["Reentrancy vulnerability in withdraw()"],
        "recommendations": ["Add a reentrancy guard"],
        "risk_score": 90,  # 40 points off, exceeds RISK_SCORE_TOLERANCE=12
        "risk_level": "High",
    }
    assert direct_vm.run_validator(leader_result=far_off_score) is False


def test_risk_level_bucket_mismatch_still_rejected(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    _mock_honest_audit(direct_vm)  # validator recomputes risk_score=50 (Medium)
    direct_vm.mock_llm(EQUIVALENCE_PROMPT_MATCH, '{"equivalent": true}')
    contract.analyze_contract("Vault", "Solidity", SAFE_CODE)

    wrong_bucket = {
        "summary": "A vault contract with a withdraw function vulnerable to reentrancy.",
        "risks": ["Reentrancy vulnerability in withdraw()"],
        "recommendations": ["Add a reentrancy guard"],
        "risk_score": 40,  # within 12 of 50, but claims "Low" -- inconsistent
        "risk_level": "Low",
    }
    assert direct_vm.run_validator(leader_result=wrong_bucket) is False


def test_static_finding_presence_still_enforced(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    # LLM under-reports on genuinely unsafe code: no mention of the
    # low-level call risk that the deterministic static scan will find in
    # UNSAFE_CODE regardless of what the LLM says.
    direct_vm.mock_llm(
        AUDIT_PROMPT_MATCH,
        '{"summary": "A simple vault.", "risks": [], '
        '"recommendations": [], "risk_score": 10}',
    )
    direct_vm.mock_llm(EQUIVALENCE_PROMPT_MATCH, '{"equivalent": true}')

    # The leader itself is forced (by _normalize_audit_response, run for
    # real even in Direct Mode's leader-only path) to include the static
    # finding and floor its score -- confirm that actually happened.
    audit_id = contract.analyze_contract("Vault", "Solidity", UNSAFE_CODE)
    analysis = contract.get_analysis(audit_id)
    assert "Static scan" in " ".join(analysis["risks"])
    assert analysis["risk_score"] >= 34

    # Now simulate a leader CLAIMING it found nothing (as if the forced
    # inclusion never happened) -- must be rejected regardless of what the
    # equivalence judge says, since this is an exact, deterministic check.
    claims_nothing_found = {
        "summary": "A simple vault.",
        "risks": [],
        "recommendations": [],
        "risk_score": 34,
        "risk_level": "Medium",
    }
    assert direct_vm.run_validator(leader_result=claims_nothing_found) is False
