"""End-to-end compliance example using the Warehouse Safety regime.

Demonstrates:
1. Building a defeasible theory from a regime provider
2. Querying with facts and observing defeater behaviour
3. Loading and evaluating an MRR policy
4. Generating and verifying a W3C Verifiable Credential
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_locp.engine import Literal
from sm_locp.mrr_evaluator import MRREvaluator
from sm_locp.mrr_loader import MRRLoader
from sm_locp.vc_generator import VCGenerator
from sm_locp.vc_verifier import VCVerifier

from .example_regime import WarehouseSafetyRegime


def _generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair and return (private_b64, public_b64)."""
    private_key = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(
        private_key.private_bytes_raw()
    ).decode("ascii")
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")
    return private_b64, public_b64


def main() -> None:
    # ------------------------------------------------------------------
    # Step 1: Build a defeasible theory from the warehouse-safety regime
    # ------------------------------------------------------------------
    regime = WarehouseSafetyRegime()
    theory = regime.build_theory()
    print(f"Regime : {regime.regime_id}")
    print(f"Rules  : {len(theory.get_rules())}")
    print()

    # ------------------------------------------------------------------
    # Step 2: Add facts -- operator is certified
    # ------------------------------------------------------------------
    theory.add_fact(Literal.parse("forklift_operator"))
    theory.add_fact(Literal.parse("has_certification"))
    print("Facts added: forklift_operator, has_certification")

    # ------------------------------------------------------------------
    # Step 3: Query permitted_operation -- should derive True
    # ------------------------------------------------------------------
    result = theory.query(Literal.parse("permitted_operation"))
    print(f"Query  : permitted_operation -> derived={result.derived}, confidence={result.confidence}")
    assert result.derived, "Expected permitted_operation to be derived"
    print()

    # ------------------------------------------------------------------
    # Step 4: Add fact expired_certification (triggers defeater WS_X1)
    # ------------------------------------------------------------------
    theory.add_fact(Literal.parse("expired_certification"))
    print("Fact added: expired_certification")

    # ------------------------------------------------------------------
    # Step 5: Query again -- should be defeated (False)
    # ------------------------------------------------------------------
    result = theory.query(Literal.parse("permitted_operation"))
    print(f"Query  : permitted_operation -> derived={result.derived}")
    if result.blocked_by:
        print(f"  Blocked by: {result.blocked_by.rule_id} ({result.blocked_by.description})")
    assert not result.derived, "Expected permitted_operation to be defeated"
    print()

    # ------------------------------------------------------------------
    # Step 6: Load the example MRR policy
    # ------------------------------------------------------------------
    policy_dir = Path(__file__).parent
    loader = MRRLoader(policies_path=policy_dir, validate_schema=False)
    policy = loader.load_file(policy_dir / "example_policy.json")
    print(f"MRR Policy loaded: {policy.rule_id} -- {policy.title}")
    print(f"  Conditions: {len(policy.conditions)}")

    # ------------------------------------------------------------------
    # Step 7: Evaluate state against the MRR policy
    # ------------------------------------------------------------------
    state = {
        "operator": {
            "certification_valid": True,
            "training_hours": 50,
            "incident_free_days": 45,
        }
    }
    evaluator = MRREvaluator(loader)
    eval_result = evaluator.evaluate(policy.rule_id, state)
    print(f"Evaluation: {eval_result.status.value} (confidence={eval_result.confidence:.2f})")
    for cr in eval_result.condition_results:
        symbol = "PASS" if cr.passed else "FAIL"
        print(f"  [{symbol}] {cr.condition.field} {cr.condition.operator} {cr.condition.value}")
    print()

    # ------------------------------------------------------------------
    # Step 8: Generate a W3C Verifiable Credential from the evaluation
    # ------------------------------------------------------------------
    private_b64, public_b64 = _generate_keypair()
    issuer_did = "did:web:stellarminds.ai:warehouse-safety"
    generator = VCGenerator(issuer_did, private_b64, default_ttl_seconds=86400)
    credential = generator.generate_from_evaluation(eval_result, subject_did=issuer_did)
    print("Verifiable Credential generated:")
    print(f"  ID     : {credential.id}")
    print(f"  Issuer : {credential.issuer}")
    print(f"  Status : {credential.credential_subject.status}")
    print()

    # ------------------------------------------------------------------
    # Step 9: Verify the credential
    # ------------------------------------------------------------------
    verifier = VCVerifier()
    verifier.register_public_key(issuer_did, public_b64)
    verification = verifier.verify(credential.to_dict(), check_expiration=True)
    print(f"Verification: valid={verification.valid}, signature={verification.signature_valid}")
    if verification.errors:
        print(f"  Errors: {verification.errors}")

    print()
    print("Done.  All steps completed successfully.")


if __name__ == "__main__":
    main()
