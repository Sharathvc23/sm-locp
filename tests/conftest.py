"""Shared test fixtures for sm-locp."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_locp.engine import (
    DefeasibleTheory,
    Literal,
    RegulatoryTheoryBuilder,
    Rule,
    RuleType,
)
from sm_locp.vc_generator import VCGenerator, reset_vc_generator_state
from sm_locp.vc_verifier import VCVerifier

# Re-use the example regime from examples/
from examples.example_regime import WarehouseSafetyRegime


@pytest.fixture()
def simple_theory() -> DefeasibleTheory:
    """A small DefeasibleTheory with a handful of rules for quick tests."""
    theory = (
        RegulatoryTheoryBuilder("TEST")
        .strict("T_S1", ["violation_found"], "penalty_required",
                description="Violation triggers penalty")
        .defeasible("T_D1", ["has_permit"], "operation_allowed",
                    priority=5, description="Permit allows operation")
        .defeater("T_X1", ["permit_revoked"], "~operation_allowed",
                  description="Revoked permit blocks operation")
        .fact("has_permit")
        .build()
    )
    return theory


@pytest.fixture()
def warehouse_regime() -> WarehouseSafetyRegime:
    """Instance of the example WarehouseSafetyRegime."""
    return WarehouseSafetyRegime()


@pytest.fixture()
def ed25519_keypair() -> tuple[str, str]:
    """Generate a test Ed25519 keypair (private_key_b64, public_key_b64)."""
    private_key = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(private_key.private_bytes_raw()).decode("ascii")
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")
    return private_b64, public_b64


@pytest.fixture()
def vc_generator(ed25519_keypair: tuple[str, str]) -> VCGenerator:
    """VCGenerator initialised with a fresh test keypair."""
    reset_vc_generator_state()
    private_b64, _ = ed25519_keypair
    return VCGenerator(
        issuer_did="did:web:test.stellarminds.ai",
        private_key_b64=private_b64,
        default_ttl_seconds=3600,
    )


@pytest.fixture()
def vc_verifier(ed25519_keypair: tuple[str, str]) -> VCVerifier:
    """VCVerifier with the test public key registered."""
    _, public_b64 = ed25519_keypair
    verifier = VCVerifier()
    verifier.register_public_key("did:web:test.stellarminds.ai", public_b64)
    return verifier
