"""sm-locp: Stellarminds Open Compliance Protocol.

Defeasible logic engine, machine-readable regulations, W3C Verifiable
Credentials, and regime providers for autonomous compliance.
"""

__version__ = "0.1.0"

from .engine import (
    DefeasibleTheory,
    DerivationStep,
    Literal,
    QueryResult,
    RegulatoryTheoryBuilder,
    Rule,
    RuleType,
    RuleValidationError,
)
from .json_theory_loader import JsonTheoryLoader, RulesManifest
from .mrr_evaluator import ComplianceStatus, ConditionResult, EvaluationResult, MRREvaluator
from .mrr_loader import MRRCertification, MRRCondition, MRRDataSource, MRRLoader, MRRPolicy
from .regime import BaseRegimeProvider, RegimeProvider
from .status_list import StatusList2021, StatusListEntry, verify_status_list_credential
from .vc_generator import (
    ComplianceCredential,
    ComplianceCredentialSubject,
    CredentialStatus,
    VCGenerator,
    VCProof,
)
from .vc_verifier import VCVerifier, VerificationResult

__all__ = [
    # Engine
    "DefeasibleTheory",
    "DerivationStep",
    "Literal",
    "QueryResult",
    "RegulatoryTheoryBuilder",
    "Rule",
    "RuleType",
    "RuleValidationError",
    # MRR Loader
    "MRRLoader",
    "MRRPolicy",
    "MRRCondition",
    "MRRDataSource",
    "MRRCertification",
    # MRR Evaluator
    "MRREvaluator",
    "EvaluationResult",
    "ConditionResult",
    "ComplianceStatus",
    # VC Generator
    "VCGenerator",
    "ComplianceCredential",
    "ComplianceCredentialSubject",
    "CredentialStatus",
    "VCProof",
    # VC Verifier
    "VCVerifier",
    "VerificationResult",
    # Status List
    "StatusList2021",
    "StatusListEntry",
    "verify_status_list_credential",
    # JSON Theory Loader
    "JsonTheoryLoader",
    "RulesManifest",
    # Regime
    "RegimeProvider",
    "BaseRegimeProvider",
]
