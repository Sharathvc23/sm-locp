# SM LOCP

**Stellarminds Open Compliance Protocol** -- a defeasible-logic compliance engine with machine-readable regulations and W3C Verifiable Credentials.

SM LOCP lets autonomous agents observe their operational state, check it against regulatory theories expressed in defeasible logic, and produce cryptographic compliance proofs as W3C Verifiable Credentials.

## Features

- **Defeasible Logic Engine** -- strict rules, defeasible rules, and defeaters with priority-based conflict resolution and skeptical reasoning.
- **Machine-Readable Regulations (MRR)** -- JSON format for encoding regulatory conditions, applicability, and certification metadata.
- **W3C Verifiable Credentials** -- Ed25519-signed compliance proofs with StatusList2021 revocation support.
- **Regime Providers** -- pluggable provider interface so any regulatory domain can be modelled and composed.
- **JSON Theory Loader** -- convert MRR policies into defeasible theories automatically.

## Installation

```bash
pip install git+https://github.com/Sharathvc23/sm-locp.git
```

## Quick Start

```python
from sm_locp import (
    Literal,
    RegulatoryTheoryBuilder,
    VCGenerator,
    ComplianceCredentialSubject,
)

# Build a theory
theory = (
    RegulatoryTheoryBuilder("WAREHOUSE")
    .defeasible("D1", ["operator_certified"], "permitted", priority=5)
    .defeater("X1", ["cert_expired"], "~permitted")
    .fact("operator_certified")
    .build()
)

# Query
result = theory.query(Literal.parse("permitted"))
print(result.derived)  # True

# Generate a Verifiable Credential
generator = VCGenerator("did:web:example.com", private_key_b64="<base64-key>")
subject = ComplianceCredentialSubject(
    id="did:web:example.com",
    rule_id="D1",
    status="COMPLIANT",
    confidence=result.confidence,
)
credential = generator.generate(subject)
print(credential.to_json())
```

## MRR Format

Policies are expressed as JSON with conditions, applicability filters, and certification metadata:

```json
{
  "rule_id": "ws-forklift-cert",
  "agency": "WAREHOUSE_SAFETY",
  "title": "Forklift Operator Certification",
  "version": "1.0.0",
  "conditions": [
    {"field": "operator.certification_valid", "operator": "==", "value": true, "required": true},
    {"field": "operator.training_hours", "operator": ">=", "value": 40, "required": true}
  ],
  "certification": {"self_certifiable": true, "proof_format": "verifiable_credential", "ttl_seconds": 86400}
}
```

## Verifiable Credentials

```python
from sm_locp import MRRLoader, MRREvaluator, VCGenerator

loader = MRRLoader(policies_path="./policies", validate_schema=False)
evaluator = MRREvaluator(loader)
result = evaluator.evaluate("ws-forklift-cert", state)

generator = VCGenerator("did:web:issuer.example", private_key_b64)
credential = generator.generate_from_evaluation(result)
```

## Custom Regime

```python
from sm_locp import BaseRegimeProvider, DefeasibleTheory, RegulatoryTheoryBuilder

class MyRegime(BaseRegimeProvider):
    @property
    def regime_id(self) -> str:
        return "my-regime"

    @property
    def jurisdiction(self) -> str:
        return "US"

    @property
    def domain(self) -> str:
        return "environmental"

    def build_theory(self) -> DefeasibleTheory:
        return (
            RegulatoryTheoryBuilder("ENV")
            .strict("S1", ["emissions_exceeded"], "violation")
            .defeasible("D1", ["has_waiver"], "exempt", priority=5)
            .defeater("X1", ["waiver_expired"], "~exempt")
            .build()
        )
```

## Related Packages

| Package | Description |
|---------|-------------|
| [sm-bridge](https://github.com/Sharathvc23/sm-bridge) | NANDA-compatible registry endpoints, AgentFacts models, and delta sync |
| [sm-airlock](https://github.com/Sharathvc23/sm-airlock) | Attribute-level capability restriction for agent plugins |
| [sm-enclave](https://github.com/Sharathvc23/sm-enclave) | Speculative execution sandbox with staged side effects and commit/discard |
| [sm-model-provenance](https://github.com/Sharathvc23/sm-model-provenance) | Model identity, versioning, and provenance metadata |
| [sm-model-governance](https://github.com/Sharathvc23/sm-model-governance) | Cryptographic model approval with Ed25519 signatures and quorum |
| [sm-model-integrity-layer](https://github.com/Sharathvc23/sm-model-integrity-layer) | Policy verification, attestation, and integrity checks |

## License

MIT

---

*First published: 2026-04-15 | Last modified: 2026-04-15*

*[stellarminds.ai](https://stellarminds.ai) -- Research Contribution to [Project NANDA](https://projectnanda.org)*
