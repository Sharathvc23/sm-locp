# Open Compliance Protocol (OCP)

**A defeasible-logic framework for autonomous, machine-verifiable regulatory compliance**

*Research by [stellarminds.ai](https://stellarminds.ai)*

---

## Abstract

The Open Compliance Protocol (OCP) is a framework for encoding regulatory obligations as machine-executable logic and producing cryptographic proofs of compliance. It combines defeasible reasoning — a form of non-monotonic logic that natively handles rules, exceptions, and overrides — with W3C Verifiable Credentials to create compliance proofs that any third party can verify without re-running the evaluation.

OCP is domain-agnostic. The engine knows nothing about any specific regulatory domain. Domain knowledge is injected through pluggable regime providers and machine-readable regulation (MRR) policy files.

## 1. Problem

Automated compliance today relies on decision trees, forward-chaining rule engines, or hard-coded conditionals. Each breaks down when regulations interact:

- **Decision trees** flatten priority structure. Two regulatory bodies issuing contradictory guidance requires manual tree restructuring. Every new exception doubles the branch count.
- **Forward-chaining engines** (Drools, CLIPS) fire all applicable rules in working-memory order. They have no native concept of "this rule overrides that one" or "this exception blocks a conclusion without asserting the opposite."
- **Hard-coded logic** is brittle. A single upstream policy change cascades through hundreds of conditionals.

None of these approaches produce machine-verifiable compliance proofs. An entity claims compliance; a regulator must trust the claim or audit the process. There is no cryptographic binding between the rules evaluated, the state observed, and the conclusion reached.

## 2. Defeasible Logic for Regulatory Reasoning

OCP uses defeasible logic because it maps directly to how regulations are structured in practice — general obligations, specific exceptions, and emergency overrides.

Rules come in three strengths:

| Type | Notation | Behavior | Regulatory analogue |
|------|----------|----------|---------------------|
| **Strict** | A → B | Always holds when antecedents are true | Absolute prohibitions, mandatory penalties |
| **Defeasible** | A ⇒ B | Holds unless defeated by a higher-priority rule or defeater | Standard compliance obligations |
| **Defeater** | A ~> ¬B | Blocks a conclusion without asserting the opposite | Exceptions, waivers, emergency overrides |

**Conflict resolution** is built into the inference step. When two defeasible rules draw opposite conclusions, the one with higher priority wins. When a defeater is applicable, it blocks the defeasible conclusion regardless of priority. Strict rules always override defeasible ones.

**Skeptical reasoning**: A conclusion is only accepted if it survives all possible attacks. This conservative posture is appropriate for compliance, where a false positive (claiming compliance when non-compliant) is more dangerous than a false negative.

**Cycle detection**: The engine detects cycles in the defeat relation before evaluation and logs warnings, ensuring the reasoning process terminates even in adversarial rule sets.

## 3. The OBSERVE — CHECK — PROVE Loop

OCP structures compliance as a continuous three-phase loop:

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ OBSERVE │────▶│  CHECK  │────▶│  PROVE  │
│         │     │         │     │         │
│ Gather  │     │ Evaluate│     │ Sign VC │
│ state   │     │ against │     │ with    │
│         │     │ rules   │     │ Ed25519 │
└─────────┘     └─────────┘     └─────────┘
     ▲                               │
     └───────────── TTL expires ─────┘
```

**OBSERVE**: Gather the current operational state from sensors, databases, APIs, or agent self-reports. The state is encoded as a dictionary of key-value pairs.

**CHECK**: Evaluate at two complementary levels:
- *MRR evaluation* — each policy specifies conditions with typed operators (`==`, `>=`, `in`, `matches`, etc.), thresholds, and weights. The evaluator checks every condition and produces a structured result with pass/fail per condition, overall compliance status, and a confidence score.
- *Defeasible reasoning* — the observed facts are fed into a defeasible theory. The engine derives which conclusions hold, which are defeated, and which rules blocked them. This handles cross-regime conflicts that simple condition checking cannot.

**PROVE**: The evaluation result is wrapped in a W3C Verifiable Credential, signed with the issuer's Ed25519 key. The credential carries the rule ID, compliance status, confidence, evaluation timestamp, and a SHA-256 hash of the ruleset applied. Any third party with the issuer's public key can verify the proof without re-running the evaluation.

The loop runs continuously. Each iteration produces a fresh credential with a configurable TTL (typically 5 minutes to 24 hours), ensuring proofs stay current.

## 4. Machine-Readable Regulations (MRR)

OCP defines a JSON format for encoding regulatory conditions:

```json
{
  "rule_id": "example-cert-check",
  "agency": "AUTHORITY_NAME",
  "conditions": [
    {"field": "operator.certification_valid", "operator": "==", "value": true, "required": true, "weight": 1.0},
    {"field": "operator.training_hours", "operator": ">=", "value": 40, "required": true, "weight": 0.8}
  ],
  "applicability": {"facility_type": ["warehouse", "factory"]},
  "certification": {"self_certifiable": true, "proof_format": "verifiable_credential", "ttl_seconds": 86400}
}
```

MRR policies and defeasible theories operate at different abstraction levels and compose naturally:

- **MRR policies** are concrete, data-level checks: "Is `operator.training_hours >= 40`?" They live as versioned JSON files, hashed for tamper detection.
- **Defeasible theories** are abstract, logic-level reasoning: "If the operator is certified AND meets training requirements, then operation is permitted — UNLESS the certification has expired."

The `JsonTheoryLoader` bridges these layers by converting MRR conditions into defeasible rules. Required conditions become strict rules; optional conditions become defeasible rules; negation-pattern conditions become defeaters.

## 5. Cryptographic Compliance Proofs

The compliance proof is a W3C Verifiable Credential (VC v1) with the following properties:

- **Ed25519 signatures** — fast, compact signing. The proof is computed over canonical JSON (sorted keys, no whitespace) for deterministic verification.
- **StatusList2021 revocation** — each credential is assigned an index in a gzip-compressed bitstring. To revoke, the issuer sets the bit. Verifiers check the status list credential (itself a signed VC) to confirm non-revocation.
- **Ruleset binding** — the credential subject includes `ruleset_hash`, `ruleset_version`, and `policy_hash`. This lets a verifier confirm exactly which version of the regulations was applied, preventing "phantom compliance" under a superseded ruleset.
- **Short TTL** — credentials expire quickly by default, forcing continuous re-evaluation rather than stale proofs.

The credential format is standard W3C VC v1, so any VC-compatible wallet, verifier, or registry can process it without OCP-specific tooling.

## 6. Extension Model

OCP is domain-agnostic by design. Domain knowledge enters through two extension points:

**RegimeProvider** (Python protocol / abstract base class): Any class implementing `regime_id`, `jurisdiction`, `domain`, and `build_theory()` can serve as a regime provider. The `RegulatoryTheoryBuilder` fluent API makes rule definition concise. This is the primary extension point for organisations encoding their regulatory expertise.

**MRR policy files** (JSON): For data-level conditions, organisations add JSON files to a policies directory. The `MRRLoader` discovers them automatically. The `JsonTheoryLoader` can convert them into defeasible rules.

Both are composable. A regime provider can build a theory combining rules from MRR policies, programmatic rules, and rules imported from other providers. The `get_combined_theory()` method merges rules from multiple regimes for cross-regime reasoning.

## 7. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Application Layer                      │
│  (your domain: safety, environmental, financial, etc.)   │
├──────────────────────────────────────────────────────────┤
│  RegimeProvider     │  MRR Policy Files (.json)          │
│  build_theory()     │  conditions, applicability         │
├─────────────────────┴────────────────────────────────────┤
│                 OCP Core Engine                           │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Defeasible   │  │  MRR         │  │  W3C VC       │  │
│  │  Theory       │  │  Evaluator   │  │  Generator    │  │
│  │              │  │              │  │  + Verifier   │  │
│  │  strict      │  │  conditions  │  │  Ed25519      │  │
│  │  defeasible  │  │  operators   │  │  StatusList   │  │
│  │  defeater    │  │  confidence  │  │  2021         │  │
│  └──────────────┘  └──────────────┘  └───────────────┘  │
├──────────────────────────────────────────────────────────┤
│  Python 3.10+ │ cryptography (Ed25519) │ zero other deps │
└──────────────────────────────────────────────────────────┘
```

## 8. Limitations and Future Work

- **No persistence layer** — the current implementation is in-memory. Production deployments should implement persistent storage for status lists and evaluation history.
- **No multi-regime orchestration** — cross-regime conflict resolution requires combining theories manually via `get_combined_theory()`. A higher-level orchestrator is left to implementors.
- **No semantic search** — policies are matched by applicability filters, not by natural language query. Embedding-based retrieval is a natural extension.
- **Confidence model is simple** — weighted average of condition results. Bayesian or Monte Carlo confidence models are possible via the `risk_model` field in MRR policies.

---

*First published: 2026-04-15 | Last modified: 2026-04-15*

*[stellarminds.ai](https://stellarminds.ai) — Research Contribution to [Project NANDA](https://projectnanda.org)*
