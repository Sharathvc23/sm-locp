# Governance

`sm-locp` is the reference implementation of the **Open Compliance Protocol (OCP)** — a defeasible-logic compliance engine, machine-readable regulations format, and W3C Verifiable Credential issuance layer. This document describes how the project is governed, what is in and out of scope, and how the Protocol surface evolves.

---

## Scope

The `sm-locp` repository is intentionally **narrow**. Its scope is:

| In scope | Out of scope |
|---|---|
| Defeasible logic engine | Curated regulatory corpora for specific domains |
| MRR JSON schema and loader | Regulatory change-detection pipelines |
| W3C Verifiable Credential generator & verifier | NL → MRR authoring tools |
| StatusList2021 revocation primitives | Cross-jurisdiction conflict resolvers |
| Persistence Protocol (policy / credential / status list / evaluation stores) | Multi-tenant SaaS operations layer |
| Zero-dependency reference backends (in-memory, filesystem) | Enterprise connectors (ERP/EHR/CRM integrations) |
| Conformance test suite | Issuer reputation / trust network |

Work that falls outside this scope belongs in separate projects — either downstream open-source repositories that depend on `sm-locp`, or commercial products that implement the public Protocol interfaces. This boundary is deliberate: it lets the Protocol stabilise while the ecosystem above it evolves freely.

## Versioning policy

`sm-locp` follows [Semantic Versioning 2.0.0](https://semver.org/):

- **Patch** (`0.x.y` → `0.x.(y+1)`) — bug fixes, documentation, internal refactors. No public API changes.
- **Minor** (`0.x.y` → `0.(x+1).0`) — additive changes: new backends, new helpers, new optional parameters with safe defaults. Existing code keeps working.
- **Major** (`x.y.z` → `(x+1).0.0`) — breaking changes to the public API.

The **persistence Protocol surface** is separately versioned under `sm_locp.persistence.PROTOCOL_VERSION`. It is governed by a stricter compatibility rule:

- Protocol **v1 is frozen.** No method signatures will change, no methods will be removed, and no new required methods will be added within v1.
- Additive Protocol extensions (e.g., new optional kwargs with defaults, new concrete helper types) may happen within v1 and are announced in the changelog.
- Breaking Protocol changes require a new major Protocol version (`PolicyStoreV2`, etc.), a 30-day public RFC window, and a documented migration path. v1 and v2 will coexist for at least one minor release of `sm-locp`.

Backends declare compatibility by referencing the Protocol version they implement:

```python
from sm_locp.persistence import PROTOCOL_VERSION
assert PROTOCOL_VERSION.startswith("1.")
```

## Conformance

Every backend — reference or third-party — is expected to pass the conformance suite in `tests/persistence/conformance.py`. The suite is the authoritative behavioural specification; the Protocol docstrings describe intent, but the tests are what backends are judged against.

Running the suite against a new backend:

```python
from sm_locp.persistence import Persistence
from tests.persistence.conformance import PersistenceConformance

class TestMyBackend(PersistenceConformance):
    persistence_factory = staticmethod(MyBackend)
```

If all tests pass against your backend, it is a conformant Protocol v1 implementation.

## Contributions

Contributions are welcome under the MIT license. Pull requests should:

1. Include tests (conformance tests for new backends, unit tests for new helpers).
2. Pass `ruff check`, `mypy --strict`, and the full test suite.
3. Not expand the Protocol surface without an accompanying RFC issue.
4. Not introduce domain-specific regulatory content (those belong in downstream corpora, not in this repo).

## Attribution

`sm-locp` is a personal research contribution by [Stellarminds.ai](https://stellarminds.ai), aligned with [Project NANDA](https://projectnanda.org) standards. The Protocol is open; proprietary corpora, operational platforms, and commercial offerings built on top of the Protocol remain the property of their respective authors.
