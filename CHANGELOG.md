# Changelog

All notable changes to `sm-locp` are documented here. The project follows
[Semantic Versioning](https://semver.org/) — see [`GOVERNANCE.md`](./GOVERNANCE.md) for the
full versioning and Protocol-stability policy.

## [0.2.0] - 2026-04-16

### Added

- **Persistence layer** (`sm_locp.persistence`) — stable Protocol surface for pluggable backends.
  - `PolicyStore`, `CredentialStore`, `StatusListStore`, `EvaluationStore` — four Protocols covering
    the entity types the engine needs to persist.
  - `Persistence` facade bundling all four stores.
  - Frozen record types: `PolicyRecord`, `CredentialRecord`, `StatusListRecord`, `EvaluationRecord`,
    and `ContentHash`.
  - Canonical JSON + SHA-256 content hashing helpers.
  - `InMemoryPersistence` — zero-dependency reference implementation backed by `threading.Lock`.
  - `FileSystemPersistence` — disk-backed implementation, `MRRLoader`-compatible layout for
    single-tenant policies, tenant-sharded layout for multi-tenant.
  - Reusable `PersistenceConformance` test suite (19 contract tests) that any third-party backend
    inherits to prove compliance.
- `PROTOCOL_VERSION = "1.0.0"` — semver-versioned Protocol surface. v1 is frozen; breaking changes
  require a new major Protocol version and a 30-day RFC window.
- `GOVERNANCE.md` — scope, versioning policy, conformance expectations, and contribution rules.

### Published guarantees (Protocol v1)

- `PolicyStore.put` is idempotent when content hash matches; rejects mutated bodies at existing
  versions with `PolicyStoreConflictError`.
- `StatusListStore.set_bit` and `reserve_index` are atomic under concurrent writes (verified by
  conformance test with 8 threads × 32 ops).
- `EvaluationStore` is append-only; history is never mutated.
- `list(...)` / `find_for_subject(...)` return iterators — implementers stream, callers must not
  assume bounded memory.

## [0.1.0] - 2026-04-15

Initial release.

- Defeasible logic engine (strict, defeasible, defeater rules).
- MRR (Machine-Readable Regulations) JSON format, loader, and evaluator.
- W3C Verifiable Credential generator and verifier (Ed25519).
- StatusList2021 revocation primitives.
- Regime provider interface.
- JSON theory loader bridging MRR policies to defeasible theories.

[0.2.0]: https://github.com/Sharathvc23/sm-locp/releases/tag/v0.2.0
[0.1.0]: https://github.com/Sharathvc23/sm-locp/releases/tag/v0.1.0
