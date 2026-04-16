"""MRR (Machine-Readable Regulations) loader for LOCP.

Loads, validates, and provides access to regulatory policies encoded as JSON.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import jsonschema

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    logger.warning("jsonschema not available -- MRR schema validation disabled")

# Default policies path relative to this module
DEFAULT_POLICIES_PATH = Path(__file__).parent / "policies"


@dataclass
class MRRCondition:
    """A single condition in an MRR policy."""

    field: str
    operator: str
    value: Any
    required: bool = True
    weight: float = 1.0
    description: str = ""
    error_message: str = ""


@dataclass
class MRRDataSource:
    """Data source configuration for an MRR policy."""

    type: str
    endpoint: str | None = None
    field_mapping: dict[str, str] = field(default_factory=dict)


@dataclass
class MRRCertification:
    """Certification configuration for an MRR policy."""

    self_certifiable: bool = True
    proof_format: str = "verifiable_credential"
    ttl_seconds: int = 300


@dataclass
class MRRPolicy:
    """A parsed MRR policy ready for evaluation."""

    rule_id: str
    agency: str
    cfr_reference: str
    version: str
    title: str
    description: str
    conditions: list[MRRCondition]
    effective_date: str | None = None
    applicability: dict[str, list[str]] = field(default_factory=dict)
    data_sources: list[MRRDataSource] = field(default_factory=list)
    certification: MRRCertification = field(default_factory=MRRCertification)
    risk_model: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MRRPolicy:
        """Create an MRRPolicy from a dictionary."""
        conditions = [
            MRRCondition(
                field=c["field"],
                operator=c["operator"],
                value=c["value"],
                required=c.get("required", True),
                weight=c.get("weight", 1.0),
                description=c.get("description", ""),
                error_message=c.get("error_message", ""),
            )
            for c in data.get("conditions", [])
        ]

        data_sources = [
            MRRDataSource(
                type=ds["type"],
                endpoint=ds.get("endpoint"),
                field_mapping=ds.get("field_mapping", {}),
            )
            for ds in data.get("data_sources", [])
        ]

        cert_data = data.get("certification", {})
        certification = MRRCertification(
            self_certifiable=cert_data.get("self_certifiable", True),
            proof_format=cert_data.get("proof_format", "verifiable_credential"),
            ttl_seconds=cert_data.get("ttl_seconds", 300),
        )

        return cls(
            rule_id=data["rule_id"],
            agency=data["agency"],
            cfr_reference=data["cfr_reference"],
            version=data["version"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            conditions=conditions,
            effective_date=data.get("effective_date"),
            applicability=data.get("applicability", {}),
            data_sources=data_sources,
            certification=certification,
            risk_model=data.get("risk_model", {}),
        )


class MRRLoader:
    """Loads and manages MRR policy files."""

    # Schema file location relative to policies_path
    SCHEMA_FILENAME = "schema/mrr.schema.json"

    # Ruleset version (updated when policies change)
    RULESET_VERSION = "2024.1"

    def __init__(
        self,
        policies_path: Path | None = None,
        *,
        validate_schema: bool = True,
    ) -> None:
        """Initialize the MRR loader.

        Args:
            policies_path: Path to the policies directory. Defaults to bundled policies.
            validate_schema: Whether to validate policies against MRR JSON Schema.
        """
        self._policies_path = Path(policies_path) if policies_path else DEFAULT_POLICIES_PATH
        self._policies: dict[str, MRRPolicy] = {}
        self._raw_policies: dict[str, bytes] = {}  # Raw JSON bytes for hashing
        self._loaded = False
        self._validate_schema = validate_schema and HAS_JSONSCHEMA
        self._schema: dict[str, Any] | None = None
        self._ruleset_hash: str | None = None
        self._load_errors: list[dict[str, str]] = []

        if validate_schema and not HAS_JSONSCHEMA:
            logger.warning("jsonschema not installed; MRR schema validation disabled")

    def _load_schema(self) -> dict[str, Any] | None:
        """Load the MRR JSON Schema for validation.

        Returns:
            The schema as a dictionary, or None if unavailable.
        """
        if self._schema is not None:
            return self._schema

        schema_path = self._policies_path / self.SCHEMA_FILENAME
        if not schema_path.exists():
            logger.warning("MRR schema not found at %s", schema_path)
            return None

        try:
            with schema_path.open("r", encoding="utf-8") as f:
                self._schema = json.load(f)
            logger.debug("Loaded MRR schema from %s", schema_path)
            return self._schema
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load MRR schema: %s", e)
            return None

    def _validate_policy(self, data: dict[str, Any], source: str) -> bool:
        """Validate a policy dictionary against the MRR schema.

        Args:
            data: The policy data to validate.
            source: Source file path for error messages.

        Returns:
            True if valid (or validation disabled), False if validation failed.
        """
        if not self._validate_schema:
            return True

        schema = self._load_schema()
        if schema is None:
            logger.error("MRR schema unavailable -- failing closed for %s", source)
            return False  # Fail-closed: don't trust unvalidated policies

        try:
            jsonschema.validate(data, schema)
            return True
        except jsonschema.ValidationError as e:
            logger.error(
                "MRR schema validation failed for %s: %s (path: %s)",
                source,
                e.message,
                ".".join(str(p) for p in e.absolute_path),
            )
            return False
        except jsonschema.SchemaError as e:
            logger.error("Invalid MRR schema: %s -- failing closed", e.message)
            return False  # Fail-closed: invalid schema means untrustworthy validation

    @property
    def policies_path(self) -> Path:
        """Get the policies directory path."""
        return self._policies_path

    def load_all(self) -> dict[str, MRRPolicy]:
        """Load all policies from the policies directory.

        Returns:
            Dictionary mapping rule_id to MRRPolicy.
        """
        if self._loaded:
            return self._policies

        self._policies = {}

        if not self._policies_path.exists():
            logger.warning("Policies path does not exist: %s", self._policies_path)
            return self._policies

        # Recursively scan for ALL JSON files in the policies directory
        for policy_file in self._policies_path.glob("**/*.json"):
            # Skip schema files
            if "schema" in policy_file.parts:
                continue

            try:
                policy = self.load_file(policy_file, skip_validation=True)
                self._policies[policy.rule_id] = policy
                logger.debug("Loaded policy: %s from %s", policy.rule_id, policy_file)
            except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
                logger.error("Failed to load policy %s: %s", policy_file, e, exc_info=True)
                self._load_errors.append({"file": str(policy_file), "error": str(e)})

        self._loaded = True
        logger.info("Loaded %d MRR policies from %s", len(self._policies), self._policies_path)
        return self._policies

    def load_file(self, path: Path, *, skip_validation: bool = False) -> MRRPolicy:
        """Load a single policy file.

        Args:
            path: Path to the JSON policy file.
            skip_validation: Skip schema validation for this file.

        Returns:
            Parsed MRRPolicy.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            json.JSONDecodeError: If the file isn't valid JSON.
            KeyError: If required fields are missing.
            ValueError: If schema validation fails.
        """
        # Read raw bytes for hashing
        raw_bytes = path.read_bytes()
        data = json.loads(raw_bytes.decode("utf-8"))

        # Validate against MRR schema
        if not skip_validation and not self._validate_policy(data, str(path)):
            raise ValueError(f"MRR schema validation failed for {path}")

        policy = MRRPolicy.from_dict(data)

        # Store raw bytes for hash computation
        self._raw_policies[policy.rule_id] = raw_bytes

        return policy

    def get(self, rule_id: str) -> MRRPolicy | None:
        """Get a policy by rule_id.

        Args:
            rule_id: The unique rule identifier.

        Returns:
            The MRRPolicy if found, None otherwise.
        """
        if not self._loaded:
            self.load_all()
        return self._policies.get(rule_id)

    def get_by_agency(self, agency: str) -> list[MRRPolicy]:
        """Get all policies for a specific agency.

        Args:
            agency: The agency code.

        Returns:
            List of policies for that agency.
        """
        if not self._loaded:
            self.load_all()
        return [p for p in self._policies.values() if p.agency == agency]

    def get_applicable(
        self,
        domain: str | None = None,
        operator_type: str | None = None,
        entity_type: str | None = None,
    ) -> list[MRRPolicy]:
        """Get policies applicable to given criteria.

        Args:
            domain: Domain or regime filter.
            operator_type: Operator type filter (e.g., commercial, government).
            entity_type: Entity type filter.

        Returns:
            List of applicable policies.
        """
        if not self._loaded:
            self.load_all()

        applicable = []
        for policy in self._policies.values():
            app = policy.applicability
            if not app:
                # No applicability restrictions = applies to all
                applicable.append(policy)
                continue

            # Check each criterion
            domain_match = not domain or not app.get("domain") or domain in app["domain"]
            operator_match = not operator_type or not app.get("operator_type") or operator_type in app["operator_type"]
            entity_match = (
                not entity_type or not app.get("entity_type") or entity_type in app["entity_type"]
            )

            if domain_match and operator_match and entity_match:
                applicable.append(policy)

        return applicable

    def list_rule_ids(self) -> list[str]:
        """List all available rule IDs.

        Returns:
            List of rule_id strings.
        """
        if not self._loaded:
            self.load_all()
        return list(self._policies.keys())

    def reload(self) -> dict[str, MRRPolicy]:
        """Force reload all policies.

        Returns:
            Dictionary mapping rule_id to MRRPolicy.
        """
        self._loaded = False
        self._policies = {}
        self._raw_policies = {}
        self._ruleset_hash = None
        self._load_errors = []
        return self.load_all()

    def compute_ruleset_hash(self) -> str:
        """Compute SHA256 hash of all loaded policies.

        The hash is computed by concatenating all policy raw bytes
        in sorted rule_id order, ensuring deterministic results.

        Returns:
            SHA256 hash prefixed with "sha256:".
        """
        if not self._loaded:
            self.load_all()

        if self._ruleset_hash is not None:
            return self._ruleset_hash

        # Sort by rule_id for deterministic ordering
        sorted_ids = sorted(self._raw_policies.keys())
        hasher = hashlib.sha256()

        for rule_id in sorted_ids:
            # Include rule_id as separator to prevent collision attacks
            hasher.update(rule_id.encode("utf-8"))
            hasher.update(b"|")
            hasher.update(self._raw_policies[rule_id])
            hasher.update(b"\n")

        self._ruleset_hash = f"sha256:{hasher.hexdigest()}"
        logger.debug("Computed ruleset hash: %s", self._ruleset_hash)
        return self._ruleset_hash

    def get_policy_hash(self, rule_id: str) -> str | None:
        """Compute SHA256 hash of a specific policy file.

        Args:
            rule_id: The unique rule identifier.

        Returns:
            SHA256 hash prefixed with "sha256:", or None if not found.
        """
        if not self._loaded:
            self.load_all()

        raw_bytes = self._raw_policies.get(rule_id)
        if raw_bytes is None:
            return None

        digest = hashlib.sha256(raw_bytes).hexdigest()
        return f"sha256:{digest}"

    @property
    def ruleset_version(self) -> str:
        """Get the ruleset version string."""
        return self.RULESET_VERSION

    @property
    def load_errors(self) -> list[dict[str, str]]:
        """Errors encountered during the last ``load_all()`` call."""
        return list(self._load_errors)


__all__ = ["MRRLoader", "MRRPolicy", "MRRCondition", "MRRDataSource", "MRRCertification"]
