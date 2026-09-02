"""Fail-closed invoke contract for catalog arms and heads.

This module defines the core contract for the extension system, providing:
- CatalogEntry: Represents items in the coverage catalog (arms, heads, methodology-only)
- Extension: Main interface for discovering, describing, and invoking catalog entries
- Transport: Protocol for different invocation mechanisms (CLI, MCP, HTTP)
- Error classes: Hierarchical exception handling for fail-closed behavior

The extension system follows a fail-closed philosophy where unknown or misconfigured
entries raise explicit errors rather than silently failing or falling back to defaults.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

import yaml

# Catalog entry kinds
CATALOG_KIND_ARM = "arm"  # Invocable tool adapters
CATALOG_KIND_HEAD = "head"  # Tool collection headers

# Transport protocols
TRANSPORT_CLI = "cli"  # Command-line interface transport
TRANSPORT_MCP = "mcp"  # Model Context Protocol transport
SUPPORTED_TRANSPORTS = frozenset({TRANSPORT_CLI, TRANSPORT_MCP})

# Lifecycle/support tiers. curated is not equivalent to maintained.
TIER_RESEARCH = "research"
TIER_EXPERIMENTAL = "experimental"
TIER_MAINTAINED = "maintained"
TIER_HELD = "held"
ALLOWED_TIERS = frozenset(
    {TIER_RESEARCH, TIER_EXPERIMENTAL, TIER_MAINTAINED, TIER_HELD}
)


class ExtensionError(Exception):
    """Fail-closed extension error."""


class UnknownIdError(ExtensionError):
    """Catalog id is not present."""

    def __init__(self, entry_id: str) -> None:
        self.entry_id = entry_id
        super().__init__(f"unknown id: {entry_id}")


class NotAnArmError(ExtensionError):
    """Row exists but is not an invocable arm."""

    def __init__(self, entry_id: str, kind: str) -> None:
        self.entry_id = entry_id
        self.kind = kind
        super().__init__(f"{entry_id} is {kind}, not an arm")


class NotAHeadError(ExtensionError):
    """Row exists but is not a head."""

    def __init__(self, entry_id: str, kind: str) -> None:
        self.entry_id = entry_id
        self.kind = kind
        super().__init__(f"{entry_id} is {kind}, not a head")


class NotCuratedError(ExtensionError):
    """Arm exists but is not curated."""

    def __init__(self, entry_id: str) -> None:
        self.entry_id = entry_id
        super().__init__(f"{entry_id} is not curated")


class NotHeldError(ExtensionError):
    """Arm exists but its support tier is held; invoke is refused."""

    def __init__(self, entry_id: str, reason: str | None = None) -> None:
        self.entry_id = entry_id
        self.reason = reason or "held"
        super().__init__(f"{entry_id} is held: {self.reason}")


class NotInstalledError(ExtensionError):
    """Arm is curated but no reachable transport is installed."""

    def __init__(self, entry_id: str) -> None:
        self.entry_id = entry_id
        super().__init__(f"{entry_id} is not installed")


class UnmanifestedCapabilityError(ExtensionError):
    """An arm action is outside the bounded X2-PUB invoke registry."""

    def __init__(self, entry_id: str, action: str) -> None:
        self.entry_id = entry_id
        self.action = action
        super().__init__(
            f"{entry_id}.{action} is not in the X2-PUB read-only manifest"
        )


def _require_bool_curated(curated: Any, *, label: str = "curated") -> None:
    # Truthy strings/ints must not become curated; the field is a real boolean.
    if not isinstance(curated, bool):
        raise ExtensionError(f"{label} must be a boolean")


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    kind: str
    protocols: tuple[str, ...]
    curated: bool
    notes: str
    tier: str
    held_reason: str | None = None

    def __post_init__(self) -> None:
        _require_bool_curated(self.curated)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "kind": self.kind,
            "protocols": list(self.protocols),
            "curated": self.curated,
            "tier": self.tier,
            "notes": self.notes,
        }
        if self.held_reason is not None:
            payload["held_reason"] = self.held_reason
        return payload


@dataclass(frozen=True)
class ArmSpec:
    id: str
    protocols: tuple[str, ...]
    curated: bool
    notes: str
    tier: str
    held_reason: str | None = None

    def __post_init__(self) -> None:
        _require_bool_curated(self.curated)

    @classmethod
    def from_entry(cls, entry: CatalogEntry) -> ArmSpec:
        return cls(
            id=entry.id,
            protocols=entry.protocols,
            curated=entry.curated,
            notes=entry.notes,
            tier=entry.tier,
            held_reason=entry.held_reason,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "kind": CATALOG_KIND_ARM,
            "protocols": list(self.protocols),
            "curated": self.curated,
            "tier": self.tier,
            "notes": self.notes,
        }
        if self.held_reason is not None:
            payload["held_reason"] = self.held_reason
        return payload


@dataclass(frozen=True)
class HeadSpec:
    id: str
    protocols: tuple[str, ...]
    curated: bool
    notes: str
    tier: str
    held_reason: str | None = None

    def __post_init__(self) -> None:
        _require_bool_curated(self.curated)

    @classmethod
    def from_entry(cls, entry: CatalogEntry) -> HeadSpec:
        return cls(
            id=entry.id,
            protocols=entry.protocols,
            curated=entry.curated,
            notes=entry.notes,
            tier=entry.tier,
            held_reason=entry.held_reason,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "kind": CATALOG_KIND_HEAD,
            "protocols": list(self.protocols),
            "curated": self.curated,
            "tier": self.tier,
            "notes": self.notes,
        }
        if self.held_reason is not None:
            payload["held_reason"] = self.held_reason
        return payload


@dataclass(frozen=True)
class Result:
    ok: bool
    arm_id: str
    action: str
    output: Any = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "arm_id": self.arm_id,
            "action": self.action,
            "output": self.output,
            "error": self.error,
        }


class Transport(Protocol):
    """Protocol for extension invocation transports.

    A transport represents a mechanism for invoking arms (tools) - either through
    direct command execution, MCP servers, HTTP endpoints, or other protocols.

    Attributes:
        protocol: The protocol identifier (e.g., "cli", "mcp", "http")

    """

    protocol: str

    def installed(self, spec: ArmSpec) -> bool:
        """Check if this transport can reach the given arm specification.

        Args:
            spec: The arm specification to check for availability

        Returns:
            True if the transport can invoke this arm, False otherwise

        """

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        """Execute an action on the specified arm.

        Args:
            spec: The arm specification to invoke
            action: The action/method name to execute
            args: Arguments to pass to the action

        Returns:
            A Result object containing the invocation outcome. Must not invent
            a success - if invocation fails, ok must be False.

        """


class Catalog:
    """Registry of catalog entries with version tracking.

    The catalog maintains a list of all known catalog entries (arms, heads,
    methodology-only entries) and provides efficient lookup by ID.

    Attributes:
        version: Catalog version number for schema evolution tracking
        entries: List of all catalog entries in insertion order

    """

    def __init__(
        self, entries: Sequence[CatalogEntry], version: int = 1
    ) -> None:
        """Initialize a new catalog.

        Args:
            entries: Sequence of catalog entries to register
            version: Catalog schema version (default: 1)

        Raises:
            ExtensionError: If duplicate entry IDs are detected

        """
        self.version = version
        self.entries = list(entries)
        self._by_id: dict[str, CatalogEntry] = {}
        for entry in self.entries:
            if entry.id in self._by_id:
                raise ExtensionError(f"duplicate catalog id: {entry.id}")
            self._by_id[entry.id] = entry

    def get(self, entry_id: str) -> CatalogEntry:
        """Retrieve a catalog entry by ID.

        Args:
            entry_id: The unique identifier of the catalog entry

        Returns:
            The requested catalog entry

        Raises:
            UnknownIdError: If no entry exists with the given ID

        """
        try:
            return self._by_id[entry_id]
        except KeyError:
            raise UnknownIdError(entry_id) from None


def default_catalog_path() -> Path:
    """Get the default path to the coverage catalog YAML file.

    Returns:
        Absolute path to coverage.yaml in the extension directory

    """
    return Path(__file__).resolve().parent / "coverage.yaml"


def load_catalog(path: Path | None = None) -> Catalog:
    """Load and validate a coverage catalog from a YAML file.

    Args:
        path: Path to the catalog file, or None to use the default path

    Returns:
        A validated Catalog instance containing all entries

    Raises:
        ExtensionError: If the YAML is invalid, the schema is incorrect,
                       or any entry fails validation

    """
    catalog_path = path or default_catalog_path()
    try:
        with catalog_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ExtensionError(f"invalid catalog yaml: {exc}") from exc
    if not isinstance(data, dict):
        raise ExtensionError("catalog must be a mapping")
    rows = data.get("entries")
    if not isinstance(rows, list):
        raise ExtensionError("catalog entries must be a list")
    entries: list[CatalogEntry] = []
    for idx, row in enumerate(rows):
        try:
            entries.append(_entry_from_row(row))
        except ExtensionError as exc:
            # Include row index to help operators diagnose coverage.yaml edits.
            raise ExtensionError(f"entry {idx}: {exc}") from exc
    try:
        version = int(data.get("version", 1))
    except (TypeError, ValueError) as exc:
        raise ExtensionError("catalog version must be an integer") from exc
    return Catalog(entries, version=version)


_ID_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_ALLOWED_PROTOCOLS = frozenset({"mcp", "cli", "http", "none"})
_ALLOWED_KINDS = frozenset({CATALOG_KIND_ARM, CATALOG_KIND_HEAD, "methodology-only"})


def _entry_from_row(row: Any) -> CatalogEntry:
    if not isinstance(row, dict):
        raise ExtensionError("catalog entry must be a mapping")
    entry_id = row.get("id")
    if entry_id is None or (isinstance(entry_id, str) and not entry_id.strip()):
        raise ExtensionError("catalog entry id is required")
    if not isinstance(entry_id, str):
        entry_id = str(entry_id)
    if not _ID_RE.match(entry_id):
        raise ExtensionError(f"catalog entry id is not kebab-case: {entry_id}")
    kind = row.get("kind")
    if kind is None or (isinstance(kind, str) and not kind.strip()):
        raise ExtensionError("catalog entry kind is required")
    if not isinstance(kind, str):
        kind = str(kind)
    if kind not in _ALLOWED_KINDS:
        raise ExtensionError(f"catalog entry kind must be one of {sorted(_ALLOWED_KINDS)}: {kind}")
    protocols = row.get("protocols")
    if not isinstance(protocols, list) or not protocols:
        raise ExtensionError("catalog entry protocols must be a non-empty list")
    for item in protocols:
        if not isinstance(item, str) or item not in _ALLOWED_PROTOCOLS:
            raise ExtensionError(f"catalog entry protocol must be one of {sorted(_ALLOWED_PROTOCOLS)}: {item!r}")
    if "none" in protocols and protocols != ["none"]:
        raise ExtensionError("catalog entry protocols 'none' must be exclusive")
    curated = row.get("curated")
    _require_bool_curated(curated, label="catalog entry curated")
    if kind == "methodology-only" and curated:
        raise ExtensionError("methodology-only entry must not be curated")
    tier = row.get("tier")
    if not isinstance(tier, str) or not tier.strip():
        raise ExtensionError("catalog entry tier is required")
    if tier not in ALLOWED_TIERS:
        raise ExtensionError(
            f"catalog entry tier must be one of {sorted(ALLOWED_TIERS)}: {tier}"
        )
    if kind == "methodology-only" and tier == TIER_MAINTAINED:
        raise ExtensionError("methodology-only entry must not be maintained")
    held_reason_raw = row.get("held_reason")
    if tier == TIER_HELD:
        if not isinstance(held_reason_raw, str) or not held_reason_raw.strip():
            raise ExtensionError("held entry requires held_reason")
        held_reason: str | None = held_reason_raw.strip()
    else:
        if held_reason_raw is not None:
            raise ExtensionError("held_reason is only valid when tier is held")
        held_reason = None
    notes = row.get("notes")
    if notes is None or (isinstance(notes, str) and not notes.strip()):
        raise ExtensionError("catalog entry notes is required")
    if not isinstance(notes, str):
        notes = str(notes)
    if not notes.strip():
        raise ExtensionError("catalog entry notes is required")
    return CatalogEntry(
        id=entry_id,
        kind=kind,
        protocols=tuple(str(item) for item in protocols),
        curated=curated,
        notes=notes,
        tier=tier,
        held_reason=held_reason,
    )


def _default_transports() -> dict[str, Transport]:
    from .transports.cli import CliTransport
    from .transports.mcp import McpTransport

    return {TRANSPORT_CLI: CliTransport(), TRANSPORT_MCP: McpTransport()}


def _default_arms() -> dict[str, Transport]:
    from .arms.burp import ARM_ID as BURP_ARM_ID
    from .arms.burp import BurpArm
    from .arms.caldera import ARM_ID as CALDERA_ARM_ID
    from .arms.caldera import CalderaArm
    from .arms.gti import ARM_ID as GTI_ARM_ID
    from .arms.gti import GtiArm
    from .arms.osmedeus import ARM_ID as OSMEDEUS_ARM_ID
    from .arms.osmedeus import OsmedeusArm
    from .arms.pagefetch import ARM_ID as PAGE_FETCH_ARM_ID
    from .arms.pagefetch import PageFetchArm
    from .arms.stratus import ARM_ID as STRATUS_ARM_ID
    from .arms.stratus import StratusArm
    from .arms.zdns import ARM_ID as ZDNS_ARM_ID
    from .arms.zdns import ZdnsArm
    from .arms.checkov import ARM_ID as CHECKOV_ARM_ID
    from .arms.checkov import CheckovArm
    from .arms.commix import ARM_ID as COMMIX_ARM_ID
    from .arms.commix import CommixArm
    from .arms.garak import ARM_ID as GARAK_ARM_ID
    from .arms.garak import GarakArm
    from .arms.metasploit import ARM_ID as METASPLOIT_ARM_ID
    from .arms.metasploit import MetasploitArm
    from .arms.mitreattack import ARM_ID as MITREATTACK_ARM_ID
    from .arms.mitreattack import MitreattackArm
    from .arms.prowler import ARM_ID as PROWLER_ARM_ID
    from .arms.prowler import ProwlerArm
    from .arms.semgrep import ARM_ID as SEMGREP_ARM_ID
    from .arms.semgrep import SemgrepArm
    from .arms.vuls import ARM_ID as VULS_ARM_ID
    from .arms.vuls import VulsArm
    from .arms.wapiti import ARM_ID as WAPITI_ARM_ID
    from .arms.wapiti import WapitiArm
    from .arms.zap import ARM_ID as ZAP_ARM_ID
    from .arms.zap import ZapArm
    from .arms.routersploit import ARM_ID as ROUTERSPLOIT_ARM_ID
    from .arms.routersploit import RoutersploitArm
    from .arms.sniper import ARM_ID as SNIPER_ARM_ID
    from .arms.sniper import SniperArm
    from .arms.zgrab2 import ARM_ID as ZGRAB2_ARM_ID
    from .arms.zgrab2 import Zgrab2Arm
    from .arms.nmap import ARM_ID as NMAP_ARM_ID
    from .arms.nmap import NmapArm
    from .arms.darkmoon import ARM_ID as DARK_MOON_ARM_ID
    from .arms.darkmoon import DarkMoonArm
    from .arms.pyrit import ARM_ID as PYRIT_ARM_ID
    from .arms.pyrit import PyritArm
    from .arms.deepsec import ARM_ID as DEEPSEC_ARM_ID
    from .arms.deepsec import DeepsecArm
    from .arms.vvah import ARM_ID as VVAH_ARM_ID
    from .arms.vvah import VvahArm
    from .arms.aideepsast import ARM_ID as AI_DEEP_SAST_ARM_ID
    from .arms.aideepsast import AiDeepSastArm
    from .arms.agentwiz import ARM_ID as AGENT_WIZ_ARM_ID
    from .arms.agentwiz import AgentWizArm

    return {
        BURP_ARM_ID: BurpArm(),
        SEMGREP_ARM_ID: SemgrepArm(),
        CHECKOV_ARM_ID: CheckovArm(),
        PROWLER_ARM_ID: ProwlerArm(),
        GARAK_ARM_ID: GarakArm(),
        ZAP_ARM_ID: ZapArm(),
        WAPITI_ARM_ID: WapitiArm(),
        COMMIX_ARM_ID: CommixArm(),
        MITREATTACK_ARM_ID: MitreattackArm(),
        VULS_ARM_ID: VulsArm(),
        STRATUS_ARM_ID: StratusArm(),
        OSMEDEUS_ARM_ID: OsmedeusArm(),
        ZDNS_ARM_ID: ZdnsArm(),
        PAGE_FETCH_ARM_ID: PageFetchArm(),
        CALDERA_ARM_ID: CalderaArm(),
        GTI_ARM_ID: GtiArm(),
        METASPLOIT_ARM_ID: MetasploitArm(),
        ROUTERSPLOIT_ARM_ID: RoutersploitArm(),
        SNIPER_ARM_ID: SniperArm(),
        ZGRAB2_ARM_ID: Zgrab2Arm(),
        NMAP_ARM_ID: NmapArm(),
        DARK_MOON_ARM_ID: DarkMoonArm(),
        PYRIT_ARM_ID: PyritArm(),
        DEEPSEC_ARM_ID: DeepsecArm(),
        VVAH_ARM_ID: VvahArm(),
        AI_DEEP_SAST_ARM_ID: AiDeepSastArm(),
        AGENT_WIZ_ARM_ID: AgentWizArm(),
    }


class Extension:
    """Main interface for catalog operations and arm invocation.

    The Extension class provides the primary API for interacting with the catalog:
    - Listing and describing catalog entries
    - Invoking curated, installed arms
    - Managing transports and specialized handlers

    Attributes:
        catalog: The catalog containing all known entries
        transports: Available transport mechanisms indexed by protocol
        arms: Specialized arm handlers indexed by arm ID

    """

    def __init__(
        self,
        catalog: Catalog | None = None,
        transports: Mapping[str, Transport] | Sequence[Transport] | None = None,
        arms: Mapping[str, Transport] | None = None,
    ) -> None:
        """Initialize a new Extension instance.

        Args:
            catalog: Optional catalog instance, loads default if None
            transports: Transport instances (mapping or sequence), uses defaults if None
            arms: Specialized arm handlers, uses defaults if None

        """
        self.catalog = catalog if catalog is not None else load_catalog()
        self.transports = _index_transports(transports)
        self.arms = _index_arms(arms)

    def list_entries(self) -> list[CatalogEntry]:
        """List all catalog entries.

        Returns:
            List of all catalog entries in insertion order

        """
        return list(self.catalog.entries)

    def describe(self, entry_id: str) -> CatalogEntry:
        """Get detailed information about a catalog entry.

        Args:
            entry_id: The unique identifier of the catalog entry

        Returns:
            The requested catalog entry

        Raises:
            UnknownIdError: If no entry exists with the given ID

        """
        return self.catalog.get(entry_id)

    def arm_spec(self, entry_id: str) -> ArmSpec:
        """Get the arm specification for a catalog entry.

        Args:
            entry_id: The unique identifier of the catalog entry

        Returns:
            An ArmSpec representing the entry

        Raises:
            UnknownIdError: If no entry exists with the given ID
            NotAnArmError: If the entry exists but is not an arm

        """
        entry = self.describe(entry_id)
        if entry.kind != CATALOG_KIND_ARM:
            raise NotAnArmError(entry.id, entry.kind)
        return ArmSpec.from_entry(entry)

    def head_spec(self, entry_id: str) -> HeadSpec:
        """Get the head specification for a catalog entry.

        Args:
            entry_id: The unique identifier of the catalog entry

        Returns:
            A HeadSpec representing the entry

        Raises:
            UnknownIdError: If no entry exists with the given ID
            NotAHeadError: If the entry exists but is not a head

        """
        entry = self.describe(entry_id)
        if entry.kind != CATALOG_KIND_HEAD:
            raise NotAHeadError(entry.id, entry.kind)
        return HeadSpec.from_entry(entry)

    def invoke(
        self,
        arm_id: str,
        action: str,
        args: Mapping[str, Any] | None = None,
    ) -> Result:
        """Invoke an action on a curated, installed, non-held arm.

        Args:
            arm_id: The unique identifier of the arm to invoke
            action: The action/method name to execute
            args: Optional arguments to pass to the action

        Returns:
            A Result object containing the invocation outcome

        Raises:
            ExtensionError: If action is not a valid string
            UnknownIdError: If no entry exists with the given ID
            NotAnArmError: If the entry exists but is not an arm
            NotHeldError: If the arm's support tier is held
            NotCuratedError: If the arm is not curated
            NotInstalledError: If no transport can reach the arm

        """
        if not isinstance(action, str) or not action.strip():
            raise ExtensionError("action is required")
        payload = _args_payload(args)
        spec = self.arm_spec(arm_id)
        if spec.tier == TIER_HELD:
            raise NotHeldError(spec.id, spec.held_reason)
        if not spec.curated:
            raise NotCuratedError(spec.id)
        handler = self._select_handler(spec)
        return handler.invoke(spec, action, payload)

    def _select_handler(self, spec: ArmSpec) -> Transport:
        specialized = self.arms.get(spec.id)
        if specialized is not None:
            if specialized.installed(spec):
                return specialized
            raise NotInstalledError(spec.id)
        if spec.curated:
            # Curated arms must never ride a generic transport: the generic
            # CLI transport splices caller-supplied actions into subprocess
            # argv and the generic MCP transport forwards unfiltered tool
            # calls. Every curated arm ships a specialized handler with a
            # policy module (fixed argv / allowlist) instead.
            raise ExtensionError(
                f"curated arm {spec.id} requires a specialized handler; "
                "generic transports are refused for curated arms"
            )
        return self._select_transport(spec)

    def _select_transport(self, spec: ArmSpec) -> Transport:
        for proto in spec.protocols:
            if proto not in SUPPORTED_TRANSPORTS:
                continue
            transport = self.transports.get(proto)
            if transport is None:
                continue
            if transport.installed(spec):
                return transport
        raise NotInstalledError(spec.id)


def _index_transports(
    transports: Mapping[str, Transport] | Sequence[Transport] | None,
) -> dict[str, Transport]:
    if transports is None:
        return _default_transports()
    if isinstance(transports, Mapping):
        return dict(transports)
    indexed: dict[str, Transport] = {}
    for transport in transports:
        indexed[transport.protocol] = transport
    return indexed


def _index_arms(arms: Mapping[str, Transport] | None) -> dict[str, Transport]:
    if arms is None:
        return _default_arms()
    return dict(arms)


def _args_payload(args: Mapping[str, Any] | None) -> dict[str, Any]:
    if args is None:
        return {}
    if not isinstance(args, Mapping):
        raise ExtensionError("args must be a mapping")
    return dict(args)


_DEFAULT: Extension | None = None


def default_extension() -> Extension:
    """Get or create the default Extension instance.

    This function provides a singleton instance of the Extension class for
    use in module-level convenience functions. Note: Not thread-safe.

    Returns:
        The default Extension instance

    """
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Extension()
    return _DEFAULT


def list_entries() -> list[CatalogEntry]:
    """List all catalog entries using the default extension.

    Returns:
        List of all catalog entries in insertion order

    """
    return default_extension().list_entries()


def describe(entry_id: str) -> CatalogEntry:
    """Describe a catalog entry using the default extension.

    Args:
        entry_id: The unique identifier of the catalog entry

    Returns:
        The requested catalog entry

    Raises:
        UnknownIdError: If no entry exists with the given ID

    """
    return default_extension().describe(entry_id)


def invoke(
    arm_id: str, action: str, args: Mapping[str, Any] | None = None
) -> Result:
    """Invoke an action using the default extension.

    Args:
        arm_id: The unique identifier of the arm to invoke
        action: The action/method name to execute
        args: Optional arguments to pass to the action

    Returns:
        A Result object containing the invocation outcome

    Raises:
        ExtensionError: If action is not valid or other invocation errors occur
        UnknownIdError: If no entry exists with the given ID
        NotAnArmError: If the entry exists but is not an arm
        NotHeldError: If the arm's support tier is held
        NotCuratedError: If the arm is not curated
        NotInstalledError: If no transport can reach the arm

    """
    return default_extension().invoke(arm_id, action, args)
