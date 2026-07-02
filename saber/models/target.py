"""Target models used across SABER.

This file defines the data structures for anything SABER may test, scan,
validate, or report against. A target can be an IP address, CIDR block, domain,
URL, IP range, hostname, or runtime session reference.

Inputs:
    - Raw target values from scope files, planner output, agent output, or tool
      wrappers.
    - Target metadata such as description, tags, and scope status.

Outputs:
    - Normalized, validated Target objects.
    - Helper methods that later layers can use to decide which tools are safe
      and appropriate for a target.

Used by:
    - saber.models.scope
    - saber.core.scope_guard
    - saber.core.phase_graph
    - saber.tools.* wrappers
    - saber.reporting exporters
"""

from __future__ import annotations

from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class TargetType(StrEnum):
    """Supported SABER target types.

    Values:
        IP: A single IPv4 or IPv6 address.
        CIDR: A CIDR network such as 10.0.0.0/24.
        IP_RANGE: A start/end IP range expressed as a string.
        DOMAIN: A DNS domain such as example.com.
        URL: A full web URL such as https://example.com/login.
        HOST: A hostname that may not be a DNS domain.
        SESSION: A runtime session reference produced during authorized testing.
    """

    IP = "ip"
    CIDR = "cidr"
    IP_RANGE = "ip_range"
    DOMAIN = "domain"
    URL = "url"
    HOST = "host"
    SESSION = "session"


class ScopeStatus(StrEnum):
    """Scope state assigned to a target.

    Values:
        IN_SCOPE: Target is explicitly authorized.
        OUT_OF_SCOPE: Target is explicitly excluded.
        REQUIRES_REVIEW: Target was discovered or inferred and needs operator review.
        UNKNOWN: Target has not yet been evaluated by ScopeGuard.
    """

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    REQUIRES_REVIEW = "requires_review"
    UNKNOWN = "unknown"


class Target(BaseModel):
    """A normalized object that SABER can scan, validate, or report against.

    Args:
        type: The kind of target represented by this object.
        value: The normalized target value.
        description: Optional human-readable context for the target.
        scope_status: Current authorization status for the target.
        source: Where the target came from, such as scope.yaml, ReconAgent, or nmap.
        tags: Optional labels used for filtering, routing, or reporting.
        metadata: Optional structured context from configs, agents, or tool output.

    Returns:
        A validated Pydantic model. Invalid IP, CIDR, URL, domain, and range
        values raise ValueError during model construction.
    """

    type: TargetType
    value: str = Field(..., min_length=1)
    description: str | None = None
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    source: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        """Normalize a raw target value.

        Args:
            value: Raw target string from config, agent output, or tool output.

        Returns:
            The stripped target string.

        Raises:
            ValueError: If the value is empty after trimming whitespace.
        """

        normalized = value.strip()
        if not normalized:
            raise ValueError("target value cannot be empty")
        return normalized

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: list[str]) -> list[str]:
        """Normalize target tags.

        Args:
            tags: Raw tag list.

        Returns:
            Lowercase, stripped, de-duplicated tags in original order.
        """

        seen: set[str] = set()
        normalized_tags: list[str] = []

        for tag in tags:
            normalized = tag.strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                normalized_tags.append(normalized)

        return normalized_tags

    @model_validator(mode="after")
    def validate_target_value(self) -> Target:
        """Validate value format based on target type.

        Returns:
            The validated Target object.

        Raises:
            ValueError: If the target value does not match the declared type.
        """

        match self.type:
            case TargetType.IP:
                ip_address(self.value)
            case TargetType.CIDR:
                ip_network(self.value, strict=False)
            case TargetType.IP_RANGE:
                self._validate_ip_range(self.value)
            case TargetType.DOMAIN:
                self._validate_domain(self.value)
                self.value = self.value.lower()
            case TargetType.URL:
                self.value = self._normalize_url(self.value)
            case TargetType.HOST:
                self._validate_host(self.value)
                self.value = self.value.lower()
            case TargetType.SESSION:
                self._validate_session_reference(self.value)

        return self

    @staticmethod
    def _validate_ip_range(value: str) -> None:
        """Validate an IP range expressed as `start-end`.

        Args:
            value: IP range string such as `10.0.0.10-10.0.0.20`.

        Raises:
            ValueError: If the range is malformed or crosses IP versions.
        """

        parts = [part.strip() for part in value.split("-")]
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError("ip_range targets must use the format start_ip-end_ip")

        start = ip_address(parts[0])
        end = ip_address(parts[1])

        if start.version != end.version:
            raise ValueError("ip_range start and end must use the same IP version")
        if int(start) > int(end):
            raise ValueError("ip_range start must be less than or equal to end")

    @staticmethod
    def _validate_domain(value: str) -> None:
        """Validate a DNS domain target.

        Args:
            value: Domain string such as `example.com`.

        Raises:
            ValueError: If the domain is malformed.
        """

        if "://" in value or "/" in value:
            raise ValueError("domain targets must not include a URL scheme or path")

        labels = value.rstrip(".").split(".")
        if len(labels) < 2:
            raise ValueError("domain targets must include at least one dot")

        for label in labels:
            if not label:
                raise ValueError("domain labels cannot be empty")
            if len(label) > 63:
                raise ValueError("domain labels cannot exceed 63 characters")
            if label.startswith("-") or label.endswith("-"):
                raise ValueError("domain labels cannot start or end with '-'")
            if not all(character.isalnum() or character == "-" for character in label):
                raise ValueError("domain labels may only contain letters, numbers, and '-'")

    @classmethod
    def _normalize_url(cls, value: str) -> str:
        """Validate and normalize a URL target.

        Args:
            value: URL string such as `https://example.com/login`.

        Returns:
            Normalized URL with lowercase scheme and hostname.

        Raises:
            ValueError: If the URL is malformed or does not use HTTP(S).
        """

        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("url targets must use http or https")
        if not parsed.hostname:
            raise ValueError("url targets must include a hostname")

        host = parsed.hostname.lower()
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""

        return f"{parsed.scheme.lower()}://{host}{port}{path}{query}{fragment}"

    @staticmethod
    def _validate_host(value: str) -> None:
        """Validate a hostname-like target.

        Args:
            value: Hostname such as `server01` or `server01.internal`.

        Raises:
            ValueError: If the hostname is empty or contains invalid characters.
        """

        if "://" in value or "/" in value:
            raise ValueError("host targets must not include a URL scheme or path")

        labels = value.split(".")
        for label in labels:
            if not label:
                raise ValueError("host labels cannot be empty")
            if len(label) > 63:
                raise ValueError("host labels cannot exceed 63 characters")
            if label.startswith("-") or label.endswith("-"):
                raise ValueError("host labels cannot start or end with '-'")
            if not all(character.isalnum() or character == "-" for character in label):
                raise ValueError("host labels may only contain letters, numbers, and '-'")

    @staticmethod
    def _validate_session_reference(value: str) -> None:
        """Validate a runtime session reference.

        Args:
            value: Session reference such as `session:abc123` or `msf:7`.

        Raises:
            ValueError: If the reference is too short or contains whitespace.
        """

        if len(value) < 3:
            raise ValueError("session references must be at least 3 characters long")
        if any(character.isspace() for character in value):
            raise ValueError("session references cannot contain whitespace")

    @property
    def is_network_target(self) -> bool:
        """Return whether the target is network-addressable.

        Returns:
            True for IP, CIDR, IP range, domain, and host targets.
        """

        return self.type in {
            TargetType.IP,
            TargetType.CIDR,
            TargetType.IP_RANGE,
            TargetType.DOMAIN,
            TargetType.HOST,
        }

    @property
    def is_web_target(self) -> bool:
        """Return whether the target is directly usable by web tools.

        Returns:
            True when the target is a URL.
        """

        return self.type == TargetType.URL

    @property
    def is_runtime_target(self) -> bool:
        """Return whether the target refers to runtime state.

        Returns:
            True when the target is a session reference.
        """

        return self.type == TargetType.SESSION

    @property
    def requires_review(self) -> bool:
        """Return whether the target needs operator review before use.

        Returns:
            True when scope_status is REQUIRES_REVIEW or UNKNOWN.
        """

        return self.scope_status in {ScopeStatus.REQUIRES_REVIEW, ScopeStatus.UNKNOWN}

    def tool_value(self) -> str:
        """Return the value that should be passed to a tool wrapper.

        Returns:
            The normalized target value.
        """

        return self.value

    def mark_in_scope(self) -> Target:
        """Return a copy of this target marked as explicitly in scope.

        Returns:
            A new Target with scope_status set to IN_SCOPE.
        """

        return self.model_copy(update={"scope_status": ScopeStatus.IN_SCOPE})

    def mark_out_of_scope(self) -> Target:
        """Return a copy of this target marked as explicitly out of scope.

        Returns:
            A new Target with scope_status set to OUT_OF_SCOPE.
        """

        return self.model_copy(update={"scope_status": ScopeStatus.OUT_OF_SCOPE})

    def mark_requires_review(self) -> Target:
        """Return a copy of this target marked as requiring operator review.

        Returns:
            A new Target with scope_status set to REQUIRES_REVIEW.
        """

        return self.model_copy(update={"scope_status": ScopeStatus.REQUIRES_REVIEW})

    def to_agent_dict(self) -> dict[str, str]:
        """Return the compact target shape used in agent JSON.

        Returns:
            A dictionary containing only the target type and value.
        """

        return {"type": self.type.value, "value": self.value}