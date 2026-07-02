"""Tests for SABER target models.

This file verifies that `saber.models.target` correctly validates,
normalizes, and classifies targets before they are used by ScopeGuard,
agent planning, tool wrappers, or report generation.
"""

from __future__ import annotations

import pytest
from saber.models.target import ScopeStatus, Target, TargetType


class TestTargetValidation:
    """Validate that supported target types accept correct values."""

    def test_valid_ip_target(self) -> None:
        """A valid IPv4 address should create an IP target."""

        target = Target(type=TargetType.IP, value="192.168.1.10")

        assert target.type == TargetType.IP
        assert target.value == "192.168.1.10"

    def test_valid_cidr_target(self) -> None:
        """A valid CIDR should create a CIDR target."""

        target = Target(type=TargetType.CIDR, value="10.0.0.0/24")

        assert target.type == TargetType.CIDR
        assert target.value == "10.0.0.0/24"

    def test_valid_ip_range_target(self) -> None:
        """A valid start-end IP range should create an IP range target."""

        target = Target(type=TargetType.IP_RANGE, value="10.0.0.10-10.0.0.20")

        assert target.type == TargetType.IP_RANGE
        assert target.value == "10.0.0.10-10.0.0.20"

    def test_valid_domain_target(self) -> None:
        """A valid domain should create a domain target."""

        target = Target(type=TargetType.DOMAIN, value="example.com")

        assert target.type == TargetType.DOMAIN
        assert target.value == "example.com"

    def test_valid_url_target(self) -> None:
        """A valid HTTP(S) URL should create a URL target."""

        target = Target(type=TargetType.URL, value="https://example.com/login")

        assert target.type == TargetType.URL
        assert target.value == "https://example.com/login"

    def test_valid_host_target(self) -> None:
        """A valid hostname should create a host target."""

        target = Target(type=TargetType.HOST, value="server01.internal")

        assert target.type == TargetType.HOST
        assert target.value == "server01.internal"

    def test_valid_session_target(self) -> None:
        """A valid runtime session reference should create a session target."""

        target = Target(type=TargetType.SESSION, value="msf:7")

        assert target.type == TargetType.SESSION
        assert target.value == "msf:7"


class TestTargetNormalization:
    """Validate normalization performed during target construction."""

    def test_value_is_trimmed(self) -> None:
        """Whitespace around target values should be removed."""

        target = Target(type=TargetType.IP, value="  192.168.1.10  ")

        assert target.value == "192.168.1.10"

    def test_domain_is_lowercased(self) -> None:
        """Domain targets should be normalized to lowercase."""

        target = Target(type=TargetType.DOMAIN, value="Example.COM")

        assert target.value == "example.com"

    def test_host_is_lowercased(self) -> None:
        """Host targets should be normalized to lowercase."""

        target = Target(type=TargetType.HOST, value="Server01.Internal")

        assert target.value == "server01.internal"

    def test_url_scheme_and_hostname_are_lowercased(self) -> None:
        """URL targets should normalize scheme and hostname."""

        target = Target(type=TargetType.URL, value="HTTPS://Example.COM/Admin")

        assert target.value == "https://example.com/Admin"

    def test_url_without_path_gets_root_path(self) -> None:
        """URL targets without a path should normalize to `/`."""

        target = Target(type=TargetType.URL, value="https://example.com")

        assert target.value == "https://example.com/"

    def test_tags_are_trimmed_lowercased_and_deduplicated(self) -> None:
        """Tags should be normalized and duplicate tags should be removed."""

        target = Target(
            type=TargetType.DOMAIN,
            value="example.com",
            tags=[" Web ", "web", "PROD", "", "prod"],
        )

        assert target.tags == ["web", "prod"]


class TestInvalidTargets:
    """Validate that malformed target values are rejected."""

    @pytest.mark.parametrize(
        ("target_type", "value"),
        [
            (TargetType.IP, "999.999.999.999"),
            (TargetType.CIDR, "10.0.0.0/99"),
            (TargetType.IP_RANGE, "10.0.0.20-10.0.0.10"),
            (TargetType.IP_RANGE, "10.0.0.10"),
            (TargetType.DOMAIN, "https://example.com"),
            (TargetType.DOMAIN, "example.com/login"),
            (TargetType.DOMAIN, "localhost"),
            (TargetType.URL, "ftp://example.com"),
            (TargetType.URL, "https:///missing-host"),
            (TargetType.HOST, "server01/internal"),
            (TargetType.HOST, "https://server01"),
            (TargetType.SESSION, "msf 7"),
        ],
    )
    def test_invalid_target_values_raise_error(
        self,
        target_type: TargetType,
        value: str,
    ) -> None:
        """Invalid values should raise validation errors during construction."""

        with pytest.raises(ValueError):
            Target(type=target_type, value=value)

    def test_empty_value_raises_error(self) -> None:
        """An empty target value should be rejected."""

        with pytest.raises(ValueError):
            Target(type=TargetType.IP, value="   ")


class TestTargetHelpers:
    """Validate helper properties and conversion methods."""

    def test_network_target_property(self) -> None:
        """Network-addressable targets should be classified correctly."""

        assert Target(type=TargetType.IP, value="192.168.1.10").is_network_target
        assert Target(type=TargetType.CIDR, value="10.0.0.0/24").is_network_target
        assert Target(type=TargetType.IP_RANGE, value="10.0.0.1-10.0.0.5").is_network_target
        assert Target(type=TargetType.DOMAIN, value="example.com").is_network_target
        assert Target(type=TargetType.HOST, value="server01").is_network_target
        assert not Target(type=TargetType.URL, value="https://example.com").is_network_target
        assert not Target(type=TargetType.SESSION, value="msf:7").is_network_target

    def test_web_target_property(self) -> None:
        """Only URL targets should be classified as direct web targets."""

        assert Target(type=TargetType.URL, value="https://example.com").is_web_target
        assert not Target(type=TargetType.DOMAIN, value="example.com").is_web_target

    def test_runtime_target_property(self) -> None:
        """Only session targets should be classified as runtime targets."""

        assert Target(type=TargetType.SESSION, value="session:abc123").is_runtime_target
        assert not Target(type=TargetType.IP, value="192.168.1.10").is_runtime_target

    def test_requires_review_property(self) -> None:
        """Unknown and review-required targets should require review."""

        unknown = Target(type=TargetType.DOMAIN, value="example.com")
        review = Target(
            type=TargetType.DOMAIN,
            value="review.example.com",
            scope_status=ScopeStatus.REQUIRES_REVIEW,
        )
        in_scope = Target(
            type=TargetType.DOMAIN,
            value="app.example.com",
            scope_status=ScopeStatus.IN_SCOPE,
        )

        assert unknown.requires_review
        assert review.requires_review
        assert not in_scope.requires_review

    def test_scope_status_marker_methods_return_updated_copies(self) -> None:
        """Scope marker helpers should return copied targets with updated status."""

        target = Target(type=TargetType.DOMAIN, value="example.com")

        in_scope = target.mark_in_scope()
        out_of_scope = target.mark_out_of_scope()
        review = target.mark_requires_review()

        assert target.scope_status == ScopeStatus.UNKNOWN
        assert in_scope.scope_status == ScopeStatus.IN_SCOPE
        assert out_of_scope.scope_status == ScopeStatus.OUT_OF_SCOPE
        assert review.scope_status == ScopeStatus.REQUIRES_REVIEW

    def test_tool_value_returns_normalized_value(self) -> None:
        """Tool value should return the normalized target value."""

        target = Target(type=TargetType.DOMAIN, value="Example.COM")

        assert target.tool_value() == "example.com"

    def test_to_agent_dict_returns_compact_agent_shape(self) -> None:
        """Agent dictionaries should include only type and value."""

        target = Target(
            type=TargetType.URL,
            value="https://example.com/login",
            description="Login page",
            tags=["web"],
        )

        assert target.to_agent_dict() == {
            "type": "url",
            "value": "https://example.com/login",
        }
