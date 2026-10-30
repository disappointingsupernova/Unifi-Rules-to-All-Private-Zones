"""Unit tests for firewall policy builder helpers."""

import pytest
from src.unifi_manager.ui.flows import (
    build_ip_scope,
    build_port_filter_inline,
    build_port_filter_ref,
    build_dest_traffic_filter,
    build_policy,
)


class TestBuildIpScope:
    def test_any_protocol(self):
        result = build_ip_scope("any")
        assert result == {"ipVersion": "IPV4"}

    def test_udp(self):
        result = build_ip_scope("udp")
        assert result["ipVersion"] == "IPV4"
        assert result["protocolFilter"]["protocol"]["name"] == "udp"

    def test_tcp(self):
        result = build_ip_scope("tcp")
        assert result["protocolFilter"]["protocol"]["name"] == "tcp"

    def test_tcp_udp_preset(self):
        result = build_ip_scope("tcp+udp")
        assert result["protocolFilter"]["type"] == "PRESET"
        assert result["protocolFilter"]["preset"]["name"] == "TCP_UDP"


class TestBuildPortFilter:
    def test_inline_single_port(self):
        result = build_port_filter_inline([514])
        assert result["type"] == "PORTS"
        assert result["items"] == [{"type": "SINGLE", "value": 514}]

    def test_inline_multiple_ports(self):
        result = build_port_filter_inline([80, 443])
        assert len(result["items"]) == 2

    def test_ref_filter(self):
        result = build_port_filter_ref("some-uuid")
        assert result["type"] == "TRAFFIC_MATCHING_LIST"
        assert result["trafficMatchingListId"] == "some-uuid"
        assert result["matchOpposite"] is False


class TestBuildDestTrafficFilter:
    def test_no_ip_no_port(self):
        assert build_dest_traffic_filter("", None) is None

    def test_port_only(self):
        pf = build_port_filter_inline([514])
        result = build_dest_traffic_filter("", pf)
        assert result["type"] == "PORT"
        assert result["portFilter"] == pf

    def test_ip_only_address(self):
        result = build_dest_traffic_filter("10.0.0.1", None)
        assert result["type"] == "IP_ADDRESS"
        assert result["ipAddressFilter"]["items"][0]["type"] == "IP_ADDRESS"

    def test_ip_only_subnet(self):
        result = build_dest_traffic_filter("10.0.0.0/24", None)
        assert result["ipAddressFilter"]["items"][0]["type"] == "SUBNET"

    def test_ip_and_port(self):
        pf = build_port_filter_inline([514])
        result = build_dest_traffic_filter("10.0.0.1", pf)
        assert result["type"] == "IP_ADDRESS"
        assert "portFilter" in result


class TestBuildPolicy:
    def test_basic_structure(self):
        policy = build_policy(
            name="Test Policy",
            description="A test",
            source_zone_id="src-uuid",
            dest_zone_id="dst-uuid",
            ip_scope={"ipVersion": "IPV4"},
            dest_traffic_filter=None,
        )
        assert policy["name"] == "Test Policy"
        assert policy["enabled"] is True
        assert policy["action"]["type"] == "ALLOW"
        assert policy["source"]["zoneId"] == "src-uuid"
        assert policy["destination"]["zoneId"] == "dst-uuid"
        assert "trafficFilter" not in policy["destination"]

    def test_with_traffic_filter(self):
        pf = build_port_filter_inline([514])
        dtf = build_dest_traffic_filter("", pf)
        policy = build_policy(
            name="Test",
            description="",
            source_zone_id="s",
            dest_zone_id="d",
            ip_scope={"ipVersion": "IPV4"},
            dest_traffic_filter=dtf,
        )
        assert "trafficFilter" in policy["destination"]
