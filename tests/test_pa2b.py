from base import *
import unittest
import random


class TestPA2BFunctionality(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False,
                              manual_sr=False, pa2b=True)

    def tearDown(self):
        self.tearDownEnvironment()

    def _client_icmp_errors(self, wait=0.7):
        return [pkt for pkt, _ in self.expectPackets("client", type="icmp", timewait_sec=wait)]

    def test_udp_to_router_generates_port_unreachable(self):
        """UDP traffic addressed to a router interface should get ICMP type 3/code 3."""
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=self.client["gw"], id=random.randint(1, 65535)) /
            UDP(sport=33434, dport=33434) /
            b"traceroute-probe"
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._client_icmp_errors()
            if p.haslayer(ICMP)
            and p[ICMP].type == 3
            and p[ICMP].code == 3
            and p[IP].src == self.client["gw"]
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP port unreachable for UDP to itself")

    def test_tcp_to_router_generates_port_unreachable(self):
        """TCP traffic addressed to a router interface should get ICMP type 3/code 3."""
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=self.client["gw"], id=random.randint(1, 65535)) /
            TCP(sport=49152, dport=80, flags="S")
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._client_icmp_errors()
            if p.haslayer(ICMP)
            and p[ICMP].type == 3
            and p[ICMP].code == 3
            and p[IP].src == self.client["gw"]
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP port unreachable for TCP to itself")


class TestPA2BLongestPrefixMatch(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable_pa2b_lpm', build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def _client_icmp_errors(self, wait=0.7):
        return [pkt for pkt, _ in self.expectPackets("client", type="icmp", timewait_sec=wait)]

    def test_lpm_prefers_more_specific_prefix(self):
        """A /24 should beat an earlier conflicting /16 route."""
        self.clearPcapBuffers()
        target = "192.168.2.99"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=target, id=random.randint(1, 65535)) /
            ICMP(type=8, id=random.randint(1, 65535))
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        server1_arps = [
            p for p, _ in self.expectPackets("server1", type="arp", timewait_sec=0.5)
            if p.haslayer(ARP)
            and p[ARP].op == 1
            and p[ARP].psrc == self.server1["gw"]
            and p[ARP].pdst == target
        ]
        self.assertTrue(server1_arps, msg="Router did not use the more specific /24 route")

        server2_arps = [
            p for p, _ in self.expectPackets("server2", type="arp", timewait_sec=0.1)
            if p.haslayer(ARP)
            and p[ARP].op == 1
            and p[ARP].pdst == self.server2["ip"]
        ]
        self.assertFalse(server2_arps, msg="Router used the broader /16 route instead of the /24")

    def test_arp_reply_releases_queued_packet(self):
        """A queued packet should be forwarded after the matching ARP reply is received."""
        self.clearPcapBuffers()
        target = "192.168.2.99"
        echo_id = random.randint(1, 65535)
        ip_id = random.randint(1, 65535)
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=target, id=ip_id) /
            ICMP(type=8, id=echo_id)
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        arps = [
            p for p, _ in self.expectPackets("server1", type="arp", timewait_sec=0.4)
            if p.haslayer(ARP)
            and p[ARP].op == 1
            and p[ARP].pdst == target
        ]
        self.assertTrue(arps, msg="Router did not ARP before forwarding to the fake host")

        self.clearPcapBuffers()
        arp_reply = (
            Ether(src=self.server1["mac"], dst=self.server1["gwmac"]) /
            ARP(
                op=2,
                hwsrc=self.server1["mac"],
                psrc=target,
                hwdst=self.server1["gwmac"],
                pdst=self.server1["gw"],
            )
        )
        self.sendPacket(arp_reply, node=self.server1["m"].name)

        forwarded = [
            p for p, _ in self.expectPackets("server1", type="icmp", timewait_sec=0.5)
            if p.haslayer(IP)
            and p.haslayer(ICMP)
            and p[IP].src == self.client["ip"]
            and p[IP].dst == target
            and p[IP].id == ip_id
            and p[ICMP].type == 8
            and p[ICMP].id == echo_id
        ]
        self.assertTrue(forwarded, msg="Router did not forward queued packet after ARP reply")

    def test_unanswered_arp_generates_host_unreachable(self):
        """After about five unanswered ARP requests, queued packets should get type 3/code 1."""
        self.clearPcapBuffers()
        target = "192.168.2.99"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=target, id=random.randint(1, 65535)) /
            ICMP(type=8, id=random.randint(1, 65535))
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._client_icmp_errors(wait=6.5)
            if p.haslayer(ICMP)
            and p[ICMP].type == 3
            and p[ICMP].code == 1
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP host unreachable after ARP retries")


if __name__ == "__main__":
    unittest.main()
