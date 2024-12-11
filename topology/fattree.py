#!/usr/bin/env python3

# Mininet script to create a FatTree topology
# Switch k = 4, Level = 2, Hosts = 4
# Use remote controller

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch


link_bandwidth = 1000  # 1 Gbps
link_delay = "10ms"


class FatTree(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch("s1", dpid="0000000000000001")
        s2 = self.addSwitch("s2", dpid="0000000000000002")
        s3 = self.addSwitch("s3", dpid="0000000000000003")
        s4 = self.addSwitch("s4", dpid="0000000000000004")
        # Hosts
        h1 = self.addHost("h1", ip="10.0.0.101/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.102/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.103/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.104/24", mac="00:00:00:00:00:04")
        # Links
        self.addLink(
            s1, s3, port1=1, port2=1, key="13", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s1, s4, port1=2, port2=1, key="14", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s2, s3, port1=1, port2=2, key="23", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s2, s4, port1=2, port2=2, key="24", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s3, h1, port1=3, port2=1, key="3h1", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s3, h2, port1=4, port2=1, key="4h2", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s4, h3, port1=3, port2=1, key="3h3", bw=link_bandwidth, delay=link_delay
        )
        self.addLink(
            s4, h4, port1=4, port2=1, key="4h4", bw=link_bandwidth, delay=link_delay
        )


if __name__ == "__main__":
    setLogLevel("info")

    topo = FatTree()
    net = Mininet(topo=topo, waitConnected=True, controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()
