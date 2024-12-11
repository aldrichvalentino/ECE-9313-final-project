# RYU controller for ECMP routing
# Topology: Fat tree with 4 switches, 2 levels, and 4 hosts
# Spine: s1, s2 with 2 connections to each leaf
# Leaf: s3, s4 with 2 connections to each spine, and 2 connections to each host
# Host: h1 and h2 connected to s3, h3 and h4 connected to s4

# ECMP routing algorithm:
# 1. Get the shortest path from source to destination
# 2. If there are multiple shortest paths, use ECMP to balance the load
# ECMP: hash source and destination IP, host and destination port, and protocol type
#      to select the next hop
# 3. Install the flow entries in the switches
# 4. Send the packet to the next hop

from ryu.base import app_manager
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, ether_types
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3


# static ip
static_host = {
    "h1": {
        "ip": "10.0.0.101",
        "mac": "00:00:00:00:00:01",
    },
    "h2": {
        "ip": "10.0.0.102",
        "mac": "00:00:00:00:00:02",
    },
    "h3": {
        "ip": "10.0.0.103",
        "mac": "00:00:00:00:00:03",
    },
    "h4": {
        "ip": "10.0.0.104",
        "mac": "00:00:00:00:00:04",
    },
}

# Switch => Dest => Port
shortest_path = {
    "1": {  # Spine
        "10.0.0.101": [1],
        "10.0.0.102": [1],
        "10.0.0.103": [2],
        "10.0.0.104": [2],
    },
    "2": {  # Spine
        "10.0.0.101": [1],
        "10.0.0.102": [1],
        "10.0.0.103": [2],
        "10.0.0.104": [2],
    },
    "3": {  # Leaf
        # Local
        "10.0.0.101": [3],
        "10.0.0.102": [4],
        # Multiple shortest paths
        "10.0.0.103": [1, 2],
        "10.0.0.104": [1, 2],
    },
    "4": {  # Leaf
        # Multiple shortest paths
        "10.0.0.101": [1, 2],
        "10.0.0.102": [1, 2],
        # Local
        "10.0.0.103": [3],
        "10.0.0.104": [4],
    },
}


class ECMP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ECMP, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(datapath, in_port, pkt)
            return

    def handle_arp(self, datapath, in_port, pkt):
        """Reply ARP request based on static IP-MAC mapping"""
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        self.logger.info("ARP request received: %s", arp_pkt)

        mac = None
        if arp_pkt.dst_ip == static_host["h1"]["ip"]:
            mac = static_host["h1"]["mac"]
        elif arp_pkt.dst_ip == static_host["h2"]["ip"]:
            mac = static_host["h2"]["mac"]
        elif arp_pkt.dst_ip == static_host["h3"]["ip"]:
            mac = static_host["h3"]["mac"]
        elif arp_pkt.dst_ip == static_host["h4"]["ip"]:
            mac = static_host["h4"]["mac"]
        else:
            return

        e = ethernet.ethernet(
            dst=arp_pkt.src_mac,
            src=mac,
            ethertype=ether_types.ETH_TYPE_ARP,
        )
        a = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=mac,
            src_ip=arp_pkt.dst_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip,
        )
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        self.send_packet(datapath, in_port, p)

    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
        self.logger.info("Packet sent: %s", pkt)

    def handle_ip(self, datapath, in_port, pkt):
        """Forward IP packet based on ECMP routing"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Get TCP/UDP port number
        src_port, dst_port, protocol = None, None, None
        if ip_pkt.proto == 6:
            tp_pkt = pkt.get_protocol(tcp.tcp)
            src_port = tp_pkt.src_port
            dst_port = tp_pkt.dst_port
            protocol = "tcp"
        elif ip_pkt.proto == 17:
            tp_pkt = pkt.get_protocol(udp.udp)
            src_port = tp_pkt.src_port
            dst_port = tp_pkt.dst_port
            protocol = "udp"

        self.logger.info(
            "IP packet received: src=%s, dst=%s, src_port=%s, dst_port=%s, protocol=%s",
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

        # Determine output port based on shortest path + ECMP
        out_port = None
        dp_id = str(datapath.id)
        paths = shortest_path[dp_id][dst_ip]
        if len(paths) == 1:
            out_port = paths[0]
        else:
            # Get hash value
            hash_val = hash((src_ip, dst_ip, src_port, dst_port, protocol))
            # Modulo to get the index
            out_port = paths[hash_val % len(paths)]

        self.logger.info("Output port: %s", out_port)

        actions = [parser.OFPActionOutput(out_port)]
        options = {}
        if ip_pkt.proto == 6:
            options["tcp_src"] = src_port  # source port TCP
            options["tcp_dst"] = dst_port  # destination port TCP
        elif ip_pkt.proto == 17:
            options["udp_src"] = src_port  # source port UDP
            options["udp_dst"] = dst_port  # destination port UDP
        # Install flow entry based on 5-tuple
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=ip_pkt.proto,  # protocol type
            ipv4_src=src_ip,  # source IP
            ipv4_dst=dst_ip,  # destination IP
            **options,
        )
        # Add flow entry
        self.add_flow(datapath, 1, match, actions)

        self.logger.info("Flow entry installed: %s", match)

        # Send packet
        self.send_packet(datapath, out_port, pkt)
