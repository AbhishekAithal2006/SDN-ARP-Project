from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp

class ARPHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARPHandler, self).__init__(*args, **kwargs)
        self.mac_to_port = {}   # {dpid: {mac: port}}
        self.arp_table = {}     # {ip: mac}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Send all unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

        print(f"Switch {datapath.id} connected")

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst = eth.dst
        src = eth.src

        # Learn MAC
        self.mac_to_port[dpid][src] = in_port
        print(f"[Switch {dpid}] Learned MAC: {src} -> Port {in_port}")

        # ARP Handling
        if eth.ethertype == 2054:
            arp_pkt = pkt.get_protocol(arp.arp)

            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
            print(f"[ARP] {arp_pkt.src_ip} -> {arp_pkt.src_mac}")

        # Forwarding decision
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print(f"[Switch {dpid}] Forwarding {src} -> {dst} via port {out_port}")
        else:
            out_port = ofproto.OFPP_FLOOD
            print(f"[Switch {dpid}] Flooding packet from {src}")

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule if known destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # Send packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
