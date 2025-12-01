from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import logging

LOG = logging.getLogger('ryu.app.dynamic_firewall')

class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    DEFAULT_PKT_THRESHOLD = 500  # Normal traffic ~30 pkts, attack ~3000 pkts

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ip_pkt_counts = {}
        self.pkt_threshold = int(kwargs.get('pkt_threshold', self.DEFAULT_PKT_THRESHOLD))
        self.poll_interval = 5  

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss: send all unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        LOG.info("Installed table-miss on switch %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == 0 and datapath.id in self.datapaths:
            del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x0800:  
            ip = pkt.get_protocol(ipv4.ipv4)
            src = ip.src

            # Count packets from each IP hitting the controller
            self.ip_pkt_counts[src] = self.ip_pkt_counts.get(src, 0) + 1

            LOG.debug("Packet from %s (count=%d)", src, self.ip_pkt_counts[src])

        # No forwarding here (table-miss handles it)
        return

    def _monitor(self):
        while True:
            # Evaluate packet counts every poll interval
            self._evaluate_counters()
            hub.sleep(self.poll_interval)

    def _evaluate_counters(self):
        to_block = []

        # Normal traffic ~30 packets, attack traffic ~3000 packets
        for ip, count in list(self.ip_pkt_counts.items()):
            if count > self.pkt_threshold:
                LOG.warning("🔥 ATTACK DETECTED from %s (%d packets)", ip, count)
                to_block.append(ip)
                del self.ip_pkt_counts[ip]

        # Install block rules
        for ip in to_block:
            for dp in list(self.datapaths.values()):
                self._install_block_flow(dp, ip)

    def _install_block_flow(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip
        )

        # No actions = drop
        instructions = []

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=200,   # High priority so it overrides everything
            match=match,
            instructions=instructions,
            hard_timeout=60  # Auto-remove after 60 sec
        )

        datapath.send_msg(mod)
        LOG.warning("Installed DROP rule for %s on switch %s", src_ip, datapath.id)