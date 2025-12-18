from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
from collections import deque
import logging

LOG = logging.getLogger('ryu.app.dynamic_firewall')
LOG.setLevel(logging.INFO)

class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    THRESHOLD = 4  # packets over WINDOW seconds to trigger block (lowered for testing)
    POLL_INTERVAL = 1  # seconds
    WINDOW = 3  # number of intervals to keep in sliding window

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # counts collected during the current interval (ip -> count)
        self.current_counts = {}
        # sliding window of recent interval counts per IP (ip -> deque)
        self.ip_pkt_window = {}
        self.blocked_ips = set()
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Table-miss: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)
        self.datapaths[datapath.id] = datapath
        LOG.info(f"Installed table-miss on switch {datapath.id}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dpid = datapath.id
        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        ip_hdr = pkt.get_protocol(ipv4.ipv4)
        if ip_hdr:
            src_ip = ip_hdr.src
            # increment counter for this interval
            self.current_counts[src_ip] = self.current_counts.get(src_ip, 0) + 1
            LOG.debug("packet from %s count=%s", src_ip, self.current_counts[src_ip])

            if src_ip in self.blocked_ips:
                # Drop attacker packets immediately (do not forward)
                LOG.info("Dropping packet from blocked IP %s", src_ip)
                return

        # L2 forwarding
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

        # Install a simple L2 forwarding flow for known destination.
        # PacketIn events and hide attack traffic from the controller.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst_mac)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=1,
                                    match=match,
                                    instructions=inst,
                                    hard_timeout=300)
            datapath.send_msg(mod)

    def _monitor(self):
        while True:
            try:
                self._check_attacks()
            except Exception:
                LOG.exception("error in monitor")
            # clear current interval counts after processing (window keeps history)
            self.current_counts.clear()
            hub.sleep(self.POLL_INTERVAL)

    def _check_attacks(self):
        # Append current interval counts into sliding windows and evaluate totals
        LOG.info("Checking attacks; monitored_ips=%s", list(self.current_counts.keys()))
        for ip, cnt in list(self.current_counts.items()):
            dq = self.ip_pkt_window.setdefault(ip, deque(maxlen=self.WINDOW))
            dq.append(cnt)
            total = sum(dq)
            LOG.info("ip %s window=%s total=%s", ip, list(dq), total)
            if total > self.THRESHOLD and ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                LOG.warning("BLOCKING attacker %s (%s pkts over %s s)", ip, total, self.WINDOW)
                if not self.datapaths:
                    LOG.warning("No datapaths known when attempting to block %s", ip)
                for dp in self.datapaths.values():
                    self._install_drop(dp, ip)

    def _install_drop(self, datapath, ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=500,
                                match=match,
                                instructions=[])  # DROP
        datapath.send_msg(mod)
        LOG.warning(f"DROP rule installed on switch {datapath.id} for {ip}")
