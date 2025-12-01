"""Simple Mininet topology for testing the SDN firewall.
Usage:
    sudo python3 simple_topo.py
Or use with mn:
    sudo mn --custom topology/simple_topo.py --topo mytopo --controller=remote,ip=127.0.0.1
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class MyTopo(Topo):
    def build(self):
        # single switch, three hosts
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

def run():
    topo = MyTopo()
    net = Mininet(topo=topo, controller=None)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    print("Network started. Hosts: ", net.hosts)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
