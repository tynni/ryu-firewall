from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.log import setLogLevel, info
import csv
import time

#simple topology w 3 hosts + 1 switch
class SimpleTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        s1 = self.addSwitch('s1')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

def run_benchmarks(csv_file="benchmark_results_static.csv"):
    topo = SimpleTopo()
    net = Mininet(topo=topo, controller=None)

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()

    h1 = net.get('h1')  #attacker
    h2 = net.get('h2')  #victim
    h3 = net.get('h3')  #normal host

    results = []

    info("*** Baseline ping h1->h2\n")
    results.append(["baseline_ping_h1_h2", h1.cmd("ping -c 5 10.0.0.2")])

    info("*** Baseline iperf h1->h2\n")
    h2.cmd("iperf -s &")
    time.sleep(1)
    results.append(["baseline_iperf_h1_h2", h1.cmd("iperf -c 10.0.0.2 -t 5")])

    info("*** Trigger attack from h1\n")
    for i in range(50):
        h1.cmd("ping -c 1 10.0.0.2 > /dev/null &")
    time.sleep(2)

    info("*** Ping after firewall block\n")
    results.append(["post_block_ping_h1_h2", h1.cmd("ping -c 5 10.0.0.2")])

    info("*** Normal host h3->h2\n")
    results.append(["normal_ping_h3_h2", h3.cmd("ping -c 5 10.0.0.2")])

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test_name", "output"])
        for row in results:
            writer.writerow(row)

    net.stop()
    info("*** Network stopped\n")

if __name__ == "__main__":
    setLogLevel("info")
    run_benchmarks()

