#!/usr/bin/env python3
import os
import sys
import time

from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mininet.node import RemoteController
from mininet.term import makeTerm
import matplotlib.pyplot as plt

# Thời gian mô phỏng sự cố AP1
AP1_DOWN_TIME = 10.0
AP1_UP_DELAY = 7.0


class MobilityDemoCLI(CLI):
 
    def __init__(self, net, **kwargs):
        super().__init__(net, **kwargs)

    def _toggle_ap1_link(self):
        
        info("*** [MobilityDemo] ap1-wlan1 will go DOWN for %.1f seconds\n" % AP1_DOWN_TIME)
        time.sleep(AP1_DOWN_TIME)

        down_cmd = "ap1 ifconfig ap1-wlan1 down"
        print(self.prompt + down_cmd)
        self.onecmd(down_cmd)

        info("*** [MobilityDemo] ap1-wlan1 will come UP after %.1f seconds\n" % AP1_UP_DELAY)
        time.sleep(AP1_UP_DELAY)

        up_cmd = "ap1 ifconfig ap1-wlan1 up"
        print(self.prompt + up_cmd)
        self.onecmd(up_cmd)

        info("*** [MobilityDemo] ap1-wlan1 is back UP\n")

    def run(self):
        self._toggle_ap1_link()
        return super().run()


def build_topology():
    net = Mininet_wifi()

    info("*** Creating nodes\n")
    h1 = net.addHost("h1", ip="10.0.0.1/8")

    sta1 = net.addStation("sta1", ip="10.0.0.3/8", position="150,70,0")
    sta2 = net.addStation("sta2", ip="10.0.0.2/8", position="50,80,0")

    ap1 = net.addAccessPoint(
        "ap1", ssid="lab-ssid", mode="g", channel="1",
        position="50,50,0", range=40
    )
    ap2 = net.addAccessPoint(
        "ap2", ssid="lab-ssid", mode="g", channel="6",
        position="150,80,0", range=40
    )

    s1 = net.addSwitch("s1")
    c0 = net.addController(
        "c0", controller=RemoteController,
        ip="127.0.0.1", port=6633
    )

    info("*** Configuring WiFi environment\n")
    net.setPropagationModel(model="logDistance", exp=4.5)
    net.configureNodes()

    info("*** Creating wired links\n")
    net.addLink(ap1, s1)
    net.addLink(ap2, s1)
    net.addLink(h1, s1)

    info("*** Plotting topology\n")
    net.plotGraph(max_x=200, max_y=150)

    info("*** Defining mobility scenario\n")
    net.startMobility(time=0)

    net.mobility(sta2, "start", time=1, position="50,80,0")
    net.mobility(sta2, "stop", time=7, position="130,80,0")

    net.mobility(sta1, "start", time=1, position="150,70,0")
    net.mobility(sta1, "stop", time=7, position="70,60,0")

    net.stopMobility(time=3600)

    plt.ion()
    plt.show(block=False)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    s1.start([c0])

    info("*** Spawning xterm for h1 -> ping sta2\n")
    makeTerm(
        h1,
        title="h1-ping-sta2",
        term="xterm",
        cmd="bash -c 'ping 10.0.0.2; exec bash'"
    )

    return net


def main():
    setLogLevel("info")

    net = build_topology()

    info("*** Starting custom CLI (MobilityDemoCLI)\n")
    MobilityDemoCLI(net)

    info("*** Stopping network\n")
    net.stop()

    info("*** Closing all xterms\n")
    os.system("killall xterm >/dev/null 2>&1 || true")


if __name__ == "__main__":
    main()

