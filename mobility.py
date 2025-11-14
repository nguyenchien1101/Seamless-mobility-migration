#!/usr/bin/env python
import os
import sys
import time

from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mininet.node import RemoteController
from mininet.term import makeTerm

import matplotlib.pyplot as plt


def trigger_link_failure(cli, ap='ap2', iface='ap2-wlan1', down_time=4):

    info(f"\n*** [Trigger] LINK FAILURE on {ap}:{iface}\n")

    cmd_down = f"{ap} ifconfig {iface} down"
    print(cli.prompt + cmd_down)
    cli.onecmd(cmd_down)

    info(f"*** {iface} is DOWN for {down_time} seconds...\n")
    time.sleep(down_time)

    cmd_up = f"{ap} ifconfig {iface} up"
    print(cli.prompt + cmd_up)
    cli.onecmd(cmd_up)

    info(f"*** {iface} is UP again, forcing STA re-association...\n")

    cli.onecmd('sta1 iwconfig sta1-wlan0 essid "ssid-1"')
    cli.onecmd('sta2 iwconfig sta2-wlan0 essid "ssid-1"')

    info("*** sta1 & sta2 reassociated to ssid-1\n")


class BatchCLI(CLI):

    def do_lf(self, line):
        trigger_link_failure(self, ap='ap2', iface='ap2-wlan1', down_time=4)

    def help_lf(self):
        info("lf: trigger link failure on ap2-wlan1 (down ~4s rồi up lại)\n")

    def run(self):
        return super().run()


def topology(args):
    net = Mininet_wifi()

    info("*** Creating nodes\n")
    h1 = net.addHost('h1', ip='10.0.0.1/8')


    sta2 = net.addStation('sta2', ip='10.0.0.2/8', position='60,70,0')    
    sta1 = net.addStation('sta1', ip='10.0.0.3/8', position='140,50,0')   
    sta3 = net.addStation('sta3', ip='10.0.0.4/8', position='100,120,0')  

    ap1 = net.addAccessPoint(
        'ap1', ssid='ssid-1', mode='g',
        channel='1', position='40,40,0', range=45
    )
    ap2 = net.addAccessPoint(
        'ap2', ssid='ssid-1', mode='g',
        channel='1', position='160,40,0', range=45
    )
    ap3 = net.addAccessPoint(
        'ap3', ssid='ssid-1', mode='g',
        channel='1', position='100,130,0', range=45
    )

    s1 = net.addSwitch('s1')
    c0 = net.addController(
        'c0', controller=RemoteController,
        ip='127.0.0.1', port=6633
    )

    info("*** Configuring WiFi environment\n")
    net.setPropagationModel(model="logDistance", exp=4.5)
    net.configureNodes()

    info("*** Creating wired links (ap1/ap2/ap3/h1 <-> s1)\n")
    net.addLink(ap1, s1)
    net.addLink(ap2, s1)
    net.addLink(ap3, s1)
    net.addLink(h1, s1)

    info("*** Showing Mininet-WiFi graph (triangle topology)\n")
    net.plotGraph(max_x=200, max_y=150)
    plt.ion()
    plt.show(block=False)


    net.startMobility(time=0)

    net.mobility(sta2, 'start', time=8,  position='60,70,0')
    net.mobility(sta2, 'stop',  time=13, position='150,70,0')

    net.mobility(sta1, 'start', time=8,  position='140,50,0')
    net.mobility(sta1, 'stop',  time=13, position='50,50,0')

    net.stopMobility(time=20)

    info("*** Starting network & controller\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])
    s1.start([c0])

    info("*** Installing static ARP entries\n")
    net.staticArp()

    time.sleep(3)

    makeTerm(
        h1,
        title='h1-ping-sta2',
        term='xterm',
        cmd="bash -c 'ping -i 0.3 -D 10.0.0.2; exec bash'"
    )

    BatchCLI(net)

    info("*** Stopping network\n")
    net.stop()

    info("*** Closing all xterms\n")
    os.system('killall xterm')


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)

