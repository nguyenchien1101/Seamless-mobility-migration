#!/usr/bin/env python
import os
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
import matplotlib.pyplot as plt
from mininet.node import RemoteController
import sys
from mininet.term import makeTerm
import time

class BatchCLI(CLI):
    def __init__(self, net, **kwargs):
        super().__init__(net)

    def run(self):
        info("*** Port ap1-wlan1 is going to be inactive for the next 10 seconds!!!\n")
        time.sleep(10.0)
        command = 'ap1 ifconfig ap1-wlan1 down'
        print(self.prompt + command)
        self.onecmd(command)

        info("*** Port ap1-wlan1 is going to be active again for the next 7 seconds!!!\n")
        time.sleep(7.0)
        command = 'ap1 ifconfig ap1-wlan1 up'
        print(self.prompt + command)
        self.onecmd(command)
        
        time.sleep(3.0)
        self.onecmd('sta1 iwconfig sta1-wlan0 essid "ssid-1"')
        self.onecmd('sta2 iwconfig sta2-wlan0 essid "ssid-1"')

        return super().run()

def topology(args):
    net = Mininet_wifi()

    info("*** Creating nodes\n")
    h1 = net.addHost('h1', ip='10.0.0.1/8')

    sta1 = net.addStation('sta1', ip='10.0.0.3/8', position='150,70,0')  # Near ap2
    sta2 = net.addStation('sta2', ip='10.0.0.2/8', position='50,80,0')   # Near ap1

    ap1 = net.addAccessPoint('ap1', ssid='ssid-1', mode='g', channel='1', position='50,50,0', range=40)
    ap2 = net.addAccessPoint('ap2', ssid='ssid-1', mode='g', channel='1', position='150,80,0', range=40)

    s1 = net.addSwitch('s1')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info("*** Configuring environment\n")
    net.setPropagationModel(model="logDistance", exp=4.5)
    net.configureNodes()
    #net.set ('ssf')
    info("*** Creating links\n")
    net.addLink(ap1, s1)
    net.addLink(ap2, s1)
    net.addLink(h1, s1)

    info("*** Show plot\n")
    net.plotGraph(max_x=200, max_y=150)

    info("*** Starting mobility\n")
    net.startMobility(time=0)

    # Mobility for sta2: go near ap2
    net.mobility(sta2, 'start', time=1, position='50,80,0')
    net.mobility(sta2, 'stop', time=7, position='130,80,0')

    # Mobility for sta1: go near ap1
    net.mobility(sta1, 'start', time=1, position='150,70,0')
    net.mobility(sta1, 'stop', time=7, position='70,60,0')

    net.stopMobility(time=3600)
    plt.ion()
    plt.show(block=False)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    s1.start([c0])
    net.staticArp()
    makeTerm(
        h1,
        title='h1-ping-sta2',
        term='xterm',
        cmd="bash -c 'ping 10.0.0.2; exec bash'"
    )

    info("*** CLI\n")
    BatchCLI(net)

    info("*** Stopping network\n")
    net.stop()

    info("*** Closing all xterms\n")
    os.system('killall xterm')

if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
