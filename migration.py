from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class CustomCLI(CLI):
    def do_movesw(self, _line):
        """Interrupt s1-s2 and connect s1-s4"""
        print(">>> Interrupt s1-s2 and connect s1-s4")
        net = self.mn

        s1 = net.get('s1')
        s4 = net.get('s4')

        # Interrupt s1-s2
        net.configLinkStatus('s1', 's2', 'down')

        # Create new link s1-s4
        link = net.addLink(s1, s4)
        link.intf1.ifconfig('up')
        link.intf2.ifconfig('up')

        s1.attach(link.intf1.name)
        s4.attach(link.intf2.name)
        print(">>> Completed: s1 connected to s4")

    def do_moveho(self, _line):
        print(">>> Migrating h2 from s1 to s2")
        net = self.mn

        s1 = net.get('s1')
        s2 = net.get('s2')
        h2 = net.get('h2')

        # Interrupt s1-h2
        net.configLinkStatus('s1', 'h2', 'down')

        # Create new link s2-h2
        link = net.addLink(s2, h2)
        link.intf1.ifconfig('up') 
        link.intf2.ifconfig('up')

        h2.setIP('10.0.0.2/8', intf=link.intf2)
        s2.attach(link.intf1.name)


def create_sdn_network():
    setLogLevel('info')

    net = Mininet()

    print("Adding controller")
    c0 = net.addController('c0', controller=RemoteController, ip="127.0.0.1", port=6633)

    print("Adding hosts")
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')

    print("Adding switches")
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    print("Creating links")
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s3, h3)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)

    print("Starting network")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    net.pingFull()

    print("Running CLI")
    CustomCLI(net)
    print("Stopping network")
    net.stop()

if __name__ == '__main__':
    create_sdn_network()
