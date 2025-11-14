from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class CustomCLI(CLI):

    def do_move_h(self, line):
        args = line.split()
        if len(args) != 2:
            print("Usage: move_h <host> <dest_switch>")
            return

        host_name, dest_sw_name = args
        net = self.mn

        try:
            host = net.get(host_name)
            dest_sw = net.get(dest_sw_name)
        except KeyError:
            print("Error: host or switch does not exist!")
            return

        print(f"HOST MIGRATION: moving {host_name} → {dest_sw_name}")

        # 1) Find old switch automatically
        old_link = None
        for link in net.links:
            if link.intf1.node == host or link.intf2.node == host:
                old_link = link
                break

        if not old_link:
            print(f"ERROR: No link found between {host_name} and any switch.")
            return

        # Identify old switch
        old_sw = old_link.intf1.node if old_link.intf1.node != host else old_link.intf2.node
        old_sw_name = old_sw.name

        print(f" - Found old connection: {host_name} ←→ {old_sw_name}")

        # Bring down old link
        net.configLinkStatus(old_sw_name, host_name, "down")

        # 2) Create new link
        print(f" - Creating new link: {host_name} ←→ {dest_sw_name}")
        newlink = net.addLink(dest_sw, host)

        newlink.intf1.ifconfig('up')
        newlink.intf2.ifconfig('up')

        # Re-apply same IP
        ip = host.IP()
        host.setIP(ip, intf=newlink.intf2)

        dest_sw.attach(newlink.intf1.name)

        print(f">>> Migration complete: {host_name} is now connected to {dest_sw_name}")

    # ------------------------------------------------------------------------

    def do_move_sw(self, line):
        args = line.split()
        if len(args) != 3:
            print("Usage: move_sw <switch1> <switch2> <switch3>")
            return

        sw1_name, sw2_name, sw3_name = args
        net = self.mn

        try:
            sw1 = net.get(sw1_name)
            sw2 = net.get(sw2_name)
            sw3 = net.get(sw3_name)
        except KeyError:
            print("Error: switch does not exist!")
            return

        print(f">>> Interrupt {sw1_name}-{sw2_name} and connect {sw1_name}-{sw3_name}")

        # Remove old link properly
        old_links = net.linksBetween(sw1, sw2)
        if old_links:
           for link in old_links:
              net.delLink(link)
        else:
           print(" - WARNING: no existing link to remove")

        # Create new link
        print(f" - Creating new link {sw1_name}-{sw3_name}")
        newlink = net.addLink(sw1, sw3)

        newlink.intf1.ifconfig('up')
        newlink.intf2.ifconfig('up')

        sw1.attach(newlink.intf1.name)
        sw3.attach(newlink.intf2.name)

        print(f">>> SWITCH MIGRATION completed: {sw1_name} now connected to {sw3_name}")

        
        
# ----------------------
# Network topology
# ----------------------
def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(s4, s3)
    net.addLink(h1, s1)
    net.addLink(s1, h2)
    net.addLink(s3, h3)
    net.addLink(s1, s2)
    net.addLink(s2, s3)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])

    info('*** Ready — starting Custom CLI\n')
    CustomCLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
    