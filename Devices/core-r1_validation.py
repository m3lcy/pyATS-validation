from pyats.topology import loader
from genie.conf import Genie
from genie.utils.diff import Diff


testbed = loader.load('network_testbed.yml')
device = testbed.devices['core-r1']

expected_config = {
    "hostname": "core-r1",
    "password": "cisco",
    "username": "admin",
    "banner": "Authorized Access Only!!!",
    "interfaces": {
        "GigabitEthernet0/0": {
            "ip_address": "172.16.12.226",
            "mask": "255.255.255.252",
            "status": "up",
            "duplex": "auto",
            "speed": "auto"
        },
        "GigabitEthernet0/1": {
            "ip_address": "172.16.12.229",
            "mask": "255.255.255.252",
            "status": "up",
            "duplex": "auto",
            "speed": "auto"
        },
        "Serial0/0/0": {
            "ip_address": "172.17.12.1",
            "mask": "255.255.255.0",
            "status": "up"
        },
        "vlan1": {
            "ip_address": "192.168.12.35",
            "mask": "255.255.255.224",
            "status": "up"
        }
    },
    "routing": {
        "ospf": {
            "router_id": "1.1.1.1",
            "networks": [
                "172.17.0.0 0.0.255.255 area 0"
            ]
        },
        
        "rip": {
            "version": 2,
            "networks": [
                "172.16.0.0",
                "172.17.0.0"
            ]
        }
    },
    "dhcp": {
        "excluded_address": [
            "172.16.12.1 172.16.12.10",
            "172.16.12.33 172.16.12.43",
            "172.16.12.65 172.16.12.75",
            "172.16.12.97 172.16.12.107",
            "172.16.12.129 172.16.12.138",
            "172.16.12.161 172.16.12.170",
            "172.16.12.193 172.16.12.202"
        ],
        "pools": {
            "vlan10": {
                "network": "172.16.12.0 255.255.255.224",
                "default_router": "172.16.12.1"
            },
            "vlan20": {
                "network": "172.16.12.32 255.255.255.224",
                "default_router": "172.16.12.33"
            },
            "vlan30": {
                "network": "172.16.12.64" "255.255.255.224",
                "default_router": "172.16.12.65"
            },
            "vlan99": {
                "network": "172.16.12.96 255.255.255.224",
                "default_router": "172.16.12.97"
            },
            "vlan100": {
                "network": "172.16.12.128 255.255.255.224",
                "defualt_router": "172.16.12.129"
            },
            "vlan200": {
                "network": "172.16.12.160 255.255.255.224",
                "default_router": "172.16.12.161"
            },
            "vlan300": {
                "network": "172.16.12.192 255.255.255.224",
                "default_router": "172.16.12.193"
            }
        }
    },
    "security": {
        "enable_secret": "cisco",
        "line_vty": {
            "password": "cisco123",
            "login_local": True,
            "transport_input": "ssh"
        },
        "ssh_key": {
            "modulus": "1024",
            "label": "ssh-key"
        }
    },
    "nat": {
        "outside": "Serial0/0/0"
    },
}


def validate_hostname():
    output = device.parse("show running-config | include hostname")
    assert output['hostname'] == expected_config["hostname"], f"Hostname mismatch: {output['hostname']}"

def validate_enable_secret():
    output = device.parse("show running-config | include enable secret")
    assert output['enable secret'] == expected_config["security"]["enable_secret"], f"Enable secret mismatch: {output['enable secret']}"

def validate_interfaces():
    interfaces = device.parse("show interface")
    for iface, config in expected_config['interfaces'].items():
        assert iface in interfaces, f"interfaces {iface} not found"     
        assert interfaces[iface]["ip_address"] == config["ip_address"], f"{iface} IP address mismatch"
        assert interfaces[iface]["mask"] == config["mask"], f"{iface} mask mismatch"
        assert interfaces[iface]["status"] == config["status"], f"{iface} status mismatch"
        if 'duplex' in config:
            assert interfaces[iface]["duplex"] == config["duplex"], f"{iface} duplex mismatch"
        if 'speed' in config: 
            assert interfaces[iface]["speed"] == config["speed"], f"{iface} speed mismatch"   

def validate_routing(): 
    ospf = device.parse("show ip ospf")
    assert ospf['router_id'] == expected_config['routing']['ospf']['router_id'], "OSPF Router ID mismatch"
    for network in expected_config['routing']['ospf']['networks']:
        assert network in ospf['networks'], f"OSPF Network {network} not configured"

        rip = device.parse("show ip rip")
        for network in expected_config['routing']['rip']['networks']:
            assert network in rip['networks'], f"RIP Network {network} not configured"

def validate_dhcp_excluded_addresses():
    dhcp = device.parse("show running-config | include ip dhcp excluded-addresses")
    for addr in expected_config['dhcp']['excluded_addresses']:
        assert addr in dhcp, f"DHCP excluded addres {addr} not found"

def validate_dhcp_pools():
    dhcp = device.parse("show running-config | include ip dhcp pool")
    for pool, config in expected_config['dhcp']['pools'].items():
        assert f"ip dhcp pool {pool}" in dhcp, f"DHCP pool {pool} not found"
        assert f"network {config['network']}" in dhcp, f"DHCP pool {pool} network mismatch"
        assert f"default-router {config['default_router']}" in dhcp, f"DHCP pool {pool} default-router mismatch"

def validate_nat():
    output  = device.parse("show runing-config | include ip nat inside")
    assert "ip nat inside" in output, "NAT configuration missing"

def validate_ssh():
    output = device.parse("show ip ssh")
    assert output['ssh_version'] == '2', "SSH version mismatch"

def validate_banner():
    output = device.parse("show running-config | include banner")
    assert expected_config["banner"] in output, "Banner mismatch"

def validate_vty_lines():
    output = device.parse("show running-config | include line vty")
    assert f"password {expected_config['security']['line_vty']['password']}" in output, "VTY password mismatch"
    assert f"transport input {expected_config['security']['line_vty']['transport_input']}" in output, "VTY transport input mismatch"

if __name__ == "__main__":
    device.connect()
    try:
        validate_hostname()
        validate_enable_secret()
        validate_interfaces()
        validate_routing()
        validate_dhcp_excluded_addresses()
        validate_dhcp_pools()
        validate_nat()
        validate_ssh()
        validate_banner()
        validate_vty_lines()
        print("All validations passed!")
    except AssertionError as e:
        print(f"Validation failed: {e}")
    finally:
        device.disconnect()