from pyats.topology import loader
from genie.conf import Genie
from genie.utils.diff import Diff

testbed = loader.load('network_testbed.yml')
device = testbed.devices['l3-sw-02']

expected_config = {
    "hostname": "l3-sw-02",
    "password": "cisco",
    "username": "admin",
    "banner": "Authorized Access Only!!!",
    "vlan": {
        10: "CORE",
        20: "MGMT",
        30: "COMPUTE",
        99: "NATIVE",
        100: "R&D",
        200: "EMPLOYEE",
        300: "GUEST",
        999: "BLACKHOLE",
    },
    "interfaces": {
        "FastEthernet0/1": {
            "mode": "trunk",
            "native_vlan": 99,
            "encapsulation": "dot1q",
        },
        **{
            f"FastEthernet0/{i}": {
                "mode": "trunk",
                "encapsulation": "dot1q",
            } for i in range(2, 3)
        },
        **{
            f"FastEthernet0/{i}": {
                "mode": "trunk",
                "native_vlan": 99,
                "encapsulation": "dot1q",
            } for i in range(4, 5)
        },
        "GigabitEthernet0/1": {
            "ip_address": "172.16.12.230",
            "mask": "255.255.255.252",
            "status": "up",
        },
        "GigabitEthernet0/2": {
            "mode": "trunk",
            "native_vlan": 99,
            "encapsulation": "dot1q",
        },
    },
    "routing": {
        "ospf": {
            "router_id": "1.1.1.1",
            "networks": [
                "172.16.12.0 0.0.0.31 area 0",
                "172.16.12.32 0.0.0.31 area 0",
                "172.16.12.64 0.0.0.31 area 0",
                "172.16.12.96 0.0.0.31 area 0",
                "172.16.12.224 0.0.0.31 area 0",
                "172.16.12.128 0.0.0.31 area 0",
                "172.16.12.160 0.0.0.31 area 0",
                "172.16.12.192 0.0.0.31 area 0",
            ],
        },
        "rip": {
            "version": 2,
            "networks": [
                "172.16.0.0",
            ],
        },
    },
    "security": {
        "enable_secret": "cisco",
        "line_vty": {
            "password": "cisco123",
            "login_local": True,
            "transport_input": "ssh",
        },
        "ssh_key": {
            "modulus": "1024",
            "label": "ssh-key",
        },
    },
}

def validate_hostname():
    output = device.parse("show running-config | include hostname")
    assert output['hostname'] == expected_config["hostname"], f"Hostname mismatch: {output['hostname']}"

def validate_enable_secret():
    output = device.parse("show running-config | include enable secret")
    assert output['enable secret'] == expected_config["security"]["enable_secret"], f"Enable secret mismatch: {output['enable secret']}"

def validate_vlans():
    vlans = device.parse("show vlan brief")
    for vlan_id, vlan_name in expected_config['vlan'].items():
        assert vlan_id in vlans['vlans'], f"VLAN {vlan_id} name not found"
        assert vlans['vlans'][vlan_id]['name'] == vlan_name, f"VLAN {vlan_id} name mismatch"

def validate_interfaces():
    interfaces = device.parse("show interface")
    for iface, config in expected_config['interfaces'].items():
        assert iface in interfaces, f"Interface {iface} not found"
        for key, value in config.items():
            assert interfaces[iface].get(key) == value, f"{iface} {key} mismatch"

def validate_routing():
    ospf = device.parse("show ip ospf")
    assert ospf['router_id'] == expected_config['routing']['ospf']['router_id'], "OSPF Router ID mismatch"
    for network in expected_config['routing']['ospf']['networks']:
        assert network in ospf['networks'], f"OSPF Network {network} not configured"

    rip = device.parse("show ip rip")
    for network in expected_config['routing']['rip']['networks']:
        assert network in rip['networks'], f"RIP Network {network} not configured"

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
        validate_vlans()
        validate_interfaces()
        validate_routing()
        validate_ssh()
        validate_banner()
        validate_vty_lines()
        print("All validations passed!")
    except AssertionError as e:
        print(f"Validation failed: {e}")
    finally:
        device.disconnect()