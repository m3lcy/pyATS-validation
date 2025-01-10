from pyats.topology import loader
from genie.conf import Genie
from genie.utils.diff import Diff


testbed = loader.load('network_testbed.yml')
device = testbed.devices['DLS2']

expected_config = {
    "hostname": "DLS1",
    "vlan": {
        10: "CORE",
        20: "MGMT",
        30: "COMPUTE",
        99: "NATIVE",
        100: "R&D",
        200: "EMPLOYEE",
        300: "GUEST",
        999: "BLACKHOLE"
    },
    "interfaces": {
        "FastEthernet0/1": {
            "mode": "trunk",
            "native_vlan": 99,
            "encapsulation": "dot1q"
        },
        {f"FastEthernet0/{i}": {
            "mode": "trunk",
            "encapsulation": "dot1q",
        } for i in range(2,3)}
        }, 
        {f"FastEthernet0/{i}": {
            "mode": "trunk",
            "native_vlan": 99,
            "encapsulation": "dot1q",
        } for i in range(4,5)}
        },
        "GigabitEthernet0/1": {
            "ip_address": "172.16.12.230",
            "mask": "255.255.255.252",
            "status": "up"
        },
        "GigabitEthernet0/2": {
            "mode": "trunk",
            "native_vlan": 99,
            "encapsulation": "dot1q"
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
                "172.16.12.192 0.0.0.31 area 0"
            ]
        }
    }
}

def validate_hostname():
    output = device.parse("show running-config | include hostname")
    assert output['hostname'] == expected_config["hostname"], f"Hostname mismatch: {output['hostname']}"

def validate_vlans():
    vlans = device.parse("show vlan brief")
    for vlan_id, vlan_name in expected_config['vlan'].items():
        assert vlan_id in vlans['vlans'], f"VLAN {vlan_id} name not found"
        assert vlans['vlans'][vlan_id]['name'] == vlan_name, f"VLAN {vlan_id} name mismatch"

def validate_interfaces():
    interfaces = device.parse("show interface")
    for iface, config in expected_config['interfaces'].items():
        assert iface in interfaces, f"interfaces {iface} not found"
        for key, value in config.items():
            assert interfaces[iface].get(key) == value, f"{iface} {key} mismatch"

def validate_routing():
    ospf = device.parse("show ip ospf")
    assert ospf['router_id'] == expected_config['routing']['ospf']['router_id'], "OSPF Router ID mismatch"
    for network in expected_config['routing']['ospf']['networks']:
        assert network in ospf['networks'], f"OSPF Network {network} not configured"

if __name__ == "__main__":
    device.connect()
    try:
        validate_hostname()
        validate_vlans()
        validate_interfaces()
        validate_routing()
        print("All validations passed!")
    except AssertionError as e:
        print(f"Validation failed: {e}")
    finally:
        device.disconnect()