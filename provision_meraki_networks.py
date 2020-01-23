import requests
import json
import random
import sys
import getopt
from pprint import pprint
import meraki_config as config
from time import sleep

# Configuration values
MERAKI_API_KEY = config.merakiapikey
MERAKI_ORG = config.org_name
MERAKI_URL = config.merakiurl
NETWORK_LAYOUTS = config.net_device_config
THIRD_PARTY_VPN = config.third_party_vpn
ORG_VPN_FIREWALL = config.org_vpn_firewall
MERAKI_SESSION = requests.Session()
SECURITY_POSTURE = config.security_posture


# Get all devices in the network, remove them, delete the network, recreate
# the network and add devices back in.
def create_org():
    try:
        pprint("Creating organization with name " + MERAKI_ORG)

        new_org = requests.post(
        "https://" + MERAKI_URL + "/organizations/", 
        json={
                    "name": MERAKI_ORG
                },
        headers={
                'X-Cisco-Meraki-API-Key': MERAKI_API_KEY,
                'Content-Type':'application/json'
            })

        new_org.raise_for_status()
        sleep(2)
        new_org = new_org.json()["id"]
        pprint("New Organization Created with id: " + new_org)

        # Add Devices
        create_networks(new_org)
        set_org_vpn_firewall(new_org)
        set_third_party_vpn(new_org)
        apply_security_posture(new_org)
    except Exception as e:
        pprint(e)

def set_third_party_vpn(new_org):
    try:
        pprint("Setting Third Party VPN Peers" + MERAKI_ORG)
        pprint(THIRD_PARTY_VPN)
        peer_set = requests.put(
        "https://" + MERAKI_URL + "/organizations/" + new_org + "/thirdPartyVPNPeers", 
        data=json.dumps(THIRD_PARTY_VPN),
        headers={
                'X-Cisco-Meraki-API-Key': MERAKI_API_KEY,
                'Content-Type':'application/json'
            })
        sleep(2)
        peer_set.raise_for_status()
        pprint("VPN Peer Set")
  

    except Exception as e:
        pprint(e)

def set_org_vpn_firewall(new_org):
    try:
        pprint("Setting Org VPN Firewall" + MERAKI_ORG)
        vpn_firewall = requests.put(
        "https://" + MERAKI_URL + "/organizations/" + new_org + "/vpnFirewallRules", 
        data=json.dumps(ORG_VPN_FIREWALL),
        headers={
                'X-Cisco-Meraki-API-Key': MERAKI_API_KEY,
                'Content-Type':'application/json'
            })
        sleep(2)
        vpn_firewall.raise_for_status()
        pprint("Org VPN Firewall Set")
  

    except Exception as e:
        pprint(e)

# Get all devices in the network, remove them, delete the network, recreate
# the network and add devices back in.
def create_networks(org):
    pprint("creating all networks")
    try:
        for network_layout in NETWORK_LAYOUTS:
            # Recreate the network
            network_name = network_layout["network"]
            pprint("Creating network with name " + network_name)

            new_network = requests.post(
            "https://" + MERAKI_URL + "/organizations/" + org + "/networks", 
            json = {
                        "name": network_name,
                        "type": "wireless switch appliance camera"
                    },
            headers={
                    'X-Cisco-Meraki-API-Key': MERAKI_API_KEY,
                    'Content-Type':'application/json'
                })
            sleep(2)
            new_network.raise_for_status()
            new_network = new_network.json()["id"]
            pprint("New Network Created with id: " + new_network)
            # Add Devices
            add_devices(new_network, network_layout["devices"])
            if "vlan_enabled" in network_layout.keys():
                enable_vlans(new_network,network_layout["vlan_enabled"])
            if "vlans" in network_layout.keys():
                create_vlans(new_network,network_layout["vlans"])
            # Set SD-WAN if present
            if "site-to-site" in network_layout.keys():
                if len(network_layout["site-to-site"]["hubs"]) > 0:
                    network_layout["site-to-site"]["hubs"] = find_hub_networks(org,network_layout["site-to-site"]["hubs"])
                    set_sd_wan(new_network, network_layout["site-to-site"])
                else:
                    set_sd_wan(new_network, network_layout["site-to-site"]) 
                    

            
    except Exception as e:
        pprint(e)


def set_sd_wan(network, site_to_site):
    pprint("SD WAN Settings for network " + network)
    try:
            set_sd_wan = requests.put(
            "https://" + MERAKI_URL + "/networks/" + network + "/siteToSiteVpn", 
            json = site_to_site,
            headers={
                    'X-Cisco-Meraki-API-Key': MERAKI_API_KEY,
                    'Content-Type':'application/json'
                })
            sleep(2)        
            set_sd_wan.raise_for_status()
            pprint("SD WAN SET for Network: " + network)
    except Exception as e:
        pprint(e)

def find_hub_networks(org,hubs):
    try:
        networks = getnetworklist(org)

        newhubs = []
        for hub in hubs:
            for network in networks:
                if network["name"] == hub["hubId"]:
                    hub["hubId"] = network["id"]
                    newhubs.append(hub)

        return newhubs   
    except Exception as e:
        pprint(e)


def add_devices(network, devices):
    # add devices from config
    pprint("add the devices for new network: " + network)
    try:
        for device in devices:
            pprint("add device: " + device["serial"])
            new_device = requests.post(
                "https://" + MERAKI_URL + \
                "/networks/" +network+"/devices/claim",
                json=device,
                headers={'X-Cisco-Meraki-API-Key': MERAKI_API_KEY,
                'Content-Type': "application/json"}
            )
            sleep(2)
            new_device.raise_for_status()

            pprint("Device Added for network " + network)
    except Exception as e:
       pprint(e)

def enable_vlans(network,vlan_enabled):
    pprint("Enable VLANS")
    try:
        vlans_enabled = requests.put(
            "https://" + MERAKI_URL + "/networks/" + network + "/vlansEnabledState",
            headers={
                "X-Cisco-Meraki-API-Key": MERAKI_API_KEY
            },
            json=vlan_enabled)
        sleep(2)
        vlans_enabled.raise_for_status()
        pprint("VLANS_ENABLED for network " + network)
        pprint(vlans_enabled)
    except Exception as e:
        pprint(e)

def create_vlans(network,vlans):
    pprint("Create VLANS")
    try:
        for vlan in vlans:
            create_vlans = requests.post(
                "https://" + MERAKI_URL + "/networks/" + network + "/vlans",
                headers={
                    "X-Cisco-Meraki-API-Key": MERAKI_API_KEY
                },
                json=vlan)
            sleep(2)
            create_vlans.raise_for_status()
            pprint("CREATE_VLANS for network " + network)
            pprint(create_vlans)
    except Exception as e:
        pprint(e)

def set_content_filtering(network):
    pprint("Set Content Filtering")
    try:
        set_content_filtering = requests.put(
            "https://" + MERAKI_URL + "/networks/" + network + "/contentFiltering",
            headers={
                "X-Cisco-Meraki-API-Key": MERAKI_API_KEY
            },
            json=SECURITY_POSTURE["content_filtering"])
        sleep(2)
        set_content_filtering.raise_for_status()
        pprint("set_content_filtering for network " + network)
        pprint(set_content_filtering)
    except Exception as e:
        pprint(e)

def set_group_policies(network):
    pprint("Set Group Policies")
    try:
        for policy in SECURITY_POSTURE["group_policies"]:
            set_group_policy = requests.post(
                "https://" + MERAKI_URL + "/networks/" + network + "/groupPolicies",
                headers={
                    "X-Cisco-Meraki-API-Key": MERAKI_API_KEY
                },
                json=policy)
            sleep(2)
            set_group_policy.raise_for_status()
            pprint("SET_GROUP_POLICY for network " + network)
    except Exception as e:
        pprint(e)

def getnetworklist(org):
    pprint("get networks")
    try:
        networks = requests.get(
            "https://" + MERAKI_URL + "/organizations/" + org +"/networks",
            headers={
                "X-Cisco-Meraki-API-Key": MERAKI_API_KEY
            })
        sleep(2)
        networks.raise_for_status()
        networks = networks.json()
        return networks
    except Exception as e:
        pprint(e)
        return ""
    
    return "No Networks Found"

def apply_security_posture(org):
    try:
        networks = getnetworklist(org)
        for network in networks:
            set_content_filtering(network["id"])
            set_group_policies(network["id"])
    except Exception as e:
        pprint(e)


if __name__ == "__main__":
    create_org()
   