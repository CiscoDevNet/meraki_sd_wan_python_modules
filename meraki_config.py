merakiapikey = "<api-key>"
merakiurl = "api.meraki.com/api/v0"
org_name = "Demo SD-WAN ORG"
net_device_config = [
  {
    "network": "SDAUTO1",
    "devices":  [
                  {"serial": "QBSA-9QAN-KB6Y"},
                  {"serial": "QBSB-XM3X-3MFZ"},
                  {"serial": "QBSC-HJPX-H7TJ"},
                  {"serial": "QBSD-X64Q-QEKU"}
                ],
    "site-to-site": {
                        "mode": "hub",
                        "hubs": [],
                        "subnets": [
                            {
                                "localSubnet": "192.168.128.0/24",
                                "useVpn": True
                            }
                        ]
    },
    "vlan_enabled": {
      "enabled": True
    },
    "vlans" : [
        {
          "id": 2,
          "name": "VLAN2",
          "applianceIp": "192.168.2.1",
          "subnet": "192.168.2.0/24",
          "fixedIpAssignments": {},
          "reservedIpRanges": [],
          "dnsNameservers": "upstream_dns",
          "dhcpHandling": "Run a DHCP server",
          "dhcpLeaseTime": "1 day",
          "dhcpBootOptionsEnabled": False,
          "dhcpOptions": []
      },
      {
          "id": 3,
          "name": "VLAN3",
          "applianceIp": "192.168.3.1",
          "subnet": "192.168.3.0/24",
          "fixedIpAssignments": {},
          "reservedIpRanges": [],
          "dnsNameservers": "upstream_dns",
          "dhcpHandling": "Run a DHCP server",
          "dhcpLeaseTime": "1 day",
          "dhcpBootOptionsEnabled": False,
          "dhcpOptions": []
      }
    ]
  },
  {
    "network": "SDAUTO2",
    "devices":  [
                  {"serial": "QBSA-9HBY-KRTW"},
                  {"serial": "QBSB-NWM5-CYNF"},
                  {"serial": "QBSC-XBTM-Z7VB"},
                  {"serial": "QBSD-7538-FYZK"}
                ],
    "site-to-site": {
                        "mode": "spoke",
                        "hubs": [
                            {
                                "hubId": "SDAUTO1",
                                "useDefaultRoute": True
                            }
                        ],
                        "subnets": [
                            {
                                "localSubnet": "192.168.128.0/24",
                                "useVpn": True
                            }
                        ]
    }
  },
  {
    "network":"SDAUTO3",
    "devices":  [
                  {"serial": "QBSA-J3ZY-2NDD"},
                  {"serial": "QBSB-68XK-8WDV"},
                  {"serial": "QBSC-AQ53-TGYH"},
                  {"serial": "QBSD-GJXD-5ULW"}
                ],
    "site-to-site": {
                    "mode": "spoke",
                    "hubs": [
                        {
                            "hubId": "SDAUTO1",
                            "useDefaultRoute": True
                        }
                    ],
                    "subnets": [
                        {
                            "localSubnet": "192.168.128.0/24",
                            "useVpn": True
                        }
                    ]
    }
  },
  {
    "network":"ENAUTO4",
    "devices":  [
                  {"serial": "QBSA-V7KY-V3A9"},
                  {"serial": "QBSB-TYB6-P4A9"},
                  {"serial": "QBSC-F9BM-KA5V"},
                  {"serial": "QBSD-GDWV-E8EQ"}
                ]
  }
]

org_vpn_firewall = {"rules":
  [
      {
        "comment":"Allow TCP traffic to subnet with HTTP servers.",
        "policy":"allow",
        "protocol":"tcp",
        "destPort":443,
        "destCidr":"192.168.1.0/24",
        "srcPort":"Any",
        "srcCidr":"Any",
        "syslogEnabled":False
      }
    ]
  }

third_party_vpn = {"peers":
  [
    {
      "name":"My peer 1",
      "publicIp":"123.123.123.1",
      "privateSubnets":[
          "192.168.1.0/24",
          "192.168.128.0/24"
        ],
        "secret":"asdf1234",
        "ipsecPolicies":{
            "ikeCipherAlgo":["tripledes"],
            "ikeAuthAlgo":["sha1"],
            "ikeDiffieHellmanGroup":["group2"],
            "ikeLifetime":28800,
            "childCipherAlgo":["aes128"],
            "childAuthAlgo":["sha1"],
            "childPfsGroup":["disabled"],
            "childLifetime":28800
          }
      },
      {
        "name":"My peer 2",
        "publicIp":"123.123.123.2",
        "remoteId":"miles@meraki.com",
        "privateSubnets":[
          "192.168.2.0/24",
          "192.168.129.0/24"
        ],
        "secret":"asdf56785678567856785678",
        "ipsecPoliciesPreset":"default"
      }
    ]
  }

security_posture = {
  "content_filtering" : {
    "allowedUrlPatterns": [
      "http://www.example.org",
      "http://help.com.au"
    ],
    "blockedUrlPatterns": [
      "http://www.example.com",
      "http://www.betting.com"
    ],
    "blockedUrlCategories": [
      "meraki:contentFiltering/category/1"
    ],
    "urlCategoryListSize": "topSites"
  },
  "malware_settings":{
    "mode": "enabled",
    "allowedUrls": [
      {
        "url": "example.org",
        "comment": "allow example.org"
      },
      {
        "url": "help.com.au",
        "comment": "allow help.com.au"
      }
    ],
    "allowedFiles": [
      {
        "sha256": "e82c5f7d75004727e1f3b94426b9a11c8bc4c312a9170ac9a73abace40aef503",
        "comment": "allow ZIP file"
      }
    ]
  },
  "fire_walled_services":{
      "service": "ICMP",
      "access": "restricted",
      "allowedIps": [
          "123.123.123.1"
      ]
  },
  "l7_firewall_rules":{
      "rules": [
          {
              "policy": "deny",
              "type": "application",
              "value": {
                  "id": "meraki:layer7/application/67",
                  "name": "Xbox LIVE"
              }
          },
          {
              "policy": "deny",
              "type": "applicationCategory",
              "value": {
                  "id": "meraki:layer7/category/2",
                  "name": "Blogging"
              }
          },
          {
              "policy": "deny",
              "type": "host",
              "value": "google.com"
          },
          {
              "policy": "deny",
              "type": "port",
              "value": "23"
          },
          {
              "policy": "deny",
              "type": "ipRange",
              "value": "10.11.12.00/24"
          },
          {
              "policy": "deny",
              "type": "ipRange",
              "value": "10.11.12.00/24:5555"
          },
          {
              "policy": "deny",
              "type": "blacklistedCountries",
              "value": [
                  "AX",
                  "CA"
              ]
          },
          {
              "policy": "deny",
              "type": "whitelistedCountries",
              "value": [
                  "US"
              ]
          }
      ]
  },
  "l3_firewall_rules":{
    "rules": [
      {
        "comment": "Allow TCP traffic to subnet with HTTP servers.",
        "policy": "allow",
        "protocol": "tcp",
        "destPort": 443,
        "destCidr": "192.168.1.0/24",
        "srcPort": "Any",
        "srcCidr": "Any",
        "syslogEnabled": False
      }
    ]
  },
  "group_policies":[
    {
      "name": "No video streaming",
      "scheduling": {
        "enabled": True,
        "monday": {
          "active": True,
          "from": "9:00",
          "to": "17:00"
        },
        "tuesday": {
          "active": True,
          "from": "9:00",
          "to": "17:00"
        },
        "wednesday": {
          "active": True,
          "from": "9:00",
          "to": "17:00"
        },
        "thursday": {
          "active": True,
          "from": "9:00",
          "to": "17:00"
        },
        "friday": {
          "active": True,
          "from": "9:00",
          "to": "17:00"
        },
        "saturday": {
          "active": False,
          "from": "0:00",
          "to": "24:00"
        },
        "sunday": {
          "active": False,
          "from": "0:00",
          "to": "24:00"
        }
      },
      "bandwidth": {
        "settings": "custom",
        "bandwidthLimits": {
          "limitUp": 1000000,
          "limitDown": 1000000
        }
      },
      "firewallAndTrafficShaping": {
        "settings": "custom",
        "trafficShapingRules": [
          {
            "definitions": [
              {
                "type": "host",
                "value": "google.com"
              },
              {
                "type": "port",
                "value": "9090"
              },
              {
                "type": "ipRange",
                "value": "192.1.0.0"
              },
              {
                "type": "ipRange",
                "value": "192.1.0.0/16"
              },
              {
                "type": "ipRange",
                "value": "10.1.0.0/16:80"
              },
              {
                "type": "localNet",
                "value": "192.168.0.0/16"
              },
              {
                "type": "applicationCategory",
                "value": {
                  "id": "meraki:layer7/category/2",
                  "name": "Blogging"
                }
              },
              {
                "type": "application",
                "value": {
                  "id": "meraki:layer7/application/133",
                  "name": "Battle.net"
                }
              }
            ],
            "perClientBandwidthLimits": {
              "settings": "custom",
              "bandwidthLimits": {
                "limitUp": 1000000,
                "limitDown": 1000000
              }
            },
            "dscpTagValue": None,
            "pcpTagValue": None
          }
        ],
        "l3FirewallRules": [
          {
            "comment": "Allow TCP traffic to subnet with HTTP servers.",
            "policy": "allow",
            "protocol": "tcp",
            "destPort": 443,
            "destCidr": "192.168.1.0/24"
          }
        ],
        "l7FirewallRules": [
            {
              "policy": "deny",
              "type": "application",
              "value": {
                "id": "meraki:layer7/application/67",
                "name": "Xbox LIVE"
              }
            },
            {
              "policy": "deny",
              "type": "applicationCategory",
              "value": {
                "id": "meraki:layer7/category/2",
                "name": "Blogging"
              }
            },
            {
              "policy": "deny",
              "type": "host",
              "value": "google.com"
            },
            {
              "policy": "deny",
              "type": "port",
              "value": "23"
            },
            {
              "policy": "deny",
              "type": "ipRange",
              "value": "10.11.12.00/24"
            },
            {
              "policy": "deny",
              "type": "ipRange",
              "value": "10.11.12.00/24:5555"
            }
          ]
      },
      "splashAuthSettings": "bypass",
      "vlanTagging": {
        "settings": "custom",
        "vlanId": "1"
      },
      "bonjourForwarding": {
        "settings": "custom",
        "rules": [
          {
            "description": "A simple bonjour rule",
            "vlanId": "1",
            "services": [
              "All Services"
            ]
          }
        ]
      }
    }
  ],
  "switch_ports":{
    "name": "My switch port",
    "tags": "tag1 tag2",
    "enabled": False
  }
}
