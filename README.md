# IoT Lab Generator

A lightweight "Infrastructure as Code" (IaC) tool to deploy realistic, virtualized IoT environments on a single Linux host. 

It spins up lightweight QEMU/Alpine VMs that mimic real-world devices (Medical, Industrial, Home, Office), generating authentic network traffic (SIP, MQTT, CoAP, HTTPS, etc.) and identifying themselves via specific DHCP fingerprints (OUI, VCI/Option 60).

## Key Features

* Dynamic Device Personas: Define devices in a simple 'iot.json' file.
* Realistic Traffic Generation: Agents generate live traffic for HTTP/S, DNS, SIP, MQTT, CoAP, SNMP, NTP, and Zigbee (tunneling).
* DHCP Fingerprinting: Real Vendor Class Identifiers (VCI) and OUIs, perfect for testing Device Identification features in Palo Alto Firewalls.
* Syslog Integration: Relays DHCP logs to the DHCP Server log ingestor in the Palo Alto Firewall for Device Mapping.
* Lightweight: Uses Alpine Linux + QEMU (256MB RAM and 1 vCPU per device). 

## Prerequisites

* OS: Ubuntu 20.04/22.04 LTS or Debian 11/12 (Script uses 'apt-get').
* Hardware: CPU with Virtualization support.
* Privileges: Root access (via 'sudo').

### Infrastructure 

![Infra](diag.svg)

*Note: Tested on Ubuntu 22.04 running inside an AWS EC2 instance (c7g.xlarge) with 3 Qemu VMs.*

## Installation

1.  Clone the Repository:

``` sh    
git clone <url>
```

2.  Make the script executable:

``` sh   
cd iot-lab
chmod +x setup.sh
```

## Usage

Run the setup script with 'sudo'. The script will automatically install dependencies (QEMU, KVM, Bridge-Utils, Kea, Python) on the first run.

### Syntax

``` sh
sudo ./setup.sh -s <subnet> -n <count> [-j <json_file>] [-f <firewall_ip>] [-c <cert_path>]
```

### Arguments

``` sh
-s : IoT Lab Subnet CIDR (e.g., 192.168.10.0/24)       [Required]
-n : Total number of VMs to deploy.                    [Required]
-j : Path to JSON device definition file.              [Required]
-f : PA Firewall Management IP to send Syslogs.        [Optional]
-c : Path to Root CA cert (if decryption is enabled).  [Optional]
```

*Note: If -n is higher than the number of devices in 'iot.json', the script will cycle through the list, reusing Personas but generating random unique MAC addresses for the extras.*

## Device Definition

The lab is driven by the 'iot.json' file. This file defines the "Persona" of every device.

### Example Object

``` json
{
    "name": "Nest_Thermostat",
    "mac": "18:B4:30:DD:EE:16",
    "vci": "Nest/Thermostat/Gen3",
    "ttl": 64,
    "cadence": 60,
    "protocols": ["HTTPS", "DNS"],
    "user_agent": "Nest/5.6.3",
    "targets": {
        "DNS": ["home.nest.com", "time.google.com"],
        "HTTPS": ["home.nest.com"]
    }
}
```

### Fields

* mac: The specific MAC address (determines OUI).
* vci: DHCP Option 60 string (Vendor Class Identifier).
* cadence: How often (in seconds) the device generates traffic.
* protocols: List of protocols to simulate.
* targets: Dictionary of destinations (Hostnames or IPs) for each protocol.

#### Protocols Available:

* DNS
* SIP
* SNMP
* HTTP
* HTTPS
* MQTT
* CoAP
* Zigbee

### Example Command

Deploy 10 devices on 192.168.50.0/24 using the default iot.json:

``` sh
sudo ./setup.sh -s 192.168.50.0/24 -n 10 -f 192.168.30.1 -j iot.json
```

## Managing the Lab

Once deployed, a helper script is generated at '/usr/local/bin/iot_lab'. Use this to control the environment.

```sh
Usage: iot_lab <command> [option]

Commands:

  start         Start the lab environment.
  stop          Stop all VMs and services.
  restart       Restart the environment.
  status        Show status of VMs, Network, and DHCP.
  connect <ID>  Connect to VM Console (e.g., iot_lab connect 01).
  clean         DESTROY the lab (Delete data and configurations).
  help          Shows this help message.
```

## Directory Structure

After installation, the environment is located at '~/iot-lab/':

``` sh
  ~/iot-lab/
  |-- certs/                    # Stored Root CA certificates
  |-- src/                      # Source code for agents
  |   |-- dhcp_processor.py     # Syslog message generator
  |   |-- vm_agent.py           # VM Injected traffic script
  |   |-- vm_deps.sh            # VM dependency installation script
  |-- vms/                      # VM Disk Images (one per device)
  |-- logs/                     # Serial logs for debugging VMs
```

## Notes

Before running this script, ensure your host machine is correctly sized. Each simulated IoT device requires **1 vCPU** and **256MB of RAM**.

> * **10 Devices:** ~2.5 GB RAM / 10 vCPUs (shared)
> * **20 Devices:** ~5.0 GB RAM / 20 vCPUs (shared)

Creating more devices than your host can handle may lead to system instability, freezing, or OOM (Out of Memory) kills.

## License

MIT
