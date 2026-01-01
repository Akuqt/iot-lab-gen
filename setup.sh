#!/bin/bash

# IoT Lab Setup
# Italo Alfaro - 2026
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Default Values
SUBNET=""
COUNT=0
CERT_PATH=""
FIREWALL_IP=""
BASE_DIR="$(pwd)"
CONFIG_FILE="iot.json"

# 2. ARGUMENT PARSING
while getopts "s:n:f:c:j:" opt; do
  case $opt in
    s) SUBNET="$OPTARG" ;;
    n) COUNT="$OPTARG" ;;
    f) FIREWALL_IP="$OPTARG" ;;
    c) CERT_PATH="$OPTARG" ;;
    j) CONFIG_FILE="$OPTARG" ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

if [ -z "$SUBNET" ] || [ "$COUNT" -eq 0 ]; then
    echo "Usage: sudo $0 -s <subnet_cidr> -n <num_devices> -j <iot.json> [-c <root_ca_path>]"
    echo ""
    echo "  -s : IoT Lab Subnet CIDR (e.g., 192.168.10.0/24)       [Required]"
    echo "  -n : Total number of VMs to deploy.                    [Required]"
    echo "  -j : Path to device definition JSON file.              [Required]"
    echo "  -f : PA Firewall Management IP to send Syslogs.        [Optional]"
    echo "  -c : Path to Root CA cert (if decryption is enabled).  [Optional]"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then echo "Please run as root (sudo)"; exit 1; fi

# Network Calculations
NET_IP=$(echo $SUBNET | cut -d'/' -f1)
PREFIX=$(echo $NET_IP | cut -d'.' -f1-3)
GATEWAY_IP="${PREFIX}.1"
DHCP_START="${PREFIX}.100"
DHCP_END="${PREFIX}.200"
if [ -z "$FIREWALL_IP" ]; then FIREWALL_IP=$GATEWAY_IP; fi

echo "========================================"
echo "      IoT Lab Deployment Started        "
echo "========================================"

# 3. INSTALL DEPENDENCIES
echo ""
echo "[1/8] Installing Dependencies..."
apt-get update
apt-get install -y qemu-system-arm qemu-utils bridge-utils kea-dhcp4-server \
    python3-pip libguestfs-tools qemu-efi-aarch64 python3-scapy net-tools virtinst \
    tmux jq socat

# 4. PREPARE ENVIRONMENT
echo ""
echo "[2/8] Preparing Directory Structure..."
mkdir -v -p "$BASE_DIR"/{certs,src,vms,logs}
mkdir -v -p /var/lib/kea
touch /var/lib/kea/kea-leases4.csv
touch "$BASE_DIR/logs/iot_traffic.log"
chown -R _kea:_kea /var/lib/kea
chmod 755 /var/lib/kea

if [ ! -z "$CERT_PATH" ] && [ -f "$CERT_PATH" ]; then
    cp -v "$CERT_PATH" "$BASE_DIR/certs/pan-root-ca.crt"
fi
cd "$BASE_DIR"

# 5. PARSE JSON & BUILD MAPS
echo ""
echo "[3/8] Processing Device Profiles..."
if [ ! -f "$CONFIG_FILE" ]; then echo "[!] JSON missing at $CONFIG_FILE"; exit 1; fi

JSON_LEN=$(jq '. | length' "$CONFIG_FILE")
if [ "$JSON_LEN" -eq 0 ]; then echo "[!] JSON empty"; exit 1; fi

declare -a FINAL_MACS
declare -a FINAL_NAMES
PYTHON_MAP_STR="{"

echo "[*] Generating $COUNT device configurations..."
for i in $(seq 0 $((COUNT-1))); do
    TEMPLATE_IDX=$(( i % JSON_LEN ))
    RAW_JSON=$(jq ".[$TEMPLATE_IDX]" "$CONFIG_FILE")
    NAME=$(echo "$RAW_JSON" | jq -r '.name')
    VCI=$(echo "$RAW_JSON" | jq -r '.vci')
    JSON_MAC=$(echo "$RAW_JSON" | jq -r '.mac')

    if [ "$i" -lt "$JSON_LEN" ]; then
        MAC="$JSON_MAC"
    else
        MAC=$(printf "52:54:00:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
        NAME="${NAME}_${i}"
    fi

    FINAL_MACS+=("$MAC")
    FINAL_NAMES+=("$NAME")
    PYTHON_MAP_STR+="\"$MAC\": {\"name\": \"$NAME\", \"vci\": \"$VCI\"},"
    echo "    - Dev $((i+1)): $NAME [$MAC]"
done
PYTHON_MAP_STR="${PYTHON_MAP_STR%,}}"
PYTHON_MAP_STR+="}"

# 6. GENERATE PYTHON AGENTS
echo ""
echo "[4/8] Writing Agent Scripts..."

# --- Syslog Processor ---
# Fix: Sanitize map string to prevent SyntaxError
if [[ "${PYTHON_MAP_STR: -3}" == "}}}" ]]; then
    PYTHON_MAP_STR="${PYTHON_MAP_STR%?}"
fi

cat << EOF > src/dhcp_processor.py
#!/usr/bin/env python3
import time, os, socket, random, sys
from datetime import datetime

KEA_LEASE_FILE = '/var/lib/kea/kea-leases4.csv'
FW_SYSLOG_HOST = os.getenv('FW_SYSLOG_HOST', '$GATEWAY_IP') 
FW_SYSLOG_PORT = 10514
HOSTNAME = "ib-appliance-01.lab.local"
LOCAL_LOG = "logs/iot_traffic.log"

# 1. Load the raw map from Bash
RAW_MAP = $PYTHON_MAP_STR

# 2. Normalize Keys to Lowercase
PERSONA_MAP = {k.lower(): v for k, v in RAW_MAP.items()}

def send_syslog(ip, mac, data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ts = datetime.now().strftime('%b %d %H:%M:%S')
    pid = random.randint(1000, 9999)
    
    p_name = data.get('name', 'Unknown')
    p_vci = data.get('vci', 'Unknown')
    
    msg = f"dhcpd[{pid}]: DHCPACK on {ip} to {mac} ({p_name}) via eth1 relay option-60:\"{p_vci}\" option-61:\"{mac}\""
    pkt = f"<134>{ts} {HOSTNAME} {msg}"
    
    # 1. Send to Firewall
    try: 
        sock.sendto(pkt.encode(), (FW_SYSLOG_HOST, FW_SYSLOG_PORT))
        print(f"[+] Sent: {msg}")
        sys.stdout.flush()
    except Exception as e:
        print(f"[-] Socket Error: {e}")

    # 2. Log locally
    try:
        with open(LOCAL_LOG, "a") as f:
            f.write(f"{datetime.now()} [SYSLOG] Target: {FW_SYSLOG_HOST} | Payload: {msg}\n")
    except: pass

def monitor():
    print(f"[*] Monitoring Leases file: {KEA_LEASE_FILE}")
    print(f"[*] Target Syslog: {FW_SYSLOG_HOST}:{FW_SYSLOG_PORT}")
    
    if not os.path.exists(KEA_LEASE_FILE): 
        open(KEA_LEASE_FILE, 'a').close()
        
    f = open(KEA_LEASE_FILE, 'r')
    f.seek(0, 2) 
    
    while True:
        line = f.readline()
        if not line: 
            time.sleep(0.5)
            continue
            
        try:
            parts = line.strip().split(',')
            if len(parts) > 2:
                ip = parts[0]
                mac = parts[1].lower()
                
                if mac in PERSONA_MAP: 
                    send_syslog(ip, mac, PERSONA_MAP[mac])
        except Exception as e:
            print(f"[-] Parse Error: {e}")

if __name__ == "__main__": 
    monitor()
EOF

# --- Traffic Generator ---
cat << 'EOF' > src/vm_agent.py
#!/usr/bin/env python3
import socket, time, random, requests, json, sys, ssl
CONFIG_PATH = "/etc/persona_profile.json"

try:
    with open(CONFIG_PATH, 'r') as f: CONFIG = json.load(f)
except Exception as e:
    print(f"Error loading config: {e}")
    sys.exit(1)

def resolve_or_raw(target):
    try: return socket.gethostbyname(target)
    except: return target

def get_target_ip(proto):
    targets = CONFIG.get('targets', {}).get(proto, [])
    if not targets: return None
    return resolve_or_raw(random.choice(targets))

def send_udp(ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, CONFIG.get('ttl', 64))
        s.sendto(payload, (ip, port))
        s.close()
    except: pass

def send_tcp(ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(payload)
        s.close()
    except: pass

def run_traffic():
    protos = CONFIG.get('protocols', [])
    ua = CONFIG.get('user_agent', 'Python-IoT-Agent')
    
    while True:
        try:
            if "DNS" in protos:
                dns_targets = CONFIG.get('targets', {}).get('DNS', [])
                for fqdn in dns_targets:
                    try: socket.gethostbyname(fqdn)
                    except: pass

            if "NTP" in protos:
                 t_ip = get_target_ip("NTP")
                 if t_ip:
                     payload = b'\x1b' + 47 * b'\0'
                     send_udp(t_ip, 123, payload)

            if "SIP" in protos:
                t_host = random.choice(CONFIG['targets'].get('SIP', []))
                t_ip = resolve_or_raw(t_host)
                payload = f"REGISTER sip:{t_host} SIP/2.0\r\nVia: SIP/2.0/UDP {t_host}:5060\r\nFrom: <sip:iot@{t_host}>\r\n\r\n".encode()
                send_udp(t_ip, 5060, payload)

            if "SNMP" in protos:
                t_ip = get_target_ip("SNMP")
                if t_ip:
                    payload = b'\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
                    send_udp(t_ip, 161, payload)

            if "HTTP" in protos:
                t_host = random.choice(CONFIG['targets'].get('HTTP', []))
                try: requests.get(f"http://{t_host}", headers={'User-Agent': ua}, timeout=2)
                except: pass
            
            if "HTTPS" in protos:
                t_host = random.choice(CONFIG['targets'].get('HTTPS', []))
                try: requests.get(f"https://{t_host}", headers={'User-Agent': ua}, timeout=2, verify=False)
                except: pass

            if "MQTT" in protos:
                t_ip = get_target_ip("MQTT")
                if t_ip:
                    payload = b'\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00'
                    send_tcp(t_ip, 1883, payload)

            if "CoAP" in protos:
                t_ip = get_target_ip("CoAP")
                if t_ip:
                    payload = b'\x40\x01' + random.randbytes(2)
                    send_udp(t_ip, 5683, payload)

            if "Zigbee" in protos:
                 t_ip = get_target_ip("Zigbee")
                 if t_ip:
                     send_udp(t_ip, 9999, b'ZIGBEE_ENCAP_DATA_FRAME')

        except Exception as e:
            pass 
            
        time.sleep(CONFIG.get('cadence', 10) + random.uniform(0.5, 3.0))

if __name__ == "__main__":
    time.sleep(random.uniform(5, 20))
    run_traffic()
EOF

# --- VM Deps Script ---
cat << 'EOF' > src/vm_deps.sh
#!/bin/sh
apk update && apk add python3 py3-pip py3-requests
rm /etc/local.d/vm_deps.start
cat << 'SERVICE' > /etc/init.d/vm_agent
#!/sbin/openrc-run
command="/usr/bin/python3"
command_args="/usr/local/bin/vm_agent.py"
command_background="true"
pidfile="/run/vm_agent.pid"
name="vm_agent"
depend() { need net; }
SERVICE
chmod +x /etc/init.d/vm_agent
rc-service vm_agent start
rc-update add vm_agent default
EOF

# 7. BUILD VMS
echo ""
echo "[5/8] Building VM Images..."
SEARCH_URL="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud/"
FILENAME=$(wget -O- "$SEARCH_URL" | grep -o 'nocloud_alpine-[0-9.]\+-aarch64-uefi-cloudinit-r[0-9]\+\.qcow2' | sort -V | tail -n 1)

# Fix: Download base image to vms/ directory
if [ ! -f "vms/alpine-base.qcow2" ]; then 
    echo "[*] Downloading Alpine Base Image to ./vms/..."
    wget -O "vms/alpine-base.qcow2" "${SEARCH_URL}${FILENAME}"
fi

ROOT_PASS="password"
CERT_CMD=""
if [ -f "certs/pan-root-ca.crt" ]; then
    CERT_CMD="--upload certs/pan-root-ca.crt:/usr/local/share/ca-certificates/pan-root-ca.crt --run-command update-ca-certificates"
fi

for i in $(seq 0 $((COUNT-1))); do
    IDX=$(printf "%02d" $((i+1)))
    IMG_NAME="vms/iot-device-${IDX}.qcow2"
    CURr_NAME="${FINAL_NAMES[$i]}"
    TEMPLATE_IDX=$(( i % JSON_LEN ))
    
    jq ".[$TEMPLATE_IDX]" "$CONFIG_FILE" > persona_temp.json

    echo "[*] Customizing VM ${IDX}: $CURr_NAME..."
    rm -f "$IMG_NAME"
    # Fix: Reference base image in local vms/ dir
    qemu-img create -f qcow2 -b "alpine-base.qcow2" -F qcow2 "$IMG_NAME" 1G
    
    virt-customize -a "$IMG_NAME" --hostname "$CURr_NAME" --root-password password:$ROOT_PASS \
        --run-command "mkdir -p /etc/cloud && touch /etc/cloud/cloud-init.disabled" \
        --upload src/vm_deps.sh:/etc/local.d/vm_deps.start --chmod 0755:/etc/local.d/vm_deps.start \
        --upload src/vm_agent.py:/usr/local/bin/vm_agent.py --chmod 0755:/usr/local/bin/vm_agent.py \
        --upload persona_temp.json:/etc/persona_profile.json $CERT_CMD \
        --run-command "rc-update add local default" \
        --run-command "mkdir -p /etc/network/interfaces.d" \
        --run-command "echo 'include /etc/network/interfaces.d/*.conf' >> /etc/network/interfaces" \
        --write /etc/network/interfaces.d/eth0:"auto eth0\niface eth0 inet dhcp\n"
    
    rm persona_temp.json
done

# 8. CONFIGURE SERVICES & LAUNCHERS
echo ""
echo "[6/8] Configuring Launcher Scripts..."
MAC_LIST_STR="${FINAL_MACS[*]}"

# --- Network Script ---
cat << EOF > /usr/local/bin/iot-lab-network
#!/bin/bash
modprobe tun 2>/dev/null || true
modprobe virtio_net 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1

# Ensure bridge exists
if ! ip link show br-iot >/dev/null 2>&1; then
    ip link add name br-iot type bridge
    ip addr add $GATEWAY_IP/24 dev br-iot
fi

# Force UP state 
ip link set br-iot up
sleep 5

# Taps
for i in \$(seq -w 01 $COUNT); do
    if ! ip link show tap-iot\$i >/dev/null 2>&1; then
        ip tuntap add dev tap-iot\$i mode tap
        ip link set tap-iot\$i master br-iot
        ip link set tap-iot\$i up
    fi
done
exit 0
EOF
chmod +x /usr/local/bin/iot-lab-network

# --- VM Launcher ---
cat << EOF > /usr/local/bin/iot-lab-launch
#!/bin/bash
cd $BASE_DIR
EFI="/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
MACS=($MAC_LIST_STR)
for i in \$(seq 0 \$(( $COUNT - 1 ))); do
    IDX=\$(printf "%02d" \$((i+1)))
    echo "Booting VM \$IDX with MAC \${MACS[\$i]}..."
    
    nice -n 19 qemu-system-aarch64 -name "iot-\$IDX" -machine virt -cpu cortex-a57 -smp 1 -m 256M \\
        -bios \$EFI -drive if=none,file="vms/iot-device-\${IDX}.qcow2",id=hd0,format=qcow2 \\
        -device virtio-blk-device,drive=hd0 -netdev tap,id=net0,ifname="tap-iot\${IDX}",script=no,downscript=no \\
        -device virtio-net-device,netdev=net0,mac=\${MACS[\$i]} -device virtio-rng-pci \\
        -display none -daemonize \\
        -chardev socket,id=char0,path=logs/vm_\${IDX}.sock,server=on,wait=off,logfile=logs/vm_\${IDX}.log \\
        -serial chardev:char0 \\
        -D logs/qemu_debug_\${IDX}.log
done
EOF
chmod +x /usr/local/bin/iot-lab-launch

# C. Kea Configuration
cat << EOF > /etc/kea/kea-dhcp4.conf
{
"Dhcp4": {
    "interfaces-config": { "interfaces": ["br-iot"] },
    "control-socket": { "socket-type": "unix", "socket-name": "/tmp/kea4-ctrl-socket" },
    "lease-database": { "type": "memfile", "persist": true, "name": "/var/lib/kea/kea-leases4.csv", "lfc-interval": 3600 },
    "subnet4": [
        {
            "subnet": "$SUBNET",
            "pools": [ { "pool": "$DHCP_START - $DHCP_END" } ],
            "option-data": [
                { "name": "routers", "data": "$GATEWAY_IP" },
                { "name": "domain-name-servers", "data": "8.8.8.8, 1.1.1.1" }
            ],
            "valid-lifetime": 600
        }
    ],
    "loggers": [ { "name": "kea-dhcp4", "output_options": [ { "output": "stdout", "pattern": "%-5p %m\n" } ], "severity": "INFO" } ]
}
}
EOF

sed -i '/FW_SYSLOG_HOST/d' /etc/environment
echo "FW_SYSLOG_HOST=$FIREWALL_IP" >> /etc/environment

cat << EOF > /etc/systemd/system/iot-network.service
[Unit]
Description=IoT Lab Network
Before=kea-dhcp4-server.service iot-vms.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/iot-lab-network
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/iot-syslog.service
[Unit]
Description=IoT Lab Syslog
After=network.target kea-dhcp4-server.service
[Service]
Type=simple
User=root
WorkingDirectory=$BASE_DIR
ExecStart=/usr/bin/python3 $BASE_DIR/src/dhcp_processor.py
Restart=always
Environment="FW_SYSLOG_HOST=$FIREWALL_IP"
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/iot-vms.service
[Unit]
Description=IoT Lab VMs
After=iot-network.service iot-syslog.service
[Service]
Type=forking
User=root
WorkingDirectory=$BASE_DIR
ExecStart=/usr/local/bin/iot-lab-launch
TimeoutSec=300
[Install]
WantedBy=multi-user.target
EOF

# 9. GENERATE SYSTEM-WIDE MANAGEMENT COMMAND
echo ""
echo "[7/8] Installing 'iot_lab' system command..."

cat << EOF > /usr/local/bin/iot_lab
#!/bin/bash
# iot_lab - Manage the IoT Simulation Environment
BASE_DIR="$BASE_DIR"
ACTION=\$1
ARG=\$2

function show_help {
    echo "Usage: iot_lab <command> [option]"
    echo "Commands:"
    echo "  start         Start the lab environment"
    echo "  stop          Stop all VMs and services"
    echo "  restart       Restart the environment"
    echo "  status        Show status of VMs, Network, and DHCP"
    echo "  connect <ID>  Connect to VM Console (e.g., iot_lab connect 01)"
    echo "  log <TARGET>  Tail log files (TARGET: 'syslog' or VM ID like '01')"
    echo "  clean         DESTROY the lab (Delete data and configurations)"
    echo "  help          Shows this help message."
}

function wait_for_interface {
    INTERFACE="br-iot"
    MAX_ATTEMPTS=10
    ATTEMPT=1
    
    echo -n "    ... checking for interface \$INTERFACE"
    while [ \$ATTEMPT -le \$MAX_ATTEMPTS ]; do
        # Check if interface exists and is Administratively UP
        STATE=\$(ip -o link show \$INTERFACE 2>/dev/null | grep -oE 'state (UP|UNKNOWN)')
        if [ ! -z "\$STATE" ]; then
            echo " [OK]"
            return 0
        fi
        echo -n "."
        sleep 1
        ATTEMPT=\$((ATTEMPT + 1))
    done
    echo " [FAILED]"
    return 1
}

function check_dhcp_port {
    for i in {1..10}; do
        if ss -tulpn | grep -q ":67 "; then
            return 0
        fi
        echo "    ... waiting for DHCP to listen (attempt \$i/10)"
        sleep 1
    done
    return 1
}

case \$ACTION in
  start)
    echo "[*] Starting services..."
    
    # 1. Start Network Layer
    sudo systemctl start iot-network
    
    # 2. Launch VMs (Required to bring bridge Operationally UP)
    echo "[*] Launching VMs..."
    sudo systemctl start iot-vms
    
    # 3. Wait for infrastructure to settle
    echo "[*] Waiting for network bridge..."
    sleep 10
    if ! wait_for_interface; then
        echo "[!] WARNING: Bridge interface check failed. Kea might fail."
    fi
    
    # 4. Start DHCP
    echo "[*] Starting DHCP Server..."
    sudo systemctl restart kea-dhcp4-server
    
    # 5. Validate DHCP Listening
    if ! check_dhcp_port; then
        echo "[!] ERROR: DHCP failed to bind port 67. Restarting..."
        sudo systemctl restart kea-dhcp4-server
        sleep 2
        if ! check_dhcp_port; then
             echo "[!] CRITICAL: DHCP still not listening. Aborting."
             echo "    Check: sudo journalctl -u kea-dhcp4-server"
             exit 1
        fi
    fi
    echo "    [+] DHCP Listening on Port 67."

    # 6. Start Agents
    sudo systemctl start iot-syslog
    echo "[+] Environment Started Successfully."
    ;;
  stop)
    echo "[*] Stopping services..."
    sudo systemctl stop iot-vms
    sudo systemctl stop iot-syslog
    sudo systemctl stop kea-dhcp4-server
    sudo systemctl stop iot-network
    sudo pkill -f qemu-system-aarch64
    echo "[-] Done."
    ;;
  restart) \$0 stop; sleep 2; \$0 start ;;
  status)
    echo "=========================================================="
    echo "                 IoT LAB STATUS                           "
    echo "=========================================================="
    systemctl status iot-network iot-syslog iot-vms kea-dhcp4-server | grep -E "●|Active:"
    echo ""
    echo "[ RUNNING VMS ]"
    pgrep -a qemu | cut -d' ' -f1-4,15-20
    echo ""
    echo "[ DHCP LEASES ]"
    tail -n 5 /var/lib/kea/kea-leases4.csv
    echo "=========================================================="
    ;;
  connect)
    if [ -z "\$ARG" ]; then
        echo "Error: Please specify a VM ID (e.g., 01, 1, 10)"
        exit 1
    fi
    ID=\$(printf "%02d" \$ARG)
    SOCK="\$BASE_DIR/logs/vm_\$ID.sock"
    
    if [ ! -S "\$SOCK" ]; then
        echo "Error: Socket \$SOCK not found. Is the VM running?"
        exit 1
    fi
    
    echo "[*] Connecting to IoT Device \$ID..."
    echo "    (Press Ctrl+C to exit console)"
    sudo socat - UNIX-CONNECT:\$SOCK
    ;;
  log)
    if [ -z "\$ARG" ]; then
        echo "Error: Please specify target (syslog or VM ID)"
        exit 1
    fi
    
    if [ "\$ARG" == "syslog" ]; then
        FILE="\$BASE_DIR/logs/iot_traffic.log"
        echo "[*] Tailing Syslog Traffic (\$FILE)..."
    else
        ID=\$(printf "%02d" \$ARG)
        FILE="\$BASE_DIR/logs/vm_\$ID.log"
        echo "[*] Tailing VM \$ID Serial Output (\$FILE)..."
    fi
    
    if [ ! -f "\$FILE" ]; then
        echo "Error: Log file \$FILE not found."
        exit 1
    fi
    
    tail -f "\$FILE"
    ;;
  clean)
    echo "[!] WARNING: This will DESTROY the lab environment."
    read -p "Are you sure? (y/N) " confirm
    if [[ \$confirm != [yY] ]]; then exit 0; fi
    
    \$0 stop
    echo "[*] Removing Systemd Services..."
    sudo rm -f /etc/systemd/system/iot-*.service
    sudo systemctl daemon-reload
    
    echo "[*] Cleaning Directories..."
    sudo rm -rf \$BASE_DIR /var/lib/kea /etc/kea/kea-dhcp4.conf
    
    echo "[*] Cleaning Network..."
    sudo ip link delete br-iot 2>/dev/null
    for i in \$(seq -w 01 20); do sudo ip link delete tap-iot\$i 2>/dev/null; done
    
    echo "[*] Uninstalling Command..."
    sudo rm -f /usr/local/bin/iot_lab
    echo "[+] System Cleaned."
    ;;
  *) 
    show_help 
    exit 1 
    ;;
esac
EOF
chmod +x /usr/local/bin/iot_lab

# 10. LAUNCH
echo ""
echo "[8/8] Finalizing & Launching..."
if ss -tulpn | grep ":67 " | grep -q "dnsmasq"; then
    virsh net-destroy default 2>/dev/null
    pkill dnsmasq
fi
chown -R $REAL_USER:$REAL_USER "$BASE_DIR"

# Clean start
systemctl daemon-reload
systemctl enable iot-network iot-syslog iot-vms

echo "[*] Invoking 'iot_lab start' to initialize environment..."
/usr/local/bin/iot_lab start

echo ""
echo "================================================================"
echo "          IoT Lab Deployed Successfully!                        "
echo "================================================================"
echo "   Devices:  $COUNT"
echo "   Sunet:    $SUBNET"
echo "   Gateway:  $GATEWAY_IP"
echo "   Syslog:   $FIREWALL_IP"
echo "================================================================"
echo ""
echo "--- MANAGEMENT COMMANDS ---"
echo "To manage the lab, use the generated script:"
echo ""
echo "   Usage: iot_lab <command> [option]"
echo ""
echo "   Commands:"
echo "     start         Start the lab environment"
echo "     stop          Stop all VMs and services"
echo "     restart       Restart the environment"
echo "     status        Show status of VMs, Network, and DHCP"
echo "     connect <ID>  Connect to VM Console (e.g., iot_lab connect 01)"
echo "     log <TARGET>  Tail logs. Target: 'syslog' or VM ID (e.g., 01)"
echo "     clean         DESTROY the lab (Delete data and configurations)"
echo "     help          Shows this help message."
echo ""
