# KRITI Network Analyzer

An offline-first, local browser dashboard for visibility into a Linux machine's network configuration and authorized private lab network. Built with Python, Flask, Nmap, and standard Linux networking tools.

## Features

- Network overview: hostname, IPv4 interfaces, private subnets, routes, DNS, and tool availability.
- Device discovery: Nmap host discovery (`nmap -sn`) on a private subnet currently assigned to this machine.
- Authorized TCP port checks: Nmap TCP connect scan (`-sT`) against one private IPv4 address in an attached subnet. Uses a fixed common-port allowlist.
- Traffic monitor: reads Linux interface RX/TX byte counters from `/sys/class/net`; these are cumulative counters, not packet capture.
- Wi-Fi status: checks `iw dev` and explains when no wireless interface is exposed.
- Reports: export the latest device list, port scan, or overview as CSV, HTML, or JSON. Reports are stored in `reports/`.
- Local-only Flask server: binds to `127.0.0.1`, not the LAN or internet.

## Safety and scope

Use this tool only on networks and devices you own or have explicit permission to assess. The app rejects public IPs, loopback, link-local addresses, large ranges, and targets outside private subnets currently assigned to this machine. Device discovery is limited to 1,024 addresses. Port checks are limited to a built-in list of common TCP ports. This is an inventory/learning tool, not a vulnerability scanner or proof that a host is secure.

## Requirements

- Kali Linux (or another Linux distribution with `iproute2`).
- Python 3.10 or newer.
- Nmap for device discovery and TCP checks.
- `iw` for wireless-interface detection (optional).
- Flask (installed from `requirements.txt`).

## Install on Kali Linux

Open Terminal and run these commands one at a time:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk iproute2 nmap iw
cd ~/Desktop
```

If you downloaded the project ZIP, extract it first. Then enter the extracted folder (adjust the folder name if needed):

```bash
cd ~/Desktop/kriti_network_analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open this address in your browser:

```text
http://127.0.0.1:5000
```

Keep the terminal open while using the dashboard. Press `Ctrl+C` in the terminal to stop it.

## First use

1. Open **Overview** and note the private network range shown under Local Networks.
2. Open **Device discovery**, use that exact range, and click **Discover devices**.
3. For a TCP check, enter the IP of a device you own/administer, select ports, tick the authorization checkbox, and start the scan.
4. Open **Traffic monitor** to view interface byte counters.
5. Open **Wi-Fi status** to see whether Kali can access a wireless interface.
6. Open **Reports** to export the latest results.

## WSL2 and virtual-machine notes

WSL2 and many VMware/VirtualBox configurations expose a virtual Ethernet interface, not the host's physical Wi-Fi adapter. In those environments, device discovery and Wi-Fi features may be limited to the virtual network. A physical Wi-Fi interface will appear only if the operating environment and hardware explicitly expose it. Do not expect `wlan0` to exist automatically.

## GitHub setup

Create a new **public** repository on GitHub named `kriti-network-analyzer`. Do not initialize it with a README if you already have this project README locally.

From the project folder:

```bash
git init
git add .
git commit -m "Initial KRITI Network Analyzer project"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/kriti-network-analyzer.git
git push -u origin main
```

Replace `YOUR_GITHUB_USERNAME` with your GitHub username. For future updates:

```bash
git add .
git commit -m "Update network analyzer"
git push
```

Never commit private logs, credentials, API keys, or network data that you do not intend to publish. The `reports/` and `logs/` contents are ignored by Git by default.

## Troubleshooting

- **`nmap: command not found`**: `sudo apt install nmap`.
- **`No module named flask`**: activate the venv with `source .venv/bin/activate`, then run `pip install -r requirements.txt`.
- **No private network detected**: check `ip -brief addr` and ensure the network interface is up and has a private IPv4 address.
- **Target is outside an assigned subnet**: connect the Kali machine to the authorized network first. The app intentionally blocks unrelated/public targets.
- **No Wi-Fi interface**: common in WSL2 and VMs; use a supported USB Wi-Fi adapter passed through to a Linux environment that supports it, or use the Ethernet-based features.
- **Permission denied / Nmap scan limitations**: this app uses TCP connect scans and does not require raw-packet privileges for the port-check feature. Device discovery behavior can vary by network and host firewall.
- **Port shows no result**: the dashboard uses Nmap `--open`, so only open ports are listed. A missing row does not prove a port is closed.

## Project structure

```text
kriti_network_analyzer/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   └── index.html
├── static/
│   ├── app.js
│   └── style.css
├── logs/
│   └── .gitkeep
└── reports/
    └── .gitkeep
```

## License

Choose a license before publishing. For a public learning portfolio, the MIT License is a common permissive option; add a `LICENSE` file only after deciding to use it.
