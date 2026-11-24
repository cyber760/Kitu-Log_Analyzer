from __future__ import annotations
import csv, html, ipaddress, json, os, re, shutil, socket, subprocess, threading, time
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file

BASE = Path(__file__).resolve().parent
REPORTS = BASE / 'reports'
LOGS = BASE / 'logs'
REPORTS.mkdir(exist_ok=True)
LOGS.mkdir(exist_ok=True)
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Local-only dashboard: never expose the service on a public interface.
HOST = '127.0.0.1'
MAX_HOSTS = 1024
MAX_PORTS = 30
ALLOWED_PORTS = {21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9000,9200,27017}


def run_cmd(args, timeout=12):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {'ok': p.returncode == 0, 'stdout': p.stdout.strip(), 'stderr': p.stderr.strip(), 'code': p.returncode}
    except FileNotFoundError:
        return {'ok': False, 'stdout': '', 'stderr': f"Required command not found: {args[0]}", 'code': 127}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'stdout': '', 'stderr': 'Command timed out.', 'code': 124}
    except Exception as exc:
        return {'ok': False, 'stdout': '', 'stderr': str(exc), 'code': 1}


def local_networks():
    result = run_cmd(['ip', '-o', '-4', 'addr', 'show', 'up'])
    nets = []
    for line in result['stdout'].splitlines():
        m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
        if not m:
            continue
        try:
            net = ipaddress.ip_interface(m.group(1)).network
            if net.is_private and not net.is_loopback and net.num_addresses <= MAX_HOSTS:
                nets.append(str(net))
        except ValueError:
            pass
    return sorted(set(nets))


def validate_local_target(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError('Enter a valid IPv4 address or CIDR range, for example 192.168.1.0/24.')
    if not isinstance(net, ipaddress.IPv4Network) or not net.is_private or net.is_loopback or net.is_link_local:
        raise ValueError('Only private IPv4 networks are allowed.')
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f'Range is too large. Maximum supported range: {MAX_HOSTS} addresses.')
    allowed = [ipaddress.ip_network(n) for n in local_networks()]
    if not any(net.subnet_of(a) for a in allowed):
        raise ValueError('Target must overlap a private network currently assigned to this machine. Connect to your authorized lab/network first.')
    return net


def network_info():
    ip = run_cmd(['ip', '-brief', 'addr'])
    route = run_cmd(['ip', 'route'])
    dns = ''
    try:
        dns = '\n'.join(x.strip() for x in Path('/etc/resolv.conf').read_text().splitlines() if x.strip().startswith('nameserver'))
    except OSError:
        pass
    hostname = socket.gethostname()
    return {'hostname': hostname, 'interfaces': ip['stdout'], 'routes': route['stdout'], 'dns': dns,
            'local_networks': local_networks(), 'nmap': shutil.which('nmap') is not None,
            'tcpdump': shutil.which('tcpdump') is not None, 'iw': shutil.which('iw') is not None}


def discover_devices(cidr):
    net = validate_local_target(cidr)
    if not shutil.which('nmap'):
        raise RuntimeError('Nmap is not installed. Run: sudo apt install nmap')
    result = run_cmd(['nmap', '-sn', '-n', str(net)], timeout=90)
    if not result['ok'] and not result['stdout']:
        raise RuntimeError(result['stderr'] or 'Nmap discovery failed.')
    devices = []
    current = None
    for line in result['stdout'].splitlines():
        m = re.search(r'Nmap scan report for (.+)', line)
        if m:
            value = m.group(1).strip()
            ipm = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
            current = {'ip': ipm.group(1) if ipm else value, 'hostname': value if ipm and value != ipm.group(1) else '', 'mac': '', 'vendor': '', 'status': 'Up'}
            devices.append(current)
        m = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})\s*\((.*?)\)', line)
        if m and current:
            current['mac'], current['vendor'] = m.group(1), m.group(2)
    return devices


def scan_ports(target, ports):
    # A single IPv4 host only; target must be inside a currently attached private subnet.
    try:
        addr = ipaddress.ip_address(target.strip())
    except ValueError:
        raise ValueError('Enter one valid IPv4 address.')
    if not isinstance(addr, ipaddress.IPv4Address) or not addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError('Only private IPv4 targets are allowed.')
    nets = [ipaddress.ip_network(n) for n in local_networks()]
    if not any(addr in n for n in nets):
        raise ValueError('Target must belong to a private network currently assigned to this machine.')
    if not ports or len(ports) > MAX_PORTS or any(p not in ALLOWED_PORTS for p in ports):
        raise ValueError('Choose up to 30 ports from the built-in common-port list.')
    if not shutil.which('nmap'):
        raise RuntimeError('Nmap is not installed. Run: sudo apt install nmap')
    result = run_cmd(['nmap', '-sT', '-Pn', '-n', '--open', '-T3', '-p', ','.join(map(str, ports)), str(addr)], timeout=75)
    if not result['ok'] and not result['stdout']:
        raise RuntimeError(result['stderr'] or 'Port scan failed.')
    found = []
    for line in result['stdout'].splitlines():
        m = re.match(r'^(\d+)/tcp\s+(open|closed|filtered)\s*(.*)$', line.strip())
        if m:
            found.append({'port': int(m.group(1)), 'state': m.group(2), 'service': m.group(3).strip()})
    return found


def interface_counters():
    out = []
    root = Path('/sys/class/net')
    if not root.exists():
        return out
    for iface in root.iterdir():
        try:
            rx = int((iface / 'statistics/rx_bytes').read_text())
            tx = int((iface / 'statistics/tx_bytes').read_text())
            state = (iface / 'operstate').read_text().strip()
            out.append({'interface': iface.name, 'state': state, 'rx_bytes': rx, 'tx_bytes': tx})
        except (OSError, ValueError):
            continue
    return out


def wifi_info():
    if not shutil.which('iw'):
        return {'available': False, 'message': 'The iw command is not installed. Install with: sudo apt install iw', 'output': ''}
    result = run_cmd(['iw', 'dev'], timeout=5)
    if not result['stdout']:
        return {'available': False, 'message': 'No wireless interface is exposed to this Kali environment. WSL and many virtual machines expose Ethernet only.', 'output': result['stderr']}
    return {'available': True, 'message': 'Wireless interfaces detected. Detailed link status may require a supported Wi-Fi adapter.', 'output': result['stdout']}


def save_report(kind, data, extension):
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = REPORTS / f'{kind}_{stamp}.{extension}'
    if extension == 'json':
        path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    elif extension == 'csv':
        rows = data if isinstance(data, list) else [data]
        keys = sorted({k for row in rows for k in row}) if rows else ['message']
        with path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys); writer.writeheader(); writer.writerows(rows)
    elif extension == 'html':
        rows = data if isinstance(data, list) else [data]
        keys = sorted({k for row in rows for k in row}) if rows else ['message']
        table = ''.join('<tr>' + ''.join(f'<td>{html.escape(str(row.get(k,"")))}</td>' for k in keys) + '</tr>' for row in rows)
        heads = ''.join(f'<th>{html.escape(k)}</th>' for k in keys)
        path.write_text(f'<!doctype html><meta charset="utf-8"><title>KRITI Network Report</title><h1>KRITI Network Analyzer Report</h1><p>Generated {datetime.now().isoformat(timespec="seconds")}</p><table border="1" cellpadding="6"><tr>{heads}</tr>{table}</table>', encoding='utf-8')
    return path


@app.get('/')
def index():
    return render_template('index.html')

@app.get('/api/overview')
def overview():
    return jsonify({'network': network_info(), 'traffic': interface_counters(), 'wifi': wifi_info()})

@app.post('/api/discover')
def discover():
    body = request.get_json(silent=True) or {}
    try:
        devices = discover_devices(body.get('cidr', ''))
        return jsonify({'ok': True, 'devices': devices, 'count': len(devices)})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

@app.post('/api/ports')
def ports():
    body = request.get_json(silent=True) or {}
    try:
        target = body.get('target', '')
        if body.get('authorized') is not True:
            raise ValueError('Confirm that you own or are authorized to test this device.')
        selected = body.get('ports', [])
        if not isinstance(selected, list) or any(not isinstance(p, int) for p in selected):
            raise ValueError('Invalid port selection.')
        found = scan_ports(target, selected)
        return jsonify({'ok': True, 'target': target, 'ports': found, 'count': len(found)})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

@app.get('/api/traffic')
def traffic():
    return jsonify({'interfaces': interface_counters(), 'timestamp': datetime.now().isoformat(timespec='seconds')})

@app.get('/api/wifi')
def wifi():
    return jsonify(wifi_info())

@app.post('/api/report')
def report():
    body = request.get_json(silent=True) or {}
    data = body.get('data', [])
    kind = re.sub(r'[^a-z0-9_-]', '', str(body.get('kind', 'network'))[:30].lower()) or 'network'
    ext = body.get('format', 'csv')
    if ext not in {'csv', 'html', 'json'}:
        return jsonify({'ok': False, 'error': 'Choose CSV, HTML, or JSON.'}), 400
    if not isinstance(data, (list, dict)):
        return jsonify({'ok': False, 'error': 'Report data must be a list or object.'}), 400
    path = save_report(kind, data, ext)
    return send_file(path, as_attachment=True, download_name=path.name)

@app.get('/api/reports')
def reports():
    files = [{'name': p.name, 'size': p.stat().st_size, 'modified': datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec='seconds')} for p in sorted(REPORTS.glob('*'), key=lambda x: x.stat().st_mtime, reverse=True)]
    return jsonify(files)

if __name__ == '__main__':
    print('KRITI Network Analyzer: http://127.0.0.1:5000')
    print('Local-only server. Do not change host to 0.0.0.0.')
    app.run(host=HOST, port=5000, debug=False)
