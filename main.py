import requests
import nmap

def get_subdomains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0'}
    response = requests.get(url, headers=headers, timeout=30)

    data = response.json()
    subdomains = set()
    
    for entry in data:
        names = entry['name_value'].split('\n')
        for name in names:
            clean_name = name.strip().lower().replace('*.', '')
            subdomains.add(clean_name)

    return sorted(list(subdomains))

def scan_ports(host):
    scanner = nmap.PortScanner()
    scanner.scan(host, arguments='-p 80,443 -Pn')
    
    hosts_found = scanner.all_hosts()
    if not hosts_found:
        return {}
    
    target = hosts_found[0]

    if scanner[target].state() != 'up':
        return {}
    
    if 'tcp' not in scanner[target].all_protocols():
        return {}

    port_data = scanner[target]['tcp']
    port_statuses = {port: port_data[port]['state'] for port in port_data}    
    
    return port_statuses

if __name__ ==  "__main__":
    print(scan_ports("google.com"))