import requests
import nmap
import json

def get_subdomains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0'}
    response = requests.get(url, headers=headers, timeout=30)
    
    if response.status_code != 200 or "json" not in response.headers.get("Content-Type", ""):
        return []

    data = response.json()
    subdomains = set()
    
    for entry in data:
        names = entry['name_value'].split('\n')
        for name in names:
                clean_name = name.strip().lower().replace('*.', '')
                if " " in clean_name or "@" in clean_name:
                    continue
                subdomains.add(clean_name)

    return sorted(list(subdomains))

def scan_ports(hosts):

    scanner = nmap.PortScanner()
    scanner.scan(hosts, arguments='-p 80,443 -Pn')
    
    results = {}
    
    if not scanner.all_hosts():
        return {}
    
    for ip in scanner.all_hosts():
        if scanner[ip].state() == 'up':
            results[ip] = {}
            if 'tcp' in scanner[ip].all_protocols():
                tcp_ports = scanner[ip]['tcp']
                for port in tcp_ports:
                    results[ip][port] = tcp_ports[port]['state']
    
    return results

def run_scan(domain):
    subs_list = get_subdomains(domain)
    subs_str = " ".join(set(subs_list + [domain]))
    scan_result = scan_ports(subs_str)
    
    final_json = {
        "subdomains": subs_list,
        "ports": scan_result
    }
    return final_json
    
if __name__ ==  "__main__":
    print(json.dumps(run_scan(input("Введите домен/ip для сканирования: ")), indent=4))
    # print(json.dumps(run_scan("example.com"), indent=4))