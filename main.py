import requests
import nmap
import json
import argparse
from concurrent.futures import ThreadPoolExecutor

def check_url(url): # проверяем URL
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code
    except requests.RequestException:
        return None

def get_subdomains(domain):  # ищем поддомены
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

def scan_ports(hosts): # сканим порты
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

def get_valid_schema(domain): # поиск https или http
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        if response.status_code:
            return "https://"
    except requests.RequestException:
        return "http://"

def setup_parser(): # парсер аргументов командной строки
    parser = argparse.ArgumentParser(description="Сканер доменов и портов")
    parser.add_argument("-d" , "--domain", help="Домен или IP для сканирования", required=True)
    parser.add_argument("-w", "--wordlist", help="Файл со списком директорий для брутфорса", required=False)
    parser.add_argument("-o", "--output", help="Файл для сохранения результатов в формате MD", required=False)
    return parser

def bruteforce_dirs(base_url, wordlist): # брутфорс директорий
    result_dict = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_dir = {executor.submit(check_url, f"{base_url.rstrip('/')}/{dir}"): dir for dir in wordlist}
        for future in future_to_dir:
            dir = future_to_dir[future]
            status = future.result()
            if status and status != 404:
                result_dict[dir] = f"{status}" 
    return result_dict

def generate_markdown(data, domain): # формируем MD отчет
    md_list = [f"# OSINT Report for {domain}\n"]
    if data.get("protocol"):
        md_list.append(f"**Protocol:** {data['protocol']}\n\n")
    if data.get("subdomains"):
        md_list.append("## Found Subdomains\n")
        for sub in data["subdomains"]:
            md_list.append(f"- {sub}\n\n")
    if data.get("ports"):
        md_list.append("## Open Ports\n")
        for ip, ports in data["ports"].items():
            md_list.append(f"### {ip}\n")
            for port, status in ports.items():
                md_list.append(f"- Port {port}: {status}\n\n")
    if data.get("directories"):
        md_list.append("## Found Directories\n")
        for dir, status in data["directories"].items():
            md_list.append(f"- {dir}: {status}\n\n")
    return "\n".join(md_list)

def run_scan(domain, wordlist_path=None): # запуск сканирования
    if wordlist_path:
            with open(wordlist_path, 'r') as f:
                common_dirs = [line.strip() for line in f if line.strip()]
    else:
        common_dirs = ["admin", "login", "dashboard", "config", "backup", "api", ".git"]
    schema = get_valid_schema(domain)
    brute_result = bruteforce_dirs(f"{schema}{domain}", common_dirs)
    subs_list = get_subdomains(domain)
    subs_str = " ".join(set(subs_list + [domain]))
    scan_result = scan_ports(subs_str)
    
    final_json = {
            "domain": domain,
            "protocol": schema,
            "subdomains": subs_list,
            "ports": scan_result,
            "directories": brute_result
        }
    return final_json


if __name__ ==  "__main__":
    parser = setup_parser()
    args = parser.parse_args()
    result = run_scan(args.domain,args.wordlist)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(generate_markdown(result, args.domain))
            print(f"Результаты сохранены в {args.output}")
    else:
        print(json.dumps(result, indent=4))