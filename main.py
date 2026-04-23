import requests

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
