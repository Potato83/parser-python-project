import responses

from main import get_subdomains, scan_ports

@responses.activate

def test_get_subdomains_valid():
    
    domain = "example.com"
    fake_json =[{"name_value": "*.example.com\nadmin.example.com", "status": "ok"}]

    responses.add(
        responses.GET, 
        f"https://crt.sh/?q={domain}&output=json",
        json=fake_json,  
        status=200     
    )

    result = get_subdomains(domain)
    
    assert isinstance(result, list), "Результат должен быть списком"
    assert len(result) > 0, "Должен быть найден хотя бы один поддомен"
    assert all(isinstance(sub, str) for sub in result), "Все элементы должны быть строками"
    
def test_scan_ports():
    host = "127.0.0.1"
    result = scan_ports(host)
    
    assert isinstance(result, dict), "Результат должен быть словарем"
    assert 80 in result, "Должен быть найден порт 80"
    assert 443 in result, "Должен быть найден порт 443"
    # assert len(result) == 0, "Словарь должен быть пустым для заглушки"