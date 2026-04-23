import responses

from main import get_subdomains

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