from unittest import result

import requests
import responses

from main import get_subdomains, scan_ports, setup_parser, bruteforce_dirs, generate_markdown, get_valid_schema, check_url

@responses.activate
def test_get_subdomains_valid():
    
    domain = "example.com"
    fake_json =[{"name_value": "*.example.com\nadmin.example.com\nemail@example.com", "status": "ok"}]

    responses.add(
        responses.GET, 
        f"https://crt.sh/?q={domain}&output=json",
        json=fake_json,  
        status=200     
    )

    result = get_subdomains(domain)
    
    assert isinstance(result, list), "Результат должен быть списком"
    assert len(result) > 0, "Должен быть найден хотя бы один поддомен"
    assert "email@example.com" not in result, "Электронная почта не должна быть включена в результат"
    assert all(isinstance(sub, str) for sub in result), "Все элементы должны быть строками"
    
def test_scan_ports():
    host = "127.0.0.1"
    result = scan_ports(host)
    
    assert isinstance(result, dict), "Результат должен быть словарем"
    assert host in result, f"Должен быть найден хост {host} в результатах сканирования"
    assert 80 in result[host], "Должен быть найден порт 80"
    assert 443 in result[host], "Должен быть найден порт 443"
    # assert len(result) == 0, "Словарь должен быть пустым для заглушки"
 
def test_cli_parser():
    parser = setup_parser()
    args = parser.parse_args(["-d", "test.com", "-w", "wordlist.txt", "-o", "output.md"])
    assert args.domain == "test.com", "Парсер должен корректно обрабатывать аргумент -d"
    assert args.wordlist == "wordlist.txt", "Парсер должен корректно обрабатывать аргумент -w"
    assert args.output == "output.md", "Парсер должен корректно обрабатывать аргумент -o"

def test_generate_md():
    fake_data = {
    "protocol": "https://",
    "subdomains":["dev.test.com"],
    "ports": {"127.0.0.1": {80: "open"}},
    "directories": {"admin": "200 OK"}
    }
    md = generate_markdown(fake_data, "test.com")
    assert "# OSINT Report for test.com" in md, "Markdown должен содержать заголовок с доменом"
    assert "dev.test.com" in md, "Markdown должен содержать найденные поддомены"
    assert "127.0.0.1" in md, "Markdown должен содержать IP-адреса из результатов сканирования портов"
    assert "Protocol" in md, "Markdown должен содержать информацию о протоколе"

@responses.activate
def test_brute_force_dirs():
    url = "http://example.com"
    dictionary_list = ["admin", "fake_dir"]
    
    responses.add(
        responses.HEAD, 
        f"{url}/admin", 
        status=200     
    )
    
    responses.add(
        responses.HEAD, 
        f"{url}/fake_dir", 
        status=404 
    )
    
    result = bruteforce_dirs(url, dictionary_list)
    # assert isinstance(result, dict), "Результат должен быть словарем"
    assert "admin" in result, "Должен быть найден каталог 'admin'"
    assert "fake_dir" not in result, "Каталог 'fake_dir' не должен быть найден"

@responses.activate
def test_get_subdomains_server_error():
    domain = "this-test-domain-does-not-exist.test123"

    responses.add(
        responses.GET, 
        f"https://crt.sh/?q={domain}&output=json",
        status=500,
        json={"error": "Internal Server Error"}
    )

    result = get_subdomains("this-test-domain-does-not-exist.test123")
    
    assert isinstance(result, list), "Результат должен быть списком"
    assert len(result) == 0, "Должен быть возвращен пустой список при ошибке сервера"

@responses.activate
def test_get_valid_schema():
    domain = "example.com"
    responses.add(
        responses.HEAD, 
        f"https://{domain}",
        status=200
    )
    schema = get_valid_schema(domain)
    assert schema == "https://", "Функция должна возвращать 'https://' для данного домена"

@responses.activate
def test_get_valid_schema_fallback():
    domain = "example.com"
    responses.add(
        responses.HEAD, 
        f"https://{domain}",
        body=requests.exceptions.ConnectionError("Connection refused")
    )
    schema = get_valid_schema(domain)
    assert schema == "http://", "Функция должна возвращать 'http://' при невозможности установить HTTPS-соединение"
    
def test_check_url():
    url = "http://example.com"
    responses.add(
        responses.HEAD, 
        url,
        status=200
    )
    status_code = check_url(url)
    assert status_code == 200, "Функция должна возвращать статус код 200 для доступного URL"
    
    url_unreachable = "http://unreachable.example.com"
    responses.add(
        responses.HEAD, 
        url_unreachable,
        body=requests.exceptions.ConnectionError("Connection refused")
    )
    status_code_unreachable = check_url(url_unreachable)
    assert status_code_unreachable is None, "Функция должна возвращать None для недоступного URL"