import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import logging
import sys
from filelock import FileLock




os.makedirs("results", exist_ok=True)

logging.basicConfig(
    filename="results/scan.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)




RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"




def check_ip_active(ip):
    urls = [f"http://{ip}", f"https://{ip}"]
    for url in urls:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in [200, 301, 302, 403]:
                return True, url
        except:
            pass
    return False, None



def detect_frameworks(url):
    frameworks = {
        'laravel': False,
        'symfony': False,
        'django': False,
        'flask': False,
        'rails': False,
        'woocommerce': False,
        'express': False,
        'wordpress': False,
        'joomla': False,
        'drupal': False,
        'magento': False,
        'git': False
    }

    try:
        r = requests.get(url, timeout=5)
        text = r.text.lower()
        headers = r.headers
        cookies = r.cookies.get_dict()
        x_powered = headers.get('x-powered-by', '').lower()
        server_header = headers.get('server', '').lower()


        if ('laravel' in text or 'laravel_session' in cookies or
            '/vendor/' in text or 'laravel' in x_powered or
            '/artisan' in text or '/storage/logs/laravel.log' in text):
            frameworks['laravel'] = True


        if ('symfony' in text or 'x-debug-token' in headers or
            '_profiler' in text or 'symfony' in x_powered or
            '/config/' in text or '/app/Resources/views/' in text):
            frameworks['symfony'] = True


        if ('django' in text or 'csrftoken' in cookies or
            'sessionid' in cookies or 'django' in x_powered or
            '/admin/login/' in text):
            frameworks['django'] = True

        if ('flask' in text or 'flask-session' in cookies or
            'flask' in x_powered or '/static/' in text or
            '.py' in text):
            frameworks['flask'] = True


        if ('rails' in text or '_rails_session' in cookies or
            'rails' in x_powered or 'x-rails' in headers or
            '/assets/' in text or '.rb' in text):
            frameworks['rails'] = True


        if ('woocommerce' in text or 'woocommerce_cart_hash' in cookies or
            'woocommerce_items_in_cart' in cookies or '/shop/' in text):
            frameworks['woocommerce'] = True

        if ('express' in x_powered or 'express' in server_header or
            'express' in text or 'node_modules' in text):
            frameworks['express'] = True

        if ('wp-content' in text or 'wp-includes' in text or
            'wp-settings-time' in cookies or 'wordpress' in x_powered or
            '/wp-login.php' in text or '/xmlrpc.php' in text):
            frameworks['wordpress'] = True


        if ('joomla' in text or 'joomla_remember_me' in cookies or
            'joomla' in x_powered or '/administrator/' in text):
            frameworks['joomla'] = True

        if ('drupal' in text or
            'x-generator' in headers.get('x-generator', '').lower() or
            '/user/login' in text or '/core/' in text or '/sites/' in text):
            frameworks['drupal'] = True


        if ('magento' in text or 'mage-' in ';'.join(cookies.keys()).lower() or
            'x-magento' in headers or '/static/adminhtml' in text or '/setup' in text):
            frameworks['magento'] = True


        git_paths = [
            "/.git/HEAD", "/.git/config", "/.git/objects/",
            "/.git/refs/heads/", "/.git/info/exclude", "/.git/logs/HEAD"
        ]

        for path in git_paths:
            try:
                r_git = requests.get(url + path, timeout=2, allow_redirects=False)
                if r_git.status_code == 200 and ("ref:" in r_git.text.lower() or "git" in r_git.text.lower()):
                    frameworks['git'] = True
                    print(f"{GREEN}[+] Git exposed at {url}{path}{RESET}")
                    break
            except:
                pass

    except:
        return frameworks

    return frameworks



def write_result(fw, url):
    path = f"results/{fw}.txt"
    with FileLock(path + ".lock"):
        with open(path, "a") as f:
            f.write(url + "\n")



def scan_ip(ip_str):
    active, url = check_ip_active(ip_str)
    if not active:
        return

    print(f"{GREEN}{ip_str} ONLINE WEBSITE ({url}){RESET}")

    frameworks = detect_frameworks(url)

    for fw, detected in frameworks.items():
        if detected:
            write_result(fw, url)
            print(f"{GREEN}{url} => {fw.upper()} DETECTED{RESET}")



def ip_stream(start, end):
    s = int(ipaddress.IPv4Address(start))
    e = int(ipaddress.IPv4Address(end))

    if s > e:
        s, e = e, s

    for i in range(s, e + 1):
        yield str(ipaddress.IPv4Address(i))



if __name__ == "__main__":

    if len(sys.argv) == 3:
        start_ip = sys.argv[1]
        end_ip = sys.argv[2]
    else:
        start_ip = input("[+] IP start: ").strip()
        end_ip = input("[+] IP end: ").strip()

    with ThreadPoolExecutor(max_workers=140) as executor:
        futures = (executor.submit(scan_ip, ip) for ip in ip_stream(start_ip, end_ip))
        for _ in as_completed(futures):
            pass

    print("\n[+] Scan terminé. Résultats dans /results.")
