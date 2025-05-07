import requests
import socket
import whois
import json
import argparse
import dns.resolver
import time
import hashlib
import re
import ssl
import urllib3
import subprocess
import platform
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, Back, init
from bs4 import BeautifulSoup
from tqdm import tqdm
from datetime import datetime
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

init(autoreset=True)

class OsintTool:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        self.web_paths = [
            '/robots.txt', '/sitemap.xml', '/admin', '/login', '/wp-admin',
            '/administrator', '/phpmyadmin', '/.git/config', '/.env',
            '/api', '/api/v1', '/api/v2', '/swagger', '/docs'
        ]
        self.technologies = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Joomla': ['com_content', 'com_users', 'Joomla!'],
            'Drupal': ['drupal.js', 'Drupal.settings'],
            'Laravel': ['laravel', 'Laravel', 'XSRF-TOKEN'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'React': ['react.js', 'react.development.js'],
            'Vue.js': ['vue.js', 'vue.min.js'],
            'Angular': ['ng-app', 'angular.js'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
            'jQuery': ['jquery.js', 'jquery.min.js']
        }

    def banner(self):
        print(Fore.CYAN + """
██╗    ██╗ ██████╗ ██████╗ ███████╗███████╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗
██║    ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝█████╗  █████╗      ███████║███████║██║     █████╔╝ 
██║███╗██║██║   ██║██╔══██╗██╔══╝  ██╔══╝      ██╔══██║██╔══██║██║     ██╔═██╗ 
╚███╔███╔╝╚██████╔╝██║  ██║██║     ███████╗    ██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                               

   




        ═══════════════════════════════════════════════
             ADVANCED OSINT INTELLIGENCE TOOL v2.0
        ═══════════════════════════════════════════════
        
        [+] Domain Analizi    [+] Port Tarama
        [+] Email İstihbarat  [+] DNS Kayıtları
        [+] Sosyal Medya      [+] Subdomain Tarama
        [+] Veri İhlali       [+] SSL Sertifika
        [+] Teknoloji Analizi [+] Güvenlik Testleri
        """ + Style.RESET_ALL)

    def check_ssl(self, domain):
        print(Fore.YELLOW + "\n[*] SSL/TLS Sertifika Analizi:" + Style.RESET_ALL)
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                print(f"\nSertifika Detayları:")
                print(f"  → Sağlayıcı: {dict(cert['issuer'])[('organizationName', )]}")
                print(f"  → Geçerlilik Başlangıç: {cert['notBefore']}")
                print(f"  → Geçerlilik Bitiş: {cert['notAfter']}")
                print(f"  → Alternatif İsimler: {', '.join(cert['subjectAltName'])}")
                
                # SSL/TLS Versiyon Kontrolü
                print("\nDesteklenen SSL/TLS Versiyonları:")
                versions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
                for version in versions:
                    try:
                        ctx = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{version.replace(".", "_")}'))
                        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                            s.connect((domain, 443))
                            print(f"  → {version}: " + Fore.GREEN + "Destekleniyor" + Style.RESET_ALL)
                    except:
                        print(f"  → {version}: " + Fore.RED + "Desteklenmiyor" + Style.RESET_ALL)
                
        except Exception as e:
            print(Fore.RED + f"[-] SSL analizi yapılamadı: {str(e)}" + Style.RESET_ALL)

    def detect_technologies(self, domain):
        print(Fore.YELLOW + "\n[*] Teknoloji Analizi:" + Style.RESET_ALL)
        detected = set()
        try:
            response = requests.get(f'https://{domain}', headers=self.headers, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Header kontrolü
            headers = response.headers
            if 'X-Powered-By' in headers:
                detected.add(f"Backend: {headers['X-Powered-By']}")
            if 'Server' in headers:
                detected.add(f"Web Server: {headers['Server']}")
            
            # Meta tag kontrolü
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                content = tag.get('content', '')
                if 'wordpress' in content.lower():
                    detected.add('CMS: WordPress')
                elif 'joomla' in content.lower():
                    detected.add('CMS: Joomla')
                elif 'drupal' in content.lower():
                    detected.add('CMS: Drupal')
            
            # JavaScript ve CSS dosyaları kontrolü
            for tech, patterns in self.technologies.items():
                for pattern in patterns:
                    if pattern.lower() in response.text.lower():
                        detected.add(f"Framework/Library: {tech}")
            
            if detected:
                print("\nTespit Edilen Teknolojiler:")
                for tech in detected:
                    print(f"  → {tech}")
            else:
                print("Belirgin bir teknoloji tespit edilemedi.")
                
        except Exception as e:
            print(Fore.RED + f"[-] Teknoloji analizi yapılamadı: {str(e)}" + Style.RESET_ALL)

    def check_security_headers(self, domain):
        print(Fore.YELLOW + "\n[*] Güvenlik Başlıkları Analizi:" + Style.RESET_ALL)
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking Koruması',
            'X-Content-Type-Options': 'MIME-sniffing Koruması',
            'X-XSS-Protection': 'XSS Koruması',
            'Referrer-Policy': 'Referrer Politikası'
        }
        
        try:
            response = requests.get(f'https://{domain}', headers=self.headers, verify=False, timeout=10)
            headers = response.headers
            
            print("\nGüvenlik Başlıkları:")
            for header, description in security_headers.items():
                if header in headers:
                    print(f"  → {description}: " + Fore.GREEN + "Var" + Style.RESET_ALL + f" ({headers[header]})")
                else:
                    print(f"  → {description}: " + Fore.RED + "Yok" + Style.RESET_ALL)
                    
        except Exception as e:
            print(Fore.RED + f"[-] Güvenlik başlıkları analizi yapılamadı: {str(e)}" + Style.RESET_ALL)

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def check_web_paths(self, domain):
        print(Fore.YELLOW + "\n[*] Hassas Dizin/Dosya Taraması:" + Style.RESET_ALL)
        found_paths = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in self.web_paths:
                url = f'https://{domain}{path}'
                futures.append(executor.submit(self.check_url, url))
            
            for future in tqdm(futures, desc="Dizinler kontrol ediliyor"):
                result = future.result()
                if result:
                    found_paths.append(result)
        
        if found_paths:
            print("\nBulunan Hassas Dizinler/Dosyalar:")
            for path in found_paths:
                print(f"  → {path}")
        else:
            print("Hassas dizin/dosya bulunamadı.")

    def check_url(self, url):
        try:
            response = requests.get(url, headers=self.headers, verify=False, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return f"{url} (Status: {response.status_code})"
        except:
            pass
        return None

    def domain_info(self, domain):
        try:
            print(Fore.GREEN + "\n[+] Detaylı Domain Analizi Başlatılıyor:" + Style.RESET_ALL)
            
            # IP adresi bulma
            print(Fore.YELLOW + "\n[*] IP Bilgileri:" + Style.RESET_ALL)
            ip = socket.gethostbyname(domain)
            print(f"Ana IP Adresi: {ip}")
            
            try:
                # Reverse DNS
                reverse_dns = socket.gethostbyaddr(ip)
                print(f"Reverse DNS: {reverse_dns[0]}")
            except:
                pass

            # WHOIS bilgileri
            print(Fore.YELLOW + "\n[*] WHOIS Bilgileri:" + Style.RESET_ALL)
            w = whois.whois(domain)
            print(f"Kayıt Tarihi: {w.creation_date}")
            print(f"Son Güncelleme: {w.updated_date}")
            print(f"Bitiş Tarihi: {w.expiration_date}")
            print(f"Registrar: {w.registrar}")
            print(f"Name Servers: {w.name_servers}")

            # DNS Kayıtları
            print(Fore.YELLOW + "\n[*] DNS Kayıtları:" + Style.RESET_ALL)
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
            for record in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record)
                    print(f"\n{record} kayıtları:")
                    for rdata in answers:
                        print(f"  → {rdata}")
                except Exception as e:
                    print(f"  → {record} kaydı bulunamadı")

            # Port Tarama
            print(Fore.YELLOW + "\n[*] Gelişmiş Port Taraması:" + Style.RESET_ALL)
            print("Yaygın portlar taranıyor...")
            
            open_ports = []
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port for port in self.common_ports.keys()}
                
                for future in tqdm(futures, desc="Portlar kontrol ediliyor"):
                    port = futures[future]
                    try:
                        if future.result():
                            service = self.common_ports[port]
                            open_ports.append((port, service))
                    except Exception:
                        continue
            
            if open_ports:
                print("\nAçık Portlar:")
                for port, service in sorted(open_ports):
                    print(f"  → Port {port}: {service}")
                    # Banner grabbing denemesi
                    try:
                        if port in [80, 8080]:
                            response = requests.get(f'http://{domain}:{port}', headers=self.headers, timeout=5)
                            server = response.headers.get('Server', 'Bilinmiyor')
                            print(f"    Banner: {server}")
                    except:
                        pass
            else:
                print("Hiç açık port bulunamadı.")

            # SSL Analizi
            if 443 in [p[0] for p in open_ports]:
                self.check_ssl(domain)

            # Teknoloji Analizi
            self.detect_technologies(domain)

            # Güvenlik Başlıkları Kontrolü
            self.check_security_headers(domain)

            # Hassas Dizin Taraması
            self.check_web_paths(domain)

        except Exception as e:
            print(Fore.RED + f"[-] Hata: {str(e)}" + Style.RESET_ALL)

    def check_email_breach(self, email):
        print(Fore.YELLOW + "\n[*] Veri İhlali Kontrolü Başlatılıyor..." + Style.RESET_ALL)
        
        # Email hash'ini al (SHA-1)
        email_hash = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
        prefix = email_hash[:5]
        suffix = email_hash[5:]
        
        # Pwned Passwords API'sini kontrol et
        try:
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        print(Fore.RED + f"[!] Bu email {count} kez veri ihlallerinde görülmüştür!" + Style.RESET_ALL)
                        return True
        except Exception as e:
            print(Fore.RED + f"[-] Pwned Passwords API hatası: {str(e)}" + Style.RESET_ALL)

        # Have I Been Pwned API kontrolü
        try:
            response = requests.get(
                f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                headers=self.hibp_headers
            )
            
            if response.status_code == 200:
                breaches = response.json()
                print(Fore.RED + f"\n[!] Bu email adresi {len(breaches)} veri ihlalinde bulundu:" + Style.RESET_ALL)
                for breach in breaches:
                    print(f"\nİhlal: {breach['Name']}")
                    print(f"Tarih: {breach['BreachDate']}")
                    print(f"Sızan Veri Türleri: {', '.join(breach['DataClasses'])}")
                    print(f"Açıklama: {breach['Description']}")
                return True
            elif response.status_code == 404:
                print(Fore.GREEN + "[+] Bu email adresi bilinen veri ihlallerinde bulunmadı!" + Style.RESET_ALL)
                return False
            else:
                print(Fore.YELLOW + f"[!] API yanıt kodu: {response.status_code}" + Style.RESET_ALL)
                
        except Exception as e:
            print(Fore.RED + f"[-] Have I Been Pwned API hatası: {str(e)}" + Style.RESET_ALL)

        return False

    def check_password_strength(self, email):
        # Email adresinden kullanıcı adını çıkar
        username = email.split('@')[0]
        
        # Yaygın zayıf parolalar listesi
        common_passwords = ['password', '123456', 'qwerty', 'admin', '12345678', 'welcome', 
                          username, username + '123', username + '12345']
        
        print(Fore.YELLOW + "\n[*] Olası Zayıf Parola Kontrolü:" + Style.RESET_ALL)
        
        for password in common_passwords:
            # Parolanın hash'ini al
            pass_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = pass_hash[:5]
            suffix = pass_hash[5:]
            
            try:
                response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
                if response.status_code == 200:
                    hashes = (line.split(':') for line in response.text.splitlines())
                    for h, count in hashes:
                        if h == suffix:
                            print(Fore.RED + f"[!] Dikkat: '{password}' parolası {count} kez veri ihlallerinde görülmüştür!" + Style.RESET_ALL)
                            print(Fore.RED + "[!] Bu tür basit parolaları kullanmaktan kaçının!" + Style.RESET_ALL)
            except Exception as e:
                continue

    def email_lookup(self, email):
        try:
            print(Fore.GREEN + "\n[+] Gelişmiş Email Araştırması Başlatılıyor:" + Style.RESET_ALL)
            domain = email.split('@')[1]
            
            # Email format kontrolü
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                print(Fore.RED + "[-] Geçersiz email formatı!" + Style.RESET_ALL)
                return
            
            # MX kayıtları kontrolü
            print(Fore.YELLOW + "\n[*] Mail Sunucu Analizi:" + Style.RESET_ALL)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                print("Mail Sunucuları:")
                for mx in mx_records:
                    print(f"  → Öncelik: {mx.preference}, Sunucu: {mx.exchange}")
            except:
                print("MX kayıtları bulunamadı")

            # SPF kaydı kontrolü
            print(Fore.YELLOW + "\n[*] SPF Kaydı Kontrolü:" + Style.RESET_ALL)
            try:
                spf = dns.resolver.resolve(domain, 'TXT')
                for record in spf:
                    if 'spf' in str(record).lower():
                        print(f"SPF Kaydı: {record}")
            except:
                print("SPF kaydı bulunamadı")

            # DMARC kaydı kontrolü
            print(Fore.YELLOW + "\n[*] DMARC Kaydı Kontrolü:" + Style.RESET_ALL)
            try:
                dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc:
                    print(f"DMARC Kaydı: {record}")
            except:
                print("DMARC kaydı bulunamadı")

            # Veri ihlali kontrolü
            self.check_email_breach(email)
            
            # Zayıf parola kontrolü
            self.check_password_strength(email)

            # Email güvenlik değerlendirmesi
            print(Fore.YELLOW + "\n[*] Email Güvenlik Değerlendirmesi:" + Style.RESET_ALL)
            security_score = 0
            checks = []
            
            if 'mx_records' in locals():
                security_score += 20
                checks.append("✓ MX kayıtları mevcut")
            if 'spf' in locals():
                security_score += 25
                checks.append("✓ SPF kaydı mevcut")
            if 'dmarc' in locals():
                security_score += 25
                checks.append("✓ DMARC kaydı mevcut")
            if not self.check_email_breach(email):
                security_score += 30
                checks.append("✓ Veri ihlallerinde bulunmadı")

            print(f"\nGüvenlik Skoru: {security_score}/100")
            for check in checks:
                print(check)

            # Güvenlik önerileri
            print(Fore.YELLOW + "\n[*] Güvenlik Önerileri:" + Style.RESET_ALL)
            if security_score < 50:
                print("⚠️  Email hesabınızın güvenliği düşük seviyede!")
                print("→ İki faktörlü doğrulama kullanmanız önerilir")
                print("→ Güçlü ve benzersiz bir parola kullanın")
                print("→ Email servis sağlayıcınızın güvenlik ayarlarını kontrol edin")
            elif security_score < 80:
                print("⚠️  Email hesabınızın güvenliği orta seviyede.")
                print("→ Güvenliği artırmak için ek önlemler alabilirsiniz")
            else:
                print("✅ Email hesabınızın güvenliği iyi seviyede!")

        except Exception as e:
            print(Fore.RED + f"[-] Hata: {str(e)}" + Style.RESET_ALL)

    def social_media_search(self, username):
        print(Fore.GREEN + "\n[+] Gelişmiş Sosyal Medya Araması:" + Style.RESET_ALL)
        social_networks = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Medium': f'https://medium.com/@{username}',
            'DeviantArt': f'https://deviantart.com/{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'VKontakte': f'https://vk.com/{username}',
            'Telegram': f'https://t.me/{username}'
        }

        print(Fore.YELLOW + "\n[*] Sosyal Medya Taraması Başlatılıyor..." + Style.RESET_ALL)
        print("Bu işlem birkaç dakika sürebilir...\n")

        results = {'found': [], 'not_found': [], 'error': []}
        
        def check_url(platform, url):
            try:
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    if platform == 'GitHub':
                        soup = BeautifulSoup(response.text, 'html.parser')
                        if soup.find('div', {'class': '404'}):
                            results['not_found'].append(platform)
                            return
                    results['found'].append((platform, url))
                else:
                    results['not_found'].append(platform)
            except:
                results['error'].append(platform)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for platform, url in social_networks.items():
                futures.append(executor.submit(check_url, platform, url))
            
            for _ in tqdm(futures, desc="Profiller kontrol ediliyor"):
                pass

        if results['found']:
            print(Fore.GREEN + "\n[+] Bulunan Profiller:" + Style.RESET_ALL)
            for platform, url in results['found']:
                print(f"✓ {platform}: {url}")

        if results['not_found']:
            print(Fore.YELLOW + "\n[-] Bulunmayan Profiller:" + Style.RESET_ALL)
            for platform in results['not_found']:
                print(f"× {platform}")

        if results['error']:
            print(Fore.RED + "\n[!] Kontrol Edilemeyen Profiller:" + Style.RESET_ALL)
            for platform in results['error']:
                print(f"? {platform}")

    def subdomain_scan(self, domain):
        print(Fore.GREEN + "\n[+] Subdomain Taraması Başlatılıyor:" + Style.RESET_ALL)
        subdomains = set()
        
        # Yaygın subdomain listesi
        common_subdomains = ['www', 'mail', 'ftp', 'smtp', 'pop', 'api', 'dev', 'staging', 
                           'admin', 'blog', 'shop', 'store', 'web', 'secure', 'vpn', 'cloud',
                           'm', 'mobile', 'app', 'test', 'portal', 'cdn', 'images', 'img']

        print(Fore.YELLOW + "\n[*] DNS Kayıtları Üzerinden Tarama:" + Style.RESET_ALL)
        for sub in tqdm(common_subdomains, desc="Subdomain taranıyor"):
            try:
                host = f"{sub}.{domain}"
                ip = socket.gethostbyname(host)
                subdomains.add((host, ip))
            except:
                continue

        if subdomains:
            print("\nBulunan Subdomainler:")
            for subdomain, ip in sorted(subdomains):
                print(f"  → {subdomain} ({ip})")
        else:
            print("Hiç subdomain bulunamadı.")


