import requests
from bs4 import BeautifulSoup
from collections import deque
from urllib.parse import urlparse, urljoin
import socket
import warnings
import re
from bs4 import XMLParsedAsHTMLWarning
import argparse
import csv
import whois
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def Skanner_title(html_text):
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            if len(title) > 30:
                return title[:27] + "..."
            return title
        else:
            return "No Title"
    except Exception:
        return "No Title"
import re

import re

def skanner_email_and_phone(text):

    email_pattern = r'[a-zA-Z0-9_.+-]+@gmail\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)

    phone_pattern = r"(?:\+98|0098|0)?(9\d{9})\b"
    raw_phones = re.findall(phone_pattern, text)
    valid_phones = []
    for number in raw_phones:
        valid_phones.append("0" + number)
    unique_emails = []
    for email in emails:
        if email not in unique_emails:
            unique_emails.append(email)

    unique_phones = []
    for phone in valid_phones:
        if phone not in unique_phones:
            unique_phones.append(phone)
    if unique_emails:
        unique_emails.sort()
        emails_str = ", ".join(unique_emails)
    else:
        emails_str = "No email found"

    if unique_phones:
        unique_phones.sort()
        phones_str = ", ".join(unique_phones)
    else:
        phones_str = "No valid Iranian phone number found"

    return emails_str, phones_str



def all_urls_depth2(start_url, max_depth=2):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

    BLOCKED_DOMAINS = ["instagram.com", "linkedin.com", "twitter.com", "facebook.com", "t.me",
                       "youtube.com", "cyberpolice.ir", "youtu.be", "l.vrgl.ir", "x.com",
                       "www.netspi.com", "book.hacktricks.xyz"]
    site_map = {}
    visited = set()

    queue = deque()
    queue.append((start_url, 0))

    while queue:
        url, depth_level = queue.popleft()

        if depth_level > max_depth or url in visited:
            continue

        visited.add(url)
        links = []

        try:
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = tag.get("href").strip()
                full_url = urljoin(url, href)

                is_http = full_url.startswith("http")
                is_not_blocked = not any(domain in full_url for domain in BLOCKED_DOMAINS)
                is_not_visited = full_url not in visited
          
           

                if is_http and is_not_blocked and is_not_visited:
                    links.append(full_url)
                    
       
        except requests.exceptions.RequestException as e:
            print(f"[❌] Failed to fetch {url}: {e}")

        site_map[url] = sorted(links)
        for link in links:
            if link not in visited:
                queue.append((link, depth_level + 1))

    return site_map
def shorten_text(text, max_len=30):
    if len(text) <= max_len:
        return text
    return text[:15] + "..." + text[-12:]

def print_urls(numbered_urls, domain, output_file="ipsocket.txt"):
    with open(output_file, "a", encoding="utf-8") as out_file:
        out_file.write(
            "| {:<5} | {:<50} | {:<15} | {:<6} | {:<8} | {:<30} | {:<30} | {:<20} |\n".format(
                "Index", "URL", "IP Address", "Status", "Type", "Title", "Emails", "Phones"
            )
        )
        out_file.write("-" * 205 + "\n")

        print("\n--- URL Table with IP, Status, Title, Emails & Phones ---")
        print("| {:<5} | {:<50} | {:<15} | {:<6} | {:<8} | {:<30} | {:<30} | {:<20} |".format(
            "Index", "URL", "IP Address", "Status", "Type", "Title", "Emails", "Phones"
        ))
        print("-" * 205)

        for index, url in numbered_urls.items():
            try:
                domain_name = urlparse(url).hostname
                ip_address = socket.gethostbyname(domain_name)
            except Exception:
                ip_address = "⛔️ Not Resolved"
                domain_name = None

            try:
                main_domain = urlparse("https://" + domain).hostname
                if domain_name and main_domain and domain_name.endswith(main_domain):
                    domain_type = "داخلی"
                else:
                    domain_type = "🌍 خارجی"
            except:
                domain_type = "نامشخص"

            try:
                response = requests.get(url, timeout=5)
                status = response.status_code
                title_tag = Skanner_title(response.text)
                emails, phones = skanner_email_and_phone(response.text)
            except Exception:
                status = "⚠️ Error"
                title_tag = "No Title"
                emails = "No email found"
                phones = "No phone found"

            # url_display = shorten_text(url, 50)
            # title_display = shorten_text(title_tag, 30)
            # emails_display = shorten_text(emails, 30)
            # phones_display = shorten_text(phones, 20)
            url_display = url
            title_display = title_tag
            emails_display = emails
            phones_display = phones

            line = "| {:<5} | {:<50} | {:<15} | {:<6} | {:<8} | {:<30} | {:<30} | {:<20} |".format(
                index, url_display, ip_address, str(status), domain_type,
                title_display, emails_display, phones_display
            )

            print(line)
            out_file.write(line + "\n")



def scan_subdomains(domain, input_file="wordlist.txt", output_file="ipsocket.txt"):
    PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    
    count_movafaq = 0
    try:
        with open(output_file, "a", encoding="utf-8") as out_file:
            try:
                with open(input_file, "r", encoding="utf-8") as file:
                    for line in file:
                        sub = line.strip()
                        if not sub:
                            continue

                        full_domain = f"{sub}.{domain}"

                        try:
                            ip = socket.gethostbyname(full_domain)
                        except socket.gaierror:
                            ip = None

                        if ip is None:                    
                            continue  

                        status = "N/A"
                        title_tag = "No Title"
                        try:
                            response = requests.get(f"https://{full_domain}", timeout=5)
                            status = response.status_code
                            title_tag = Skanner_title(response.text)
                        except requests.exceptions.RequestException:
                            try:
                                response = requests.get(f"http://{full_domain}", timeout=5)
                                status = response.status_code
                                title_tag = Skanner_title(response.text)
                            except requests.exceptions.RequestException:
                                status = "⚠️ No Response"
                                title_tag = "No Title"

                        if len(title_tag) > 40:
                            title_tag = title_tag[:37] + "..."

                        open_ports = []
                        for port in PORTS:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(0.5)
                            try:
                                s.connect((ip, port))
                                open_ports.append(port)
                            except:
                                pass
                            finally:
                                s.close()

                        if open_ports:
                            ports_info = "Open ports: " + ", ".join(str(p) for p in open_ports)
                        else:
                            ports_info = "No open ports"

                        count_movafaq += 1
                        print(f"{count_movafaq} [✅] {full_domain} → {ip} | Status: {status} | Open Ports: {ports_info} | Title: {title_tag}")
                        out_file.write(f"{count_movafaq}  {full_domain}  {ip}  {status}  Ports: {ports_info}  Title: {title_tag}\n")

            except FileNotFoundError:
                print(f"File {input_file} not found.")
    except Exception as e:
        print(f"Error opening output file: {e}")

def get_whois_info(domain):
    print("\n--- WHOIS Info ---")
    try:
        w = whois.whois(domain)
        print(f"Domain: {domain}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Name Servers: {w.name_servers}")
        print(f"Emails: {w.emails}")
        print(f"Country: {w.country}")
    except Exception as e:
        print(f"Failed to fetch WHOIS info: {e}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Crawler & Subdomain Scanner")
    parser.add_argument("--domain", required=True, help="Website domain without https:// (e.g. example.com)")
    args = parser.parse_args()

    domain = args.domain.strip()
    start_url = "https://" + domain

    site_map = all_urls_depth2(start_url, max_depth=2)

    counter = 1
    numbered_urls = {}
    seen_urls = set()

    for url, links in site_map.items():
        if url not in seen_urls:
            numbered_urls[counter] = url
            counter += 1
            seen_urls.add(url)

        for link in links:
            if link not in seen_urls:
                numbered_urls[counter] = link
                counter += 1
                seen_urls.add(link)

    print_urls(numbered_urls, domain)


    get_whois_info(domain)

    scan_subdomains(domain, output_file="ipsocket.txt")


