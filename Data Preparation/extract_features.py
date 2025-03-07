import pandas as pd
import re
from urllib.parse import urlparse,urljoin
import socket
import time
from bs4 import BeautifulSoup
import requests

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None


def full_url_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="full_url_length", value=df["URL"].apply(len))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'full_url_length' added.")

def hostname_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_hostname_length(url):
        match = re.search(r'^(?:https?://)?([^/]+)', url)
        return len(match.group(1)) if match else 0
    df.insert(loc=df.columns.get_loc("Label"), column="hostname_length", value=df["URL"].apply(get_hostname_length))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'hostname_length' added.")

def directory_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_directory_length(url):
        match = re.search(r'^(?:https?://)?[^/]+(?P<path>/.*)?$', url)
        if match:
            path = match.group("path") or ""
            if path and not path.endswith('/'):
                parts = path.rsplit('/', 1)
                if len(parts) == 2:
                    return len(parts[0] + '/')
                else:
                    return 0
            else:
                return len(path)
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="directory_length", value=df["URL"].apply(get_directory_length))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'directory_length' added.")

def file_name_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_file_name_length(url):
        match = re.search(r'^(?:https?://)?[^/]+(?P<path>/.*)?$', url)
        if match:
            path = match.group("path") or ""
            # If path exists and does not end with '/', assume the last segment is the file name.
            if path and not path.endswith('/'):
                parts = path.rsplit('/', 1)
                if len(parts) == 2:
                    return len(parts[1])
                else:
                    return 0
            else:
                return 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="file_name_length", value=df["URL"].apply(get_file_name_length))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'file_name_length' added.")

def parameters_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Look for the query part (after the '?') and return its length.
    def get_parameters_length(url):
        match = re.search(r'\?(.*)$', url)
        return len(match.group(1)) if match else 0
    df.insert(loc=df.columns.get_loc("Label"), column="parameters_length", value=df["URL"].apply(get_parameters_length))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'parameters_length' added.")

def tld_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Get the top-level domain from the hostname and return its length.
    def get_tld_length(url):
        match = re.search(r'^(?:https?://)?([^/]+)', url)
        if match:
            domain = match.group(1)
            tld_match = re.search(r'\.([a-zA-Z0-9]+)$', domain)
            if tld_match:
                return len(tld_match.group(1))
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="tld_length", value=df["URL"].apply(get_tld_length))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'tld_length' added.")


def add_special_char_count(feature_name, pattern):
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column=feature_name,
              value=df["URL"].apply(lambda x: len(re.findall(pattern, x))))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print(f"Feature '{feature_name}' added.")

def dot_count():
    add_special_char_count("dot_count", r'\.')

def hyphen_count():
    add_special_char_count("hyphen_count", r'-')

def underscore_count():
    add_special_char_count("underscore_count", r'_')

def slash_count():
    add_special_char_count("slash_count", r'/')

def question_mark_count():
    add_special_char_count("question_mark_count", r'\?')

def equal_count():
    add_special_char_count("equal_count", r'=')

def at_count():
    add_special_char_count("at_count", r'@')

def ampersand_count():
    add_special_char_count("ampersand_count", r'&')

def exclamation_count():
    add_special_char_count("exclamation_count", r'!')

def vertical_bar_count():
    add_special_char_count("vertical_bar_count", r'\|')

def colon_count():
    add_special_char_count("colon_count", r':')

def semicolon_count():
    add_special_char_count("semicolon_count", r';')

def space_count():
    add_special_char_count("space_count", r' ')

def tilde_count():
    add_special_char_count("tilde_count", r'˜')

def comma_count():
    add_special_char_count("comma_count", r',')

def plus_count():
    add_special_char_count("plus_count", r'\+')

def asterisk_count():
    add_special_char_count("asterisk_count", r'\*')

def hashtag_count():
    add_special_char_count("hashtag_count", r'#')

def dollar_count():
    add_special_char_count("dollar_count", r'\$')

def percent_count():
    add_special_char_count("percent_count", r'%')


def common_term_occurrence(term, pattern, column_name):
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column=column_name,
              value=df["URL"].apply(lambda x: len(re.findall(pattern, x, re.IGNORECASE))))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print(f"Feature '{column_name}' added.")

def www_occurrence():
    common_term_occurrence("www", r'www', "www_occurrence")

def com_occurrence():
    common_term_occurrence(".com", r'\.com', "com_occurrence")

def http_occurrence():
    common_term_occurrence("http", r'http', "http_occurrence")

def double_slash_occurrence():
    common_term_occurrence("//", r'//', "double_slash_occurrence")

def email_in_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Check if an email pattern exists in the URL.
    email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    df.insert(loc=df.columns.get_loc("Label"), column="email_in_url",
              value=df["URL"].apply(lambda x: 1 if re.search(email_pattern, x) else 0))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'email_in_url' added.")



def https_token():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Returns 1 if the URL starts with "https://", else 0.
    df.insert(loc=df.columns.get_loc("Label"), column="https_token",
              value=df["URL"].apply(lambda x: 1 if x.lower().startswith("https://") else 1))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'https_token' added.")

def ip_address_in_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_ip(url):
        m = re.search(r'^(?:https?://)?((?:\d{1,3}\.){3}\d{1,3})', url)
        return 1 if m else 0
    df.insert(loc=df.columns.get_loc("Label"), column="ip_address_in_url",
              value=df["URL"].apply(check_ip))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'ip_address_in_url' added.")

def punycode_usage():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Checks if the domain contains "xn--", which indicates punycode usage.
    def check_punycode(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            return 1 if "xn--" in domain.lower() else 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="punycode_usage",
              value=df["URL"].apply(check_punycode))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'punycode_usage' added.")

def port_number_presence():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Checks if a port number is specified (e.g., :80, :443) after the domain.
    def check_port(url):
        m = re.search(r'^(?:https?://)?[^/]+:(\d+)', url)
        return 1 if m else 0
    df.insert(loc=df.columns.get_loc("Label"), column="port_number_presence",
              value=df["URL"].apply(check_port))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'port_number_presence' added.")

def tld_in_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Check if a TLD-like pattern appears in the path portion.
    def check_tld_in_path(url):
        parsed = urlparse(url)
        path = parsed.path
        # Look for a dot followed by 2-6 alphabetic characters in the path.
        if re.search(r'\.[a-zA-Z]{2,6}', path):
            return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="tld_in_path",
              value=df["URL"].apply(check_tld_in_path))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'tld_in_path' added.")

def tld_in_subdomain():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # Check if any subdomain part contains a TLD-like pattern.
    def check_tld_in_subdomain(url):
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  
        parts = domain.split('.')
        if len(parts) > 2:
            subdomains = parts[:-2]
            for sub in subdomains:
                if re.fullmatch(r'[a-zA-Z]{2,6}', sub):
                    return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="tld_in_subdomain",
              value=df["URL"].apply(check_tld_in_subdomain))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'tld_in_subdomain' added.")

def abnormal_subdomains():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_abnormal_subdomains(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            parts = domain.split('.')
            if len(parts) > 2:
                for part in parts[:-2]:
                    if re.search(r'\d', part) and part.lower() != "www":
                        return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="abnormal_subdomains",
              value=df["URL"].apply(check_abnormal_subdomains))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'abnormal_subdomains' added.")

def number_of_subdomains():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_subdomains(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            parts = domain.split('.')
            if len(parts) > 2:
                return len(parts) - 2
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="number_of_subdomains",
              value=df["URL"].apply(count_subdomains))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'number_of_subdomains' added.")

def prefix_suffix_hyphen():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_prefix_suffix(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            return 1 if '-' in domain else 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="prefix_suffix_hyphen",
              value=df["URL"].apply(check_prefix_suffix))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'prefix_suffix_hyphen' added.")

def random_domain_indicator():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_random_domain(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            domain = domain.split(':')[0]
            domain = re.sub(r'^www\.', '', domain)
            parts = domain.split('.')
            main = "".join(parts[:-1]) if len(parts) > 1 else parts[0]
            if len(main) == 0:
                return 0
            vowels = re.findall(r'[aeiou]', main, re.IGNORECASE)
            ratio = len(vowels) / len(main)
            return 1 if ratio < 0.3 else 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="random_domain_indicator",
              value=df["URL"].apply(check_random_domain))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'random_domain_indicator' added.")

def url_shortening_service():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly", 
                  "adf.ly", "bit.do", "cutt.ly", "is.gd", "soo.gd", "s2r.co", "clicky.me"]
    def check_shortener(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1).lower()
            for short in shorteners:
                if short in domain:
                    return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="url_shortening_service",
              value=df["URL"].apply(check_shortener))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'url_shortening_service' added.")

def path_extension_check():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    suspicious_exts = [".exe", ".js"]
    def check_path_ext(url):
        m = re.search(r'^(?:https?://)?[^/]+(?P<path>/.*)$', url)
        if m:
            path = m.group("path").lower()
            for ext in suspicious_exts:
                if path.endswith(ext):
                    return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="path_extension_check",
              value=df["URL"].apply(check_path_ext))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'path_extension_check' added.")

def suspicious_tld():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    suspicious_list = ["tk", "ml", "ga", "cf", "gq"]
    def check_suspicious_tld(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            tld_match = re.search(r'\.([a-zA-Z0-9]+)$', domain)
            if tld_match:
                tld = tld_match.group(1).lower()
                return 1 if tld in suspicious_list else 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="suspicious_tld",
              value=df["URL"].apply(check_suspicious_tld))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'suspicious_tld' added.")

def statistical_report():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    top_phishing_ips = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
    
    def check_statistical_report(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            ips = socket.gethostbyname_ex(domain)[2]
            for ip in ips:
                if ip in top_phishing_ips:
                    return 1
            return 0
        except Exception as e:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="statistical_report",
              value=df["URL"].apply(check_statistical_report))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'statistical_report' added.")

def digit_ratio_full_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="digit_ratio_full_url",
              value=df["URL"].apply(lambda x: sum(c.isdigit() for c in x) / len(x) if len(x) > 0 else 0))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'digit_ratio_full_url' added.")

def digit_ratio_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def calc_digit_ratio(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1)
            return sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="digit_ratio_hostname",
              value=df["URL"].apply(calc_digit_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'digit_ratio_hostname' added.")


def parse_url_components(url):
    parsed = urlparse(url)
    return parsed.netloc, parsed.path

def max_consecutive_repeat(s):
    max_repeat = 0
    for m in re.finditer(r'(.)\1+', s):
        repeat_length = m.end() - m.start()
        if repeat_length > max_repeat:
            max_repeat = repeat_length
    return max_repeat

def shortest_word(text):
    words = re.findall(r'\w+', text)
    return min(len(w) for w in words) if words else 0

def longest_word(text):
    words = re.findall(r'\w+', text)
    return max(len(w) for w in words) if words else 0

def average_word_length(text):
    words = re.findall(r'\w+', text)
    return sum(len(w) for w in words) / len(words) if words else 0

def word_count_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="word_count_url",
              value=df["URL"].apply(lambda x: len(re.findall(r'\w+', x))))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'word_count_url' added.")

def word_count_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_host_words(url):
        hostname, _ = parse_url_components(url)
        return len(re.findall(r'\w+', hostname))
    df.insert(loc=df.columns.get_loc("Label"), column="word_count_hostname",
              value=df["URL"].apply(count_host_words))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'word_count_hostname' added.")

def word_count_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_path_words(url):
        _, path = parse_url_components(url)
        return len(re.findall(r'\w+', path))
    df.insert(loc=df.columns.get_loc("Label"), column="word_count_path",
              value=df["URL"].apply(count_path_words))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'word_count_path' added.")


def char_repeat_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="char_repeat_url",
              value=df["URL"].apply(lambda x: max_consecutive_repeat(x)))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'char_repeat_url' added.")

def char_repeat_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def repeat_hostname(url):
        hostname, _ = parse_url_components(url)
        return max_consecutive_repeat(hostname)
    df.insert(loc=df.columns.get_loc("Label"), column="char_repeat_hostname",
              value=df["URL"].apply(repeat_hostname))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'char_repeat_hostname' added.")

def char_repeat_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def repeat_path(url):
        _, path = parse_url_components(url)
        return max_consecutive_repeat(path)
    df.insert(loc=df.columns.get_loc("Label"), column="char_repeat_path",
              value=df["URL"].apply(repeat_path))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'char_repeat_path' added.")


def shortest_word_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="shortest_word_url",
              value=df["URL"].apply(lambda x: shortest_word(x)))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'shortest_word_url' added.")

def shortest_word_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def shortest_host(url):
        hostname, _ = parse_url_components(url)
        return shortest_word(hostname)
    df.insert(loc=df.columns.get_loc("Label"), column="shortest_word_hostname",
              value=df["URL"].apply(shortest_host))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'shortest_word_hostname' added.")

def shortest_word_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def shortest_path(url):
        _, path = parse_url_components(url)
        return shortest_word(path)
    df.insert(loc=df.columns.get_loc("Label"), column="shortest_word_path",
              value=df["URL"].apply(shortest_path))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'shortest_word_path' added.")


def longest_word_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="longest_word_url",
              value=df["URL"].apply(lambda x: longest_word(x)))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'longest_word_url' added.")

def longest_word_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def longest_host(url):
        hostname, _ = parse_url_components(url)
        return longest_word(hostname)
    df.insert(loc=df.columns.get_loc("Label"), column="longest_word_hostname",
              value=df["URL"].apply(longest_host))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'longest_word_hostname' added.")

def longest_word_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def longest_path(url):
        _, path = parse_url_components(url)
        return longest_word(path)
    df.insert(loc=df.columns.get_loc("Label"), column="longest_word_path",
              value=df["URL"].apply(longest_path))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'longest_word_path' added.")


def average_word_length_url():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="average_word_length_url",
              value=df["URL"].apply(lambda x: average_word_length(x)))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'average_word_length_url' added.")

def average_word_length_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def avg_length_hostname(url):
        hostname, _ = parse_url_components(url)
        return average_word_length(hostname)
    df.insert(loc=df.columns.get_loc("Label"), column="average_word_length_hostname",
              value=df["URL"].apply(avg_length_hostname))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'average_word_length_hostname' added.")

def average_word_length_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def avg_length_path(url):
        _, path = parse_url_components(url)
        return average_word_length(path)
    df.insert(loc=df.columns.get_loc("Label"), column="average_word_length_path",
              value=df["URL"].apply(avg_length_path))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'average_word_length_path' added.")

def phish_hints():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # List of suspicious keywords commonly seen in phishing URLs.
    phish_words = ["login", "admin", "signin", "wp", "includes", "content", "site", 
                   "images", "js", "alibaba", "css", "myaccount", "dropbox", "themes", "plugins", "view"]
    def count_phish_words(url):
        count = 0
        for word in phish_words:
            count += len(re.findall(word, url, re.IGNORECASE))
        return count
    df.insert(loc=df.columns.get_loc("Label"), column="phish_hints",
              value=df["URL"].apply(count_phish_words))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'phish_hints' added.")



def brand_in_domain():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    # List of known brand names (example list; modify as needed)
    brands = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal", "linkedin", "twitter",
    "instagram", "whatsapp", "youtube", "tiktok", "snapchat", "reddit", "spotify", "uber", "airbnb",
    "tesla", "samsung", "nvidia", "intel", "amd", "adobe", "oracle", "salesforce", "zoom", "ebay",
    "yahoo", "bing", "wechat", "alibaba", "baidu", "discord", "twitch", "dropbox", "slack", "github",
    "gitlab", "atlassian", "wordpress", "pinterest", "stripe", "shopify", "tesco", "walmart", "target",
    "nike", "adidas", "puma", "huawei", "xiaomi", "oneplus", "dell", "hp", "lenovo", "cisco", "ibm",
    "sony", "lg", "pepsi", "coca-cola", "starbucks", "mcdonalds", "kfc", "burgerking", "dominos",
    "subway", "zomato", "swiggy", "doordash", "ubereats", "lyft", "tesla", "ford", "bmw", "audi",
    "mercedes", "toyota", "honda", "hyundai", "volkswagen", "nissan", "porsche", "ferrari", "lamborghini"
    ]

    def check_brand(url):
        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1).lower()
            for brand in brands:
                if brand in domain:
                    return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="brand_in_domain",
              value=df["URL"].apply(check_brand))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'brand_in_domain' added.")

def brand_in_subdomain():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    brands = [
        "google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal", "linkedin", "twitter",
        "instagram", "whatsapp", "youtube", "tiktok", "snapchat", "reddit", "spotify", "uber", "airbnb",
        "tesla", "samsung", "nvidia", "intel", "amd", "adobe", "oracle", "salesforce", "zoom", "ebay",
        "yahoo", "bing", "wechat", "alibaba", "baidu", "discord", "twitch", "dropbox", "slack", "github",
        "gitlab", "atlassian", "wordpress", "pinterest", "stripe", "shopify", "tesco", "walmart", "target",
        "nike", "adidas", "puma", "huawei", "xiaomi", "oneplus", "dell", "hp", "lenovo", "cisco", "ibm",
        "sony", "lg", "pepsi", "coca-cola", "starbucks", "mcdonalds", "kfc", "burgerking", "dominos",
        "subway", "zomato", "swiggy", "doordash", "ubereats", "lyft", "ford", "bmw", "audi",
        "mercedes", "toyota", "honda", "hyundai", "volkswagen", "nissan", "porsche", "ferrari", "lamborghini"
    ]
    def check_brand_subdomain(url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        parts = domain.split('.')
        # If there are more than two parts, subdomains exist.
        subdomains = parts[:-2] if len(parts) > 2 else []
        for sub in subdomains:
            for brand in brands:
                if brand in sub:
                    return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="brand_in_subdomain",
              value=df["URL"].apply(check_brand_subdomain))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'brand_in_subdomain' added.")

def brand_in_path():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    brands = [
        "google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal", "linkedin", "twitter",
        "instagram", "whatsapp", "youtube", "tiktok", "snapchat", "reddit", "spotify", "uber", "airbnb",
        "tesla", "samsung", "nvidia", "intel", "amd", "adobe", "oracle", "salesforce", "zoom", "ebay",
        "yahoo", "bing", "wechat", "alibaba", "baidu", "discord", "twitch", "dropbox", "slack", "github",
        "gitlab", "atlassian", "wordpress", "pinterest", "stripe", "shopify", "tesco", "walmart", "target",
        "nike", "adidas", "puma", "huawei", "xiaomi", "oneplus", "dell", "hp", "lenovo", "cisco", "ibm",
        "sony", "lg", "pepsi", "coca-cola", "starbucks", "mcdonalds", "kfc", "burgerking", "dominos",
        "subway", "zomato", "swiggy", "doordash", "ubereats", "lyft", "ford", "bmw", "audi",
        "mercedes", "toyota", "honda", "hyundai", "volkswagen", "nissan", "porsche", "ferrari", "lamborghini"
    ]
    def check_brand_path(url):
        parsed = urlparse(url)
        path = parsed.path.lower()
        for brand in brands:
            if brand in path:
                return 1
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="brand_in_path",
              value=df["URL"].apply(check_brand_path))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'brand_in_path' added.")

def get_title_from_url(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url 
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        return soup.title.string.strip() if soup.title else "-1"
    except Exception:
        return "-1"

def domain_in_title():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_domain_in_title(row):
        url = row["URL"]
        title = get_title_from_url(url)  
        if title == "-1": 
            return -1

        m = re.search(r'^(?:https?://)?([^/]+)', url)
        if m:
            domain = m.group(1).lower()
            return 1 if domain in title.lower() else 0
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="domain_in_title",
              value=df.apply(check_domain_in_title, axis=1))
    
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_in_title' added.")

def fetch_page(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        return response
    except Exception as e:
        return None

def redirection_count():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_redirection_count(url):
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            return len(response.history)
        except:
            return -1  # Use -1 for error cases
    
    df.insert(loc=df.columns.get_loc("Label"), column="redirection_count",
              value=df["URL"].apply(get_redirection_count))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'redirection_count' added.")

def external_redirection_count():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_external_redirect_count(url):
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            original_domain = urlparse(url).netloc
            count = 0
            for resp in response.history:
                redirected_domain = urlparse(resp.url).netloc
                if redirected_domain and (redirected_domain != original_domain):
                    count += 1
            return count
        except:
            return -1
          
    df.insert(loc=df.columns.get_loc("Label"), column="external_redirection_count",
              value=df["URL"].apply(get_external_redirect_count))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_redirection_count' added.")

def internal_redirection_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_internal_ratio(url):
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            total = len(response.history)
            if total == 0:
                return 0
            original_domain = urlparse(url).netloc
            internal = 0
            for resp in response.history:
                redirected_domain = urlparse(resp.url).netloc
                if redirected_domain == original_domain:
                    internal += 1
            return internal / total
        except:
            return -1
    
    df.insert(loc=df.columns.get_loc("Label"), column="internal_redirection_ratio",
              value=df["URL"].apply(get_internal_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'internal_redirection_ratio' added.")

def external_redirection_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_external_ratio(url):
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            total = len(response.history)
            if total == 0:
                return 0
            original_domain = urlparse(url).netloc
            external = 0
            for resp in response.history:
                redirected_domain = urlparse(resp.url).netloc
                if redirected_domain and (redirected_domain != original_domain):
                    external += 1
            return external / total
        except:
            return -1
    
    df.insert(loc=df.columns.get_loc("Label"), column="external_redirection_ratio",
              value=df["URL"].apply(get_external_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_redirection_ratio' added.")

def fetch_page(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response
    except Exception:
        return None
    return None

def count_links(url):
    try:
        response = fetch_page(url)
        if not response:
            return 0, 0, 0
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)
        if not links:
            return 0, 0, 0
        internal = 0
        external = 0
        domain = urlparse(url).netloc
        for link in links:
            href = link.get("href")
            parsed = urlparse(href)
            if parsed.netloc == "" or parsed.netloc == domain:
                internal += 1
            else:
                external += 1
        total = len(links)
        return internal, external, total
    except Exception:
        return 0, 0, 0

def internal_hyperlink_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def compute_internal(url):
        internal, external, total = count_links(url)
        return internal / total if total > 0 else 0
    
    # Insert the new column before 'Label'
    df.insert(loc=df.columns.get_loc("Label"), column="internal_hyperlink_ratio", 
              value=df["URL"].apply(compute_internal))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'internal_hyperlink_ratio' added.")

def external_hyperlink_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def compute_external(url):
        internal, external, total = count_links(url)
        return external / total if total > 0 else 0
    
    # Insert the new column before 'Label'
    df.insert(loc=df.columns.get_loc("Label"), column="external_hyperlink_ratio", 
              value=df["URL"].apply(compute_external))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_hyperlink_ratio' added.")

def null_hyperlinks_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_null_ratio(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", href=True)
            if not links:
                return 0
            null_count = 0
            for link in links:
                href = link['href'].strip().lower()
                if href in ["", "#", "javascript:void(0)"]:
                    null_count += 1
            return null_count / len(links)
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="null_hyperlinks_ratio",
              value=df["URL"].apply(get_null_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'null_hyperlinks_ratio' added.")

def media_links_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_media_ratio(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            original_domain = urlparse(url).netloc
            media_tags = soup.find_all(["img", "video", "audio"])
            if not media_tags:
                return 0
            internal = 0
            external = 0
            for tag in media_tags:
                src = tag.get("src", "")
                parsed = urlparse(src)
                if parsed.netloc == "" or parsed.netloc == original_domain:
                    internal += 1
                else:
                    external += 1
            total = internal + external
            return internal / total if total > 0 else 0
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="media_links_ratio",
              value=df["URL"].apply(get_media_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'media_links_ratio' added.")

def internal_media_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_internal_media_ratio(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            # Gather media elements: <img>, <video>, and <audio>
            media_tags = soup.find_all("img", src=True)
            media_tags += soup.find_all("video", src=True)
            media_tags += soup.find_all("audio", src=True)
            if not media_tags:
                return 0  # No media found
            original_domain = urlparse(url).netloc
            internal_count = 0
            for tag in media_tags:
                src = tag.get("src")
                full_url = urljoin(url, src)
                media_domain = urlparse(full_url).netloc
                if media_domain == original_domain:
                    internal_count += 1
            return internal_count / len(media_tags)
        except Exception:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="internal_media_ratio",
              value=df["URL"].apply(get_internal_media_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'internal_media_ratio' added.")

def external_media_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_external_media_ratio(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            # Gather media elements: <img>, <video>, and <audio>
            media_tags = soup.find_all("img", src=True)
            media_tags += soup.find_all("video", src=True)
            media_tags += soup.find_all("audio", src=True)
            if not media_tags:
                return 0  # No media found
            original_domain = urlparse(url).netloc
            external_count = 0
            for tag in media_tags:
                src = tag.get("src")
                full_url = urljoin(url, src)
                media_domain = urlparse(full_url).netloc
                # Count as external if the domain differs and is not empty.
                if media_domain and media_domain != original_domain:
                    external_count += 1
            return external_count / len(media_tags)
        except Exception:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="external_media_ratio",
              value=df["URL"].apply(get_external_media_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_media_ratio' added.")

def internal_errors_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_internal_error_ratio(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a", href=True)
            if not links:
                return 0
            original_domain = urlparse(url).netloc
            internal_links = []
            for link in links:
                href = link["href"].strip()
                parsed = urlparse(href)
                if parsed.netloc == "" or parsed.netloc == original_domain:
                    # Resolve relative URLs.
                    full_url = urljoin(url, href)
                    internal_links.append(full_url)
            if not internal_links:
                return 0
            error_count = 0
            for link in internal_links:
                try:
                    head = requests.head(link, timeout=5)
                    if head.status_code >= 400:
                        error_count += 1
                except:
                    error_count += 1
            return error_count / len(internal_links)
        except:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="internal_errors_ratio",
              value=df["URL"].apply(get_internal_error_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'internal_errors_ratio' added.")

def external_errors_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_external_error_ratio(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a", href=True)
            if not links:
                return 0
            original_domain = urlparse(url).netloc
            external_links = []
            for link in links:
                href = link["href"].strip()
                parsed = urlparse(href)
                if parsed.netloc and parsed.netloc != original_domain:
                    full_url = urljoin(url, href)
                    external_links.append(full_url)
            if not external_links:
                return 0
            error_count = 0
            for link in external_links:
                try:
                    head = requests.head(link, timeout=5)
                    if head.status_code >= 400:
                        error_count += 1
                except:
                    error_count += 1
            return error_count / len(external_links)
        except:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="external_errors_ratio",
              value=df["URL"].apply(get_external_error_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_errors_ratio' added.")


def connection_errors_ratio():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_connection_errors_ratio(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", href=True)
            if not links:
                return 0
            errors = 0
            tested = 0
            for link in links[:5]:
                href = link['href']
                parsed = urlparse(href)
                if not parsed.scheme:
                    href = url.rstrip('/') + '/' + href.lstrip('/')
                try:
                    head = requests.head(href, timeout=5)
                    if head.status_code >= 400:
                        errors += 1
                except:
                    errors += 1
                tested += 1
            return errors / tested if tested > 0 else 0
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="connection_errors_ratio",
              value=df["URL"].apply(get_connection_errors_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'connection_errors_ratio' added.")

def number_of_hyperlinks():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_hyperlinks_count(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            return len(soup.find_all("a"))
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="number_of_hyperlinks",
              value=df["URL"].apply(get_hyperlinks_count))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'number_of_hyperlinks' added.")

def external_css_files_count():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_external_css_count(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            original_domain = urlparse(url).netloc
            count = 0
            for link in soup.find_all("link", rel=lambda x: x and "stylesheet" in x.lower()):
                href = link.get("href", "")
                parsed = urlparse(href)
                if parsed.netloc and parsed.netloc != original_domain:
                    count += 1
            return count
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="external_css_files_count",
              value=df["URL"].apply(get_external_css_count))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_css_files_count' added.")

def login_forms_presence():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_login_form(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                # If a form contains an input of type "password", consider it a login form.
                if form.find("input", {"type": "password"}):
                    action = form.get("action", "")
                    if action == "" or action.startswith("#"):
                        return 1
            return 0
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="login_forms_presence",
              value=df["URL"].apply(check_login_form))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'login_forms_presence' added.")

def external_favicon():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_external_favicon(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            original_domain = urlparse(url).netloc
            favicon = soup.find("link", rel=lambda x: x and ("icon" in x.lower() or "shortcut icon" in x.lower()))
            if favicon:
                href = favicon.get("href", "")
                parsed = urlparse(href)
                if parsed.netloc and parsed.netloc != original_domain:
                    return 1
            return 0
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="external_favicon",
              value=df["URL"].apply(check_external_favicon))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'external_favicon' added.")


def internal_links_in_link_tags():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def get_internal_links_ratio(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            link_tags = soup.find_all("link", href=True)
            if not link_tags:
                return 0  # No <link> tags found, so ratio is 0.
            original_domain = urlparse(url).netloc
            internal_count = 0
            for tag in link_tags:
                href = tag.get("href", "").strip()
                # Resolve relative URLs.
                full_url = urljoin(url, href)
                domain = urlparse(full_url).netloc
                if domain == original_domain:
                    internal_count += 1
            return internal_count / len(link_tags)
        except Exception:
            return -1  # Error indicator.
    
    df.insert(loc=df.columns.get_loc("Label"), column="internal_link_tags_ratio",
              value=df["URL"].apply(get_internal_links_ratio))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'internal_link_tags_ratio' added.")

def submit_to_email():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_submit_to_email(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "").lower()
                if "mailto:" in action or "mail()" in action:
                    return 1
            return 0
        except Exception:
            return -1
    
    df.insert(loc=df.columns.get_loc("Label"), column="submit_to_email",
              value=df["URL"].apply(check_submit_to_email))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'submit_to_email' added.")

def invisible_iframe():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_invisible_iframe(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            iframes = soup.find_all("iframe")
            count = 0
            for iframe in iframes:
                style = iframe.get("style", "").lower()
                width = iframe.get("width", "")
                height = iframe.get("height", "")
                if ("display:none" in style) or (width == "0" and height == "0"):
                    count += 1
            return count
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="invisible_iframe",
              value=df["URL"].apply(check_invisible_iframe))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'invisible_iframe' added.")

def pop_up_windows():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_popups(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            return r.text.lower().count("window.open(")
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="pop_up_windows",
              value=df["URL"].apply(check_popups))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'pop_up_windows' added.")

def unsafe_anchors():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_unsafe_anchors(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            count = 0
            for a in soup.find_all("a", href=True):
                href = a['href'].strip().lower()
                if href.startswith("javascript:") or href == "#":
                    count += 1
            return count
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="unsafe_anchors",
              value=df["URL"].apply(count_unsafe_anchors))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'unsafe_anchors' added.")

def right_click_blocking():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_right_click(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            return 1 if 'oncontextmenu="return false"' in r.text.lower() else 0
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="right_click_blocking",
              value=df["URL"].apply(check_right_click))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'right_click_blocking' added.")

def empty_title():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_empty_title(url):
        try:
            r = fetch_page(url)
            if not r:
                return -1
            soup = BeautifulSoup(r.text, "html.parser")
            title_tag = soup.find("title")
            if title_tag and title_tag.text.strip():
                return 0
            else:
                return 1
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="empty_title",
              value=df["URL"].apply(check_empty_title))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'empty_title' added.")


def sfh_form_action():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_sfh(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "").strip().lower()
                if action == "" or action == "about:blank":
                    return 1
            return 0
        except Exception:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="sfh",
              value=df["URL"].apply(check_sfh))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'sfh' added.")

def domain_in_copyright():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_copyright(url):
        try:
            response = requests.get(url, timeout=10)
            if not response:
                return -1
            soup = BeautifulSoup(response.text, "html.parser")
            page_text = soup.get_text(separator="\n")
            domain = urlparse(url).netloc.lower()
            lines = [line.strip() for line in page_text.splitlines() if ("copyright" in line.lower() or "©" in line)]
            for line in lines:
                if domain in line:
                    return 1
            return 0
        except Exception:
            return -1

    df.insert(loc=df.columns.get_loc("Label"), column="domain_in_copyright",
              value=df["URL"].apply(check_copyright))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_in_copyright' added.")


def whois_registration():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_whois(url):
        try:
            domain = urlparse(url).netloc
            if whois:
                w = whois.whois(domain)
                return 1 if w.domain_name else 0
            else:
                return -1
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="whois_registration",
              value=df["URL"].apply(check_whois))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'whois_registration' added.")

def domain_registration_length():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_registration_length(url):
        try:
            domain = urlparse(url).netloc
            if whois:
                w = whois.whois(domain)
                # Use first dates if lists
                exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if exp and cre:
                    return (exp - cre).days / 365.0
            return -1
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="domain_registration_length",
              value=df["URL"].apply(get_registration_length))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_registration_length' added.")

def domain_age():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_domain_age(url):
        try:
            domain = urlparse(url).netloc
            if whois:
                w = whois.whois(domain)
                cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if cre:
                    return (pd.Timestamp.now() - pd.Timestamp(cre)).days / 365.0
            return -1
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="domain_age",
              value=df["URL"].apply(get_domain_age))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_age' added.")

def dns_record_check():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_dns(url):
        try:
            domain = urlparse(url).netloc
            socket.gethostbyname(domain)
            return 1
        except:
            return 0
    df.insert(loc=df.columns.get_loc("Label"), column="dns_record_check",
              value=df["URL"].apply(check_dns))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'dns_record_check' added.")


def google_index():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    def is_indexed(url):
        search_url = f"https://www.google.com/search?q=site:{url}"
        headers = {"User-Agent": "Mozilla/5.0"} 
        try:
            response = requests.get(search_url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            return int(bool(soup.find("div", id="search")))  
        except Exception:
            return 0  
    df.insert(loc=df.columns.get_loc("Label"), column="google_index", 
              value=df["URL"].apply(is_indexed))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'google_index' added.")


def get_page_rank(url):
    search_url = f"https://www.google.com/search?q=site:{url}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(search_url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        result_stats = soup.find("div", {"id": "result-stats"})
        if result_stats:
            text = result_stats.text.replace(",", "").split()[1]  
            return int(text) if text.isdigit() else 0
    except Exception:
        return 0

def page_rank():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    
    df.insert(loc=df.columns.get_loc("Label"), column="page_rank", 
              value=df["URL"].apply(get_page_rank))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'page_rank' added.")

def get_web_traffic(url):
    search_url = f"https://www.google.com/search?q={url} site:similarweb.com"
    headers = {"User-Agent": "Mozilla/5.0"}
    
    try:
        response = requests.get(search_url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        result_stats = soup.find("div", {"id": "result-stats"})
        if result_stats:
            text = result_stats.text.replace(",", "").split()[1]
            return int(text) if text.isdigit() else 0
    except Exception:
        return 0

def web_traffic():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    df.insert(loc=df.columns.get_loc("Label"), column="web_traffic", 
              value=df["URL"].apply(get_web_traffic))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'web_traffic' added.")


def vowel_count_in_domain():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_vowels(url):
        domain = urlparse(url).netloc
        return sum(1 for c in domain.lower() if c in "aeiou")
    df.insert(loc=df.columns.get_loc("Label"), column="vowel_count_in_domain",
              value=df["URL"].apply(count_vowels))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'vowel_count_in_domain' added.")

def domain_in_ip_format():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_domain_ip(url):
        domain = urlparse(url).netloc
        return 1 if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain) else 0
    df.insert(loc=df.columns.get_loc("Label"), column="domain_in_ip_format",
              value=df["URL"].apply(check_domain_ip))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_in_ip_format' added.")

def server_or_client_in_domain():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_server_client(url):
        domain = urlparse(url).netloc.lower()
        return 1 if ("server" in domain or "client" in domain) else 0
    df.insert(loc=df.columns.get_loc("Label"), column="server_or_client_in_domain",
              value=df["URL"].apply(check_server_client))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'server_or_client_in_domain' added.")

def domain_lookup_response_time():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def lookup_time(url):
        try:
            domain = urlparse(url).netloc
            start = time.time()
            socket.gethostbyname(domain)
            return time.time() - start
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="domain_lookup_response_time",
              value=df["URL"].apply(lookup_time))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_lookup_response_time' added.")

def spf_record():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_spf(url):
        if dns:
            try:
                domain = urlparse(url).netloc
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    if rdata.to_text().startswith('"v=spf1'):
                        return 1
                return 0
            except:
                return -1
        else:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="spf_record",
              value=df["URL"].apply(check_spf))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'spf_record' added.")

import pandas as pd
import whois
import requests

def asn():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_asn(url):
        domain = url.split("//")[-1].split("/")[0]  
        try:
            w = whois.whois(domain)
            return w.get("asn", -1) 
        except:
            return -1 
    df.insert(loc=df.columns.get_loc("Label"), column="asn", value=df["URL"].apply(get_asn))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'asn' added.")

def domain_activation_time():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_activation_time(url):
        domain = url.split("//")[-1].split("/")[0]  
        try:
            w = whois.whois(domain)
            return int(w.creation_date.timestamp()) if w.creation_date else -1
        except:
            return -1  
    df.insert(loc=df.columns.get_loc("Label"), column="domain_activation_time", value=df["URL"].apply(get_activation_time))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_activation_time' added.")

def domain_expiration_time():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def get_expiration_time(url):
        domain = url.split("//")[-1].split("/")[0] 
        try:
            w = whois.whois(domain)
            return int(w.expiration_date.timestamp()) if w.expiration_date else -1
        except:
            return -1  
    
    df.insert(loc=df.columns.get_loc("Label"), column="domain_expiration_time", value=df["URL"].apply(get_expiration_time))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'domain_expiration_time' added.")


def number_of_resolved_ips():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_ips(url):
        try:
            domain = urlparse(url).netloc
            ips = socket.gethostbyname_ex(domain)[2]
            return len(ips)
        except:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="number_of_resolved_ips",
              value=df["URL"].apply(count_ips))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'number_of_resolved_ips' added.")

def nameservers_count():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_ns(url):
        if dns:
            try:
                domain = urlparse(url).netloc
                answers = dns.resolver.resolve(domain, 'NS')
                return len(answers)
            except:
                return -1
        else:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="nameservers_count",
              value=df["URL"].apply(count_ns))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'nameservers_count' added.")

def mx_servers_count():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_mx(url):
        if dns:
            try:
                domain = urlparse(url).netloc
                answers = dns.resolver.resolve(domain, 'MX')
                return len(answers)
            except:
                return -1
        else:
            return -1
    df.insert(loc=df.columns.get_loc("Label"), column="mx_servers_count",
              value=df["URL"].apply(count_mx))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'mx_servers_count' added.")

def get_ttl(domain):
    try:
        answer = dns.resolver.resolve(domain, 'A')
        return answer.rrset.ttl
    except Exception as e:
        return -1

def ttl_hostname():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def fetch_ttl(url):
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  
        return get_ttl(domain)
    df.insert(loc=df.columns.get_loc("Label"), column="ttl_hostname", value=df["URL"].apply(fetch_ttl))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'ttl_hostname' added.")


def tls_ssl_certificate():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_ssl(url):
        return 1 if url.lower().startswith("https://") else 0
    df.insert(loc=df.columns.get_loc("Label"), column="tls_ssl_certificate",
              value=df["URL"].apply(check_ssl))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'tls_ssl_certificate' added.")


def tld_present_in_parameters():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def check_tld_in_params(url):
        parsed = urlparse(url)
        query = parsed.query
        return 1 if re.search(r'\.[a-zA-Z]{2,6}', query) else 0
    df.insert(loc=df.columns.get_loc("Label"), column="tld_present_in_parameters",
              value=df["URL"].apply(check_tld_in_params))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'tld_present_in_parameters' added.")

def number_of_parameters():
    df = pd.read_csv("221IT085_URLfeaturedataset.csv")
    def count_params(url):
        query = urlparse(url).query
        if query:
            params = query.split('&')
            return len(params)
        return 0
    df.insert(loc=df.columns.get_loc("Label"), column="number_of_parameters",
              value=df["URL"].apply(count_params))
    df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    print("Feature 'number_of_parameters' added.")

def main():
    # df = pd.read_csv("phishing_site_urls_dataset.csv")
    # new_df = df[["URL", "Label"]].copy()
    # new_df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
    # print("Initial dataset created.")
 
    # full_url_length()  
    # hostname_length()  
    # ip_address_in_url()
    # #Special Character Counts
    # dot_count()
    # hyphen_count()
    # underscore_count()
    # slash_count()
    # question_mark_count()
    # equal_count()
    # at_count()
    # ampersand_count()
    # exclamation_count()
    # space_count()
    # tilde_count()
    # comma_count()
    # plus_count()
    # asterisk_count()
    # hashtag_count()
    # dollar_count()
    # percent_count()
    # vertical_bar_count()
    # colon_count()
    # semicolon_count()
    # #Common Terms
    # www_occurrence()
    # com_occurrence()
    # http_occurrence()
    # double_slash_occurrence()
    # https_token()
    # digit_ratio_full_url()
    # digit_ratio_hostname()
    # punycode_usage()
    # port_number_presence()
    # tld_in_path()
    # tld_in_subdomain()
    # abnormal_subdomains()
    # number_of_subdomains()
    # prefix_suffix_hyphen()
    # random_domain_indicator()
    # url_shortening_service()
    # path_extension_check()
    # redirection_count()
    # external_redirection_count()
    # word_count_url()
    # word_count_hostname()
    # word_count_path()
    # char_repeat_url()
    # char_repeat_hostname()
    # char_repeat_path()
    # shortest_word_url()
    # shortest_word_hostname()
    # shortest_word_path()
    # longest_word_url()
    # longest_word_hostname()
    # longest_word_path()
    # average_word_length_url()
    # average_word_length_hostname()
    # average_word_length_path()
    # phish_hints()
    # brand_in_domain()
    # brand_in_subdomain()
    # brand_in_path()
    # suspicious_tld()
    # statistical_report()
    # number_of_hyperlinks()
    # null_hyperlinks_ratio()
    # external_css_files_count()
    # internal_redirection_ratio()
    # external_redirection_ratio()
    # internal_errors_ratio()
    # external_errors_ratio()
    # login_forms_presence()
    # external_favicon()
    # internal_links_in_link_tags()
    # submit_to_email()
    # internal_hyperlink_ratio()
    # external_hyperlink_ratio()
    # internal_media_ratio()
    # external_media_ratio()
    # sfh_form_action()
    # invisible_iframe()
    # pop_up_windows()
    # unsafe_anchors()
    # right_click_blocking()
    # empty_title()
    # domain_in_copyright()
    # whois_registration()
    # domain_registration_length()
    # domain_age()
    # directory_length()
    # file_name_length()
    # parameters_length()
    # tld_length()
    # email_in_url()
    # vowel_count_in_domain()
    # domain_in_ip_format()
    # server_or_client_in_domain()
    # domain_lookup_response_time()
    # asn()
    # domain_activation_time()
    # domain_expiration_time()
    # number_of_resolved_ips()
    # nameservers_count()
    # ttl_hostname()
    # tls_ssl_certificate()
    # tld_present_in_parameters()
    # number_of_parameters()
    # dns_record_check()
    # media_links_ratio()
    # connection_errors_ratio()

    
    web_traffic()
    google_index()
    page_rank()
    mx_servers_count()
    spf_record()
    domain_in_title()


if __name__ == "__main__":
    main()
