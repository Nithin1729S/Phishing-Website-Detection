import pickle

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import pandas as pd
import requests
from urllib.parse import urlparse,urljoin
import socket
from bs4 import BeautifulSoup
import whois
import dns.resolver
import re
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from tensorflow.keras.models import load_model
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Optional libraries for WHOIS and DNS lookups
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

# Define request model
class URLRequest(BaseModel):
    url: str  

# Initialize FastAPI app
app = FastAPI()

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the pre-trained phishing detection model
model_path = "model/phishing.pkl"
try:
    with open(model_path, "rb") as model_file:
        loaded_model = pickle.load(model_file)
except Exception as e:
    raise RuntimeError(f"Failed to load the model: {e}")
flag=0
@app.get("/")
def health_check():
    return {"status": "OK"}

@app.post("/api/check-phishing")
async def check_phishing(request: URLRequest):
    try:
        url = request.url
        flag=0
        # Remove the protocol if present (case-sensitive check)
        if url.startswith("https://"):
            url = url[8:]
        elif url.startswith("http://"):
            url = url[7:]
            flag=1
        
        full_url_length_ = full_url_length(url)
        hostname_length_ = hostname_length(url)
        ip_address_in_url_ = ip_address_in_url(url)
        dot_count_ = dot_count(url)
        hyphen_count_ = hyphen_count(url)
        underscore_count_ = underscore_count(url)
        slash_count_ = slash_count(url)
        question_mark_count_ = question_mark_count(url)
        equal_count_ = equal_count(url)
        at_count_ = at_count(url)
        exclamation_count_ = exclamation_count(url)
        space_count_ = space_count(url)
        tilde_count_ = tilde_count(url)
        comma_count_ = comma_count(url)
        plus_count_ = plus_count(url)
        asterisk_count_ = asterisk_count(url)
        hashtag_count_ = hashtag_count(url)
        dollar_count_ = dollar_count(url)
        percent_count_ = percent_count(url)
        vertical_bar_count_ = vertical_bar_count(url)
        colon_count_ = colon_count(url)
        semicolon_count_ = semicolon_count(url)
        www_occurrence_ = www_occurrence(url)
        com_occurrence_ = com_occurrence(url)
        http_occurrence_ = http_occurrence(url)
        double_slash_occurrence_ = double_slash_occurrence(url)
        https_token_ = https_token(url)
        digit_ratio_full_url_ = digit_ratio_full_url(url)
        digit_ratio_hostname_ = digit_ratio_hostname(url)
        punycode_usage_ = punycode_usage(url)
        port_number_presence_ = port_number_presence(url)
        tld_in_path_ = tld_in_path(url)
        tld_in_subdomain_ = tld_in_subdomain(url)
        abnormal_subdomains_ = abnormal_subdomains(url)
        number_of_subdomains_ = number_of_subdomains(url)
        prefix_suffix_hyphen_ = prefix_suffix_hyphen(url)
        random_domain_indicator_ = random_domain_indicator(url)
        url_shortening_service_ = url_shortening_service(url)
        path_extension_check_ = path_extension_check(url)
        redirection_count_ = redirection_count(url)
        external_redirection_count_ = external_redirection_count(url)
        word_count_url_ = word_count_url(url)
        word_count_hostname_ = word_count_hostname(url)
        word_count_path_ = word_count_path(url)
        char_repeat_url_ = char_repeat_url(url)
        shortest_word_url_ = shortest_word_url(url)
        longest_word_url_ = longest_word_url(url)
        longest_word_path_ = longest_word_path(url)
        average_word_length_url_ = average_word_length_url(url)
        average_word_length_path_ = average_word_length_path(url)
        phish_hints_ = phish_hints(url)
        brand_in_domain_ = brand_in_domain(url)
        brand_in_subdomain_ = brand_in_subdomain(url)
        brand_in_path_ = brand_in_path(url)
        suspicious_tld_ = suspicious_tld(url)
        statistical_report_ = statistical_report(url)
        number_of_hyperlinks_ = number_of_hyperlinks(url)
        null_hyperlinks_ratio_ = null_hyperlinks_ratio(url)
        external_css_files_count_ = external_css_files_count(url)
        internal_redirection_ratio_ = internal_redirection_ratio(url)
        external_redirection_ratio_ = external_redirection_ratio(url)
        internal_errors_ratio_ = internal_errors_ratio(url)
        external_errors_ratio_ = external_errors_ratio(url)
        login_forms_presence_ = login_forms_presence(url)
        external_favicon_ = external_favicon(url)
        internal_hyperlink_ratio_ = internal_hyperlink_ratio(url)
        external_hyperlink_ratio_ = external_hyperlink_ratio(url)
        internal_media_ratio_ = internal_media_ratio(url)
        external_media_ratio_ = external_media_ratio(url)
        sfh_form_action_ = sfh_form_action(url)
        invisible_iframe_ = invisible_iframe(url)
        pop_up_windows_ = pop_up_windows(url)
        unsafe_anchors_ = unsafe_anchors(url)
        right_click_blocking_ = right_click_blocking(url)
        empty_title_ = empty_title(url)
        domain_in_copyright_ = domain_in_copyright(url)
        whois_registration_ = whois_registration(url)
        domain_registration_length_ = domain_registration_length(url)
        domain_age_ = domain_age(url)
        directory_length_ = directory_length(url)
        file_name_length_ = file_name_length(url)
        tld_length_ = tld_length(url)
        email_in_url_ = email_in_url(url)
        domain_in_ip_format_ = domain_in_ip_format(url)
        server_or_client_in_domain_ = server_or_client_in_domain(url)
        asn_ = asn(url)
        domain_activation_time_ = domain_activation_time(url)
        domain_expiration_time_ = domain_expiration_time(url)
        number_of_resolved_ips_ = number_of_resolved_ips(url)
        ttl_hostname_ = ttl_hostname(url)
        tls_ssl_certificate_ = tls_ssl_certificate(url)
        tld_present_in_parameters_ = tld_present_in_parameters(url)
        media_links_ratio_ = media_links_ratio(url)
        connection_errors_ratio_ = connection_errors_ratio(url)
        mx_servers_count_ = mx_servers_count(url)

        input_features = [
            full_url_length_, hostname_length_, ip_address_in_url_, dot_count_, hyphen_count_, underscore_count_,
            slash_count_, question_mark_count_, equal_count_, at_count_, exclamation_count_, space_count_,
            tilde_count_, comma_count_, plus_count_, asterisk_count_, hashtag_count_, dollar_count_, percent_count_,
            vertical_bar_count_, colon_count_, semicolon_count_, www_occurrence_, com_occurrence_, http_occurrence_,
            double_slash_occurrence_, https_token_, digit_ratio_full_url_, digit_ratio_hostname_, punycode_usage_,
            port_number_presence_, tld_in_path_, tld_in_subdomain_, abnormal_subdomains_, number_of_subdomains_,
            prefix_suffix_hyphen_, random_domain_indicator_, url_shortening_service_, path_extension_check_,
            redirection_count_, external_redirection_count_, word_count_url_, word_count_hostname_, word_count_path_,
            char_repeat_url_, shortest_word_url_, longest_word_url_, longest_word_path_, average_word_length_url_,
            average_word_length_path_, phish_hints_, brand_in_domain_, brand_in_subdomain_, brand_in_path_,
            suspicious_tld_, statistical_report_, number_of_hyperlinks_, null_hyperlinks_ratio_, external_css_files_count_,
            internal_redirection_ratio_, external_redirection_ratio_, internal_errors_ratio_, external_errors_ratio_,
            login_forms_presence_, external_favicon_, internal_hyperlink_ratio_, external_hyperlink_ratio_,
            internal_media_ratio_, external_media_ratio_, sfh_form_action_, invisible_iframe_, pop_up_windows_,
            unsafe_anchors_, right_click_blocking_, empty_title_, domain_in_copyright_, whois_registration_,
            domain_registration_length_, domain_age_, directory_length_, file_name_length_, tld_length_, email_in_url_,
            domain_in_ip_format_, server_or_client_in_domain_, asn_, domain_activation_time_, domain_expiration_time_,
            number_of_resolved_ips_, ttl_hostname_, tls_ssl_certificate_, tld_present_in_parameters_, media_links_ratio_,
            connection_errors_ratio_, mx_servers_count_
        ]

        encoder_model = load_model("model/encoder_model.h5")
        input_features = np.array(input_features).reshape(1, -1)
        if input_features.shape[1] < 97:
            dummy_fill = np.zeros((1, 97 - input_features.shape[1]))
            input_features = np.hstack((input_features, dummy_fill))
        elif input_features.shape[1] > 97:
            input_features = input_features[:, :97]
        encoded_features = encoder_model.predict(input_features)
        #print(encoded_features)
        model_filename = f'model/svm_model_rbf.pkl'
        with open(model_filename, 'rb') as file:
            loaded_modle = pickle.load(file)
        encoded_features=url
        prediction = loaded_model.predict([encoded_features])[0]  # Get prediction
        print(url)
        print(prediction)
        if(flag==1):
            prediction='bad'
        return {
            "prediction": prediction,
            "full_url_length": full_url_length_,
            "hostname_length": hostname_length_,
            "ip_address_in_url": ip_address_in_url_,
            "dot_count": dot_count_,
            "hyphen_count": hyphen_count_,
            "underscore_count": underscore_count_,
            "slash_count": slash_count_,
            "question_mark_count": question_mark_count_,
            "equal_count": equal_count_,
            "at_count": at_count_,
            "exclamation_count": exclamation_count_,
            "space_count": space_count_,
            "tilde_count": tilde_count_,
            "comma_count": comma_count_,
            "plus_count": plus_count_,
            "asterisk_count": asterisk_count_,
            "hashtag_count": hashtag_count_,
            "dollar_count": dollar_count_,
            "percent_count": percent_count_,
            "vertical_bar_count": vertical_bar_count_,
            "colon_count": colon_count_,
            "semicolon_count": semicolon_count_,
            "www_occurrence": www_occurrence_,
            "com_occurrence": com_occurrence_,
            "http_occurrence": http_occurrence_,
            "double_slash_occurrence": double_slash_occurrence_,
            "https_token": https_token_,
            "digit_ratio_full_url": digit_ratio_full_url_,
            "digit_ratio_hostname": digit_ratio_hostname_,
            "punycode_usage": punycode_usage_,
            "port_number_presence": port_number_presence_,
            "tld_in_path": tld_in_path_,
            "tld_in_subdomain": tld_in_subdomain_,
            "abnormal_subdomains": abnormal_subdomains_,
            "number_of_subdomains": number_of_subdomains_,
            "prefix_suffix_hyphen": prefix_suffix_hyphen_,
            "random_domain_indicator": random_domain_indicator_,
            "url_shortening_service": url_shortening_service_,
            "path_extension_check": path_extension_check_,
            "redirection_count": redirection_count_,
            "external_redirection_count": external_redirection_count_,
            "word_count_url": word_count_url_,
            "word_count_hostname": word_count_hostname_,
            "word_count_path": word_count_path_,
            "char_repeat_url": char_repeat_url_,
            "shortest_word_url": shortest_word_url_,
            "longest_word_url": longest_word_url_,
            "longest_word_path": longest_word_path_,
            "average_word_length_url": average_word_length_url_,
            "average_word_length_path": average_word_length_path_,
            "phish_hints": phish_hints_,
            "brand_in_domain": brand_in_domain_,
            "brand_in_subdomain": brand_in_subdomain_,
            "brand_in_path": brand_in_path_,
            "suspicious_tld": suspicious_tld_,
            "statistical_report": statistical_report_,
            "number_of_hyperlinks": number_of_hyperlinks_,
            "null_hyperlinks_ratio": null_hyperlinks_ratio_,
            "external_css_files_count": external_css_files_count_,
            "internal_redirection_ratio": internal_redirection_ratio_,
            "external_redirection_ratio": external_redirection_ratio_,
            "internal_errors_ratio": internal_errors_ratio_,
            "external_errors_ratio": external_errors_ratio_,
            "login_forms_presence": login_forms_presence_,
            "external_favicon": external_favicon_,
            "internal_hyperlink_ratio": internal_hyperlink_ratio_,
            "external_hyperlink_ratio": external_hyperlink_ratio_,
            "internal_media_ratio": internal_media_ratio_,
            "external_media_ratio": external_media_ratio_,
            "sfh_form_action": sfh_form_action_,
            "invisible_iframe": invisible_iframe_,
            "pop_up_windows": pop_up_windows_,
            "unsafe_anchors": unsafe_anchors_,
            "right_click_blocking": right_click_blocking_,
            "empty_title": empty_title_,
            "domain_in_copyright": domain_in_copyright_,
            "whois_registration": whois_registration_,
            "domain_registration_length": domain_registration_length_,
            "domain_age": domain_age_,
            "directory_length": directory_length_,
            "file_name_length": file_name_length_,
            "tld_length": tld_length_,
            "email_in_url": email_in_url_,
            "domain_in_ip_format": domain_in_ip_format_,
            "server_or_client_in_domain": server_or_client_in_domain_,
            "asn": asn_,
            "domain_activation_time": domain_activation_time_,
            "domain_expiration_time": domain_expiration_time_,
            "number_of_resolved_ips": number_of_resolved_ips_,
            "ttl_hostname": ttl_hostname_,
            "tls_ssl_certificate": tls_ssl_certificate_,
            "tld_present_in_parameters": tld_present_in_parameters_,
            "media_links_ratio": media_links_ratio_,
            "connection_errors_ratio": connection_errors_ratio_,
            "mx_servers_count": mx_servers_count_
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



######################################### Functions to Extract Features from URL ##################################################

def full_url_length(url: str) -> int:
    """Return the full URL length."""
    return len(url)

def hostname_length(url: str) -> int:
    """Return the length of the hostname in the URL."""
    match = re.search(r'^(?:https?://)?([^/]+)', url)
    return len(match.group(1)) if match else 0

def ip_address_in_url(url: str) -> int:
    """Return 1 if an IP address is present at the start of the URL, else 0."""
    m = re.search(r'^(?:https?://)?((?:\d{1,3}\.){3}\d{1,3})', url)
    return 1 if m else 0

def special_char_count(url: str, pattern: str) -> int:
    """Return the count of special characters matching the regex pattern in the URL."""
    return len(re.findall(pattern, url))

def dot_count(url: str) -> int:
    return special_char_count(url, r'\.')

def hyphen_count(url: str) -> int:
    return special_char_count(url, r'-')

def underscore_count(url: str) -> int:
    return special_char_count(url, r'_')

def slash_count(url: str) -> int:
    return special_char_count(url, r'/')

def question_mark_count(url: str) -> int:
    return special_char_count(url, r'\?')

def equal_count(url: str) -> int:
    return special_char_count(url, r'=')

def at_count(url: str) -> int:
    return special_char_count(url, r'@')

def exclamation_count(url: str) -> int:
    return special_char_count(url, r'!')

def space_count(url: str) -> int:
    return special_char_count(url, r' ')

def tilde_count(url: str) -> int:
    return special_char_count(url, r'˜')

def comma_count(url: str) -> int:
    return special_char_count(url, r',')

def plus_count(url: str) -> int:
    return special_char_count(url, r'\+')

def asterisk_count(url: str) -> int:
    return special_char_count(url, r'\*')

def hashtag_count(url: str) -> int:
    return special_char_count(url, r'#')

def dollar_count(url: str) -> int:
    return special_char_count(url, r'\$')

def percent_count(url: str) -> int:
    return special_char_count(url, r'%')

def vertical_bar_count(url: str) -> int:
    return special_char_count(url, r'\|')

def colon_count(url: str) -> int:
    return special_char_count(url, r':')

def semicolon_count(url: str) -> int:
    return special_char_count(url, r';')

def common_term_occurrence(url: str, pattern: str) -> int:
    """Return the count of occurrences of the pattern in the URL (case-insensitive)."""
    return len(re.findall(pattern, url, re.IGNORECASE))

def www_occurrence(url: str) -> int:
    return common_term_occurrence(url, r'www')

def com_occurrence(url: str) -> int:
    return common_term_occurrence(url, r'\.com')

def http_occurrence(url: str) -> int:
    return common_term_occurrence(url, r'http')

def double_slash_occurrence(url: str) -> int:
    return common_term_occurrence(url, r'//')

def https_token(url: str) -> int:
    """Return 1 if the URL starts with 'https://', else 0."""
    return 1 if url.lower().startswith("https://") else 0

def digit_ratio_full_url(url: str) -> float:
    """Return the ratio of digit characters to total characters in the URL."""
    return sum(c.isdigit() for c in url) / len(url) if url else 0

def digit_ratio_hostname(url: str) -> float:
    """Return the ratio of digit characters to total characters in the hostname."""
    match = re.search(r'^(?:https?://)?([^/]+)', url)
    if match:
        domain = match.group(1)
        return sum(c.isdigit() for c in domain) / len(domain) if domain else 0
    return 0

def punycode_usage(url: str) -> int:
    """Return 1 if the URL's domain uses punycode (contains 'xn--'), else 0."""
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1)
        return 1 if "xn--" in domain.lower() else 0
    return 0

def port_number_presence(url: str) -> int:
    """Return 1 if a port number is specified in the URL, else 0."""
    m = re.search(r'^(?:https?://)?[^/]+:(\d+)', url)
    return 1 if m else 0

def tld_in_path(url: str) -> int:
    """Return 1 if the URL's path contains a TLD-like pattern, else 0."""
    parsed = urlparse(url)
    path = parsed.path
    return 1 if re.search(r'\.[a-zA-Z]{2,6}', path) else 0

def tld_in_subdomain(url: str) -> int:
    """Return 1 if any subdomain part matches a TLD-like pattern (2-6 alphabetic characters), else 0."""
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    if len(parts) > 2:
        subdomains = parts[:-2]
        for sub in subdomains:
            if re.fullmatch(r'[a-zA-Z]{2,6}', sub):
                return 1
    return 0

def abnormal_subdomains(url: str) -> int:
    """
    Return 1 if any subdomain (excluding 'www') contains digits,
    which may indicate abnormal subdomain usage.
    """
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1)
        parts = domain.split('.')
        if len(parts) > 2:
            for part in parts[:-2]:
                if re.search(r'\d', part) and part.lower() != "www":
                    return 1
    return 0

def number_of_subdomains(url: str) -> int:
    """
    Return the number of subdomains in the URL.
    Counts the number of parts in the domain beyond the last two.
    """
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1)
        parts = domain.split('.')
        if len(parts) > 2:
            return len(parts) - 2
    return 0

def prefix_suffix_hyphen(url: str) -> int:
    """Return 1 if the URL's domain contains a hyphen, else 0."""
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1)
        return 1 if '-' in domain else 0
    return 0

def random_domain_indicator(url: str) -> int:
    """
    Return 1 if the ratio of vowels in the main part of the domain (excluding TLD)
    is less than 0.3, suggesting a possibly random domain; else 0.
    """
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1)
        # Remove port number if present and remove the leading www.
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

def url_shortening_service(url: str) -> int:
    """
    Return 1 if the URL is from a known shortening service, else 0.
    """
    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly", 
        "adf.ly", "bit.do", "cutt.ly", "is.gd", "soo.gd", "s2r.co", "clicky.me"
    ]
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1).lower()
        for short in shorteners:
            if short in domain:
                return 1
    return 0

def path_extension_check(url: str) -> int:
    """
    Return 1 if the URL's path ends with a suspicious extension (.exe or .js), else 0.
    """
    suspicious_exts = [".exe", ".js"]
    m = re.search(r'^(?:https?://)?[^/]+(?P<path>/.*)$', url)
    if m:
        path = m.group("path").lower()
        for ext in suspicious_exts:
            if path.endswith(ext):
                return 1
    return 0

def redirection_count(url: str) -> int:
    """
    Return the number of redirections encountered when accessing the URL.
    Returns -1 in case of an error.
    """
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return len(response.history)
    except:
        return -1


def external_redirection_count(url: str) -> int:
    """
    Return the number of external redirections encountered when accessing the URL.
    An external redirection is counted when the redirected domain differs from the original domain.
    Returns -1 in case of an error.
    """
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        original_domain = urlparse(url).netloc
        count = 0
        for resp in response.history:
            redirected_domain = urlparse(resp.url).netloc
            if redirected_domain and (redirected_domain != original_domain):
                count += 1
        return count
    except Exception:
        return -1

def word_count_url(url: str) -> int:
    """
    Return the number of word tokens in the URL.
    Words are defined as sequences of alphanumeric characters.
    """
    return len(re.findall(r'\w+', url))

def parse_url_components(url: str):
    """
    Parse the URL and return a tuple containing the hostname and path.
    """
    parsed = urlparse(url)
    return parsed.netloc, parsed.path

def word_count_hostname(url: str) -> int:
    """
    Return the number of word tokens in the hostname component of the URL.
    """
    hostname, _ = parse_url_components(url)
    return len(re.findall(r'\w+', hostname))

def word_count_path(url: str) -> int:
    """
    Return the number of word tokens in the path component of the URL.
    """
    _, path = parse_url_components(url)
    return len(re.findall(r'\w+', path))

def max_consecutive_repeat(s: str) -> int:
    """
    Return the maximum number of consecutive repeated characters in the string.
    """
    max_repeat = 0
    for m in re.finditer(r'(.)\1+', s):
        repeat_length = m.end() - m.start()
        if repeat_length > max_repeat:
            max_repeat = repeat_length
    return max_repeat

def char_repeat_url(url: str) -> int:
    """
    Return the maximum consecutive character repetition found in the URL.
    """
    return max_consecutive_repeat(url)

def shortest_word(text: str) -> int:
    """
    Return the length of the shortest word found in the text.
    Words are defined as sequences of alphanumeric characters.
    """
    words = re.findall(r'\w+', text)
    return min(len(w) for w in words) if words else 0

def longest_word(text: str) -> int:
    """
    Return the length of the longest word found in the text.
    """
    words = re.findall(r'\w+', text)
    return max(len(w) for w in words) if words else 0

def average_word_length(text: str) -> float:
    """
    Return the average word length in the text.
    """
    words = re.findall(r'\w+', text)
    return sum(len(w) for w in words) / len(words) if words else 0

def shortest_word_url(url: str) -> int:
    """
    Return the length of the shortest word found in the URL.
    """
    return shortest_word(url)

def longest_word_url(url: str) -> int:
    """
    Return the length of the longest word found in the URL.
    """
    return longest_word(url)

def longest_word_path(url: str) -> int:
    """
    Return the length of the longest word found in the URL's path component.
    """
    _, path = parse_url_components(url)
    return longest_word(path)

def average_word_length_url(url: str) -> float:
    """
    Return the average word length computed over the URL.
    """
    return average_word_length(url)

def average_word_length_path(url: str) -> float:
    """
    Return the average word length computed over the URL's path component.
    """
    _, path = parse_url_components(url)
    return average_word_length(path)

def phish_hints(url: str) -> int:
    """
    Return the total count of suspicious phishing-related keywords found in the URL.
    """
    phish_words = [
        "login", "admin", "signin", "wp", "includes", "content", "site",
        "images", "js", "alibaba", "css", "myaccount", "dropbox", "themes", "plugins", "view"
    ]
    count = 0
    for word in phish_words:
        count += len(re.findall(word, url, re.IGNORECASE))
    return count



def fetch_page(url: str):
    """Helper function to retrieve a web page with a timeout of 10 seconds."""
    try:
        response = requests.get(url, timeout=10)
        return response
    except Exception:
        return None

# --------------------- Brand Related Features --------------------- #

def brand_in_domain(url: str) -> int:
    """Return 1 if a known brand name is found in the URL's domain, else 0."""
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
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1).lower()
        for brand in brands:
            if brand in domain:
                return 1
    return 0

def brand_in_subdomain(url: str) -> int:
    """Return 1 if a known brand name is found within any subdomain, else 0."""
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
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    parts = domain.split('.')
    subdomains = parts[:-2] if len(parts) > 2 else []
    for sub in subdomains:
        for brand in brands:
            if brand in sub:
                return 1
    return 0

def brand_in_path(url: str) -> int:
    """Return 1 if a known brand name is found in the URL's path, else 0."""
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
    parsed = urlparse(url)
    path = parsed.path.lower()
    for brand in brands:
        if brand in path:
            return 1
    return 0

# --------------------- TLD and Domain Features --------------------- #

def suspicious_tld(url: str) -> int:
    """Return 1 if the URL's top-level domain (TLD) is in a list of suspicious TLDs, else 0."""
    suspicious_list = ["tk", "ml", "ga", "cf", "gq"]
    m = re.search(r'^(?:https?://)?([^/]+)', url)
    if m:
        domain = m.group(1)
        tld_match = re.search(r'\.([a-zA-Z0-9]+)$', domain)
        if tld_match:
            tld = tld_match.group(1).lower()
            return 1 if tld in suspicious_list else 0
    return 0

def statistical_report(url: str) -> int:
    """
    Return 1 if any of the domain's IP addresses match a known list of top phishing IPs;
    return 0 if none match, or -1 on error.
    """
    top_phishing_ips = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        ips = socket.gethostbyname_ex(domain)[2]
        for ip in ips:
            if ip in top_phishing_ips:
                return 1
        return 0
    except Exception:
        return -1

# --------------------- Hyperlink & CSS Features --------------------- #

def number_of_hyperlinks(url: str) -> int:
    """Return the count of all hyperlink (<a>) elements found on the webpage."""
    r = fetch_page(url)
    if not r:
        return -1
    soup = BeautifulSoup(r.text, "html.parser")
    return len(soup.find_all("a"))

def null_hyperlinks_ratio(url: str) -> float:
    """
    Return the ratio of hyperlinks that are null or non-functional (e.g., empty, "#", or "javascript:void(0)")
    relative to the total number of hyperlinks on the page.
    """
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

def external_css_files_count(url: str) -> int:
    """
    Return the count of external CSS files linked on the webpage.
    An external CSS file is one whose URL domain differs from the original domain.
    """
    r = fetch_page(url)
    if not r:
        return -1
    parsed_url = urlparse(url)
    original_domain = parsed_url.netloc
    soup = BeautifulSoup(r.text, "html.parser")
    count = 0
    for link in soup.find_all("link", rel=lambda x: x and "stylesheet" in x.lower()):
        href = link.get("href", "")
        parsed = urlparse(href)
        if parsed.netloc and parsed.netloc != original_domain:
            count += 1
    return count

# --------------------- Redirection and Error Ratios --------------------- #

def internal_redirection_ratio(url: str) -> float:
    """
    Return the ratio of internal redirections (redirects to the same domain) to the total redirections.
    Returns 0 if no redirections are present or -1 in case of error.
    """
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
    except Exception:
        return -1

def external_redirection_ratio(url: str) -> float:
    """
    Return the ratio of external redirections (redirects to a different domain) to the total redirections.
    Returns 0 if no redirections occur or -1 in case of error.
    """
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
    except Exception:
        return -1

def internal_errors_ratio(url: str) -> float:
    """
    Return the ratio of internal hyperlinks (within the same domain) that return error status codes (>=400)
    relative to the total number of internal hyperlinks. Returns -1 on error.
    """
    try:
        r = requests.get(url, timeout=10)
        if not r:
            return -1
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a", href=True)
        if not links:
            return 0
        original_domain = urlparse(url).netloc
        internal_links = []
        for link in links:
            href = link["href"].strip()
            parsed = urlparse(href)
            if parsed.netloc == "" or parsed.netloc == original_domain:
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
            except Exception:
                error_count += 1
        return error_count / len(internal_links)
    except Exception:
        return -1

def external_errors_ratio(url: str) -> float:
    """
    Return the ratio of external hyperlinks (pointing to a different domain) that return error status codes (>=400)
    relative to the total number of external hyperlinks. Returns -1 on error.
    """
    try:
        r = requests.get(url, timeout=10)
        if not r:
            return -1
        soup = BeautifulSoup(r.text, "html.parser")
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
            except Exception:
                error_count += 1
        return error_count / len(external_links)
    except Exception:
        return -1

# --------------------- Login Form Detection --------------------- #

def login_forms_presence(url: str) -> int:
    """
    Return 1 if a login form (a form with a password input and no or placeholder action)
    is detected on the webpage; otherwise return 0. Returns -1 on error.
    """
    try:
        r = fetch_page(url)
        if not r:
            return -1
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            # Check for a password input field.
            if form.find("input", {"type": "password"}):
                action = form.get("action", "")
                if action == "" or action.startswith("#"):
                    return 1
        return 0
    except Exception:
        return -1


def fetch_page(url: str):
    """Helper function to retrieve a web page with a timeout of 10 seconds."""
    try:
        response = requests.get(url, timeout=10)
        return response
    except Exception:
        return None

def external_favicon(url: str) -> int:
    """
    Return 1 if the webpage's favicon is external (i.e. from a different domain than the URL), 
    0 if not, or -1 if an error occurs.
    """
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
    except Exception:
        return -1

from typing import Tuple

def count_links(url: str) -> Tuple[int, int, int]:
    """
    Return a tuple (internal, external, total) representing the number of internal links,
    external links, and total hyperlinks found on the webpage.
    """
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

def internal_hyperlink_ratio(url: str) -> float:
    """
    Return the ratio of internal hyperlinks to the total hyperlinks on the webpage.
    """
    internal, _, total = count_links(url)
    return internal / total if total > 0 else 0

def external_hyperlink_ratio(url: str) -> float:
    """
    Return the ratio of external hyperlinks to the total hyperlinks on the webpage.
    """
    _, external, total = count_links(url)
    return external / total if total > 0 else 0

def internal_media_ratio(url: str) -> float:
    """
    Return the ratio of media elements (img, video, audio) that are hosted on the same domain 
    as the URL to the total number of media elements on the page.
    """
    try:
        response = requests.get(url, timeout=10)
        if not response:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        media_tags = soup.find_all("img", src=True)
        media_tags += soup.find_all("video", src=True)
        media_tags += soup.find_all("audio", src=True)
        if not media_tags:
            return 0
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

def external_media_ratio(url: str) -> float:
    """
    Return the ratio of media elements (img, video, audio) that are hosted on a domain different 
    from the URL's domain to the total number of media elements on the page.
    """
    try:
        response = requests.get(url, timeout=10)
        if not response:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        media_tags = soup.find_all("img", src=True)
        media_tags += soup.find_all("video", src=True)
        media_tags += soup.find_all("audio", src=True)
        if not media_tags:
            return 0
        original_domain = urlparse(url).netloc
        external_count = 0
        for tag in media_tags:
            src = tag.get("src")
            full_url = urljoin(url, src)
            media_domain = urlparse(full_url).netloc
            if media_domain and media_domain != original_domain:
                external_count += 1
        return external_count / len(media_tags)
    except Exception:
        return -1

def sfh_form_action(url: str) -> int:
    """
    Return 1 if at least one form on the page has an unsafe form action 
    (i.e. an empty action or "about:blank"), 0 otherwise, or -1 on error.
    """
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

def invisible_iframe(url: str) -> int:
    """
    Return the count of invisible iframes on the page. An iframe is considered invisible if 
    its style contains "display:none" or if both its width and height are "0". Returns -1 on error.
    """
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
    except Exception:
        return -1

def pop_up_windows(url: str) -> int:
    """
    Return the number of occurrences of "window.open(" in the webpage's HTML, 
    which may indicate the presence of pop-up windows. Returns -1 on error.
    """
    try:
        r = fetch_page(url)
        if not r:
            return -1
        return r.text.lower().count("window.open(")
    except Exception:
        return -1






def fetch_page(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        return response
    except Exception:
        return None

def unsafe_anchors(url):
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
    except Exception:
        return -1

def right_click_blocking(url):
    try:
        r = fetch_page(url)
        if not r:
            return -1
        return 1 if 'oncontextmenu="return false"' in r.text.lower() else 0
    except Exception:
        return -1

def empty_title(url):
    try:
        r = fetch_page(url)
        if not r:
            return -1
        soup = BeautifulSoup(r.text, "html.parser")
        title_tag = soup.find("title")
        return 0 if title_tag and title_tag.text.strip() else 1
    except Exception:
        return -1

def domain_in_copyright(url):
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

def whois_registration(url):
    try:
        domain = urlparse(url).netloc
        if whois:
            w = whois.whois(domain)
            return 1 if w.domain_name else 0
        else:
            return -1
    except Exception:
        return -1

def domain_registration_length(url):
    try:
        domain = urlparse(url).netloc
        if whois:
            w = whois.whois(domain)
            exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if exp and cre:
                return (exp - cre).days / 365.0
        return -1
    except Exception:
        return -1

def domain_age(url):
    try:
        domain = urlparse(url).netloc
        if whois:
            w = whois.whois(domain)
            cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if cre:
                return (pd.Timestamp.now() - pd.Timestamp(cre)).days / 365.0
        return -1
    except Exception:
        return -1

def directory_length(url):
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

def file_name_length(url):
    match = re.search(r'^(?:https?://)?[^/]+(?P<path>/.*)?$', url)
    if match:
        path = match.group("path") or ""
        if path and not path.endswith('/'):
            parts = path.rsplit('/', 1)
            if len(parts) == 2:
                return len(parts[1])
            else:
                return 0
        else:
            return 0
    return 0

def tld_length(url):
    match = re.search(r'^(?:https?://)?([^/]+)', url)
    if match:
        domain = match.group(1)
        tld_match = re.search(r'\.([a-zA-Z0-9]+)$', domain)
        if tld_match:
            return len(tld_match.group(1))
    return 0

def email_in_url(url):
    email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    return 1 if re.search(email_pattern, url) else 0

def domain_in_ip_format(url):
    domain = urlparse(url).netloc
    return 1 if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain) else 0

def server_or_client_in_domain(url):
    domain = urlparse(url).netloc.lower()
    return 1 if ("server" in domain or "client" in domain) else 0

def asn(url):
    domain = url.split("//")[-1].split("/")[0]
    try:
        if whois:
            w = whois.whois(domain)
            return w.get("asn", -1)
        else:
            return -1
    except Exception:
        return -1

def domain_activation_time(url):
    domain = url.split("//")[-1].split("/")[0]
    try:
        if whois:
            w = whois.whois(domain)
            return int(w.creation_date.timestamp()) if w.creation_date else -1
        else:
            return -1
    except Exception:
        return -1

def domain_expiration_time(url):
    domain = url.split("//")[-1].split("/")[0]
    try:
        if whois:
            w = whois.whois(domain)
            return int(w.expiration_date.timestamp()) if w.expiration_date else -1
        else:
            return -1
    except Exception:
        return -1

def number_of_resolved_ips(url):
    try:
        domain = urlparse(url).netloc
        ips = socket.gethostbyname_ex(domain)[2]
        return len(ips)
    except Exception:
        return -1

def get_ttl(domain):
    try:
        if dns:
            answer = dns.resolver.resolve(domain, 'A')
            return answer.rrset.ttl
        else:
            return -1
    except Exception:
        return -1

def ttl_hostname(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    return get_ttl(domain)

def tls_ssl_certificate(url):
    return 1 if url.lower().startswith("https://") else 0

def tld_present_in_parameters(url):
    parsed = urlparse(url)
    query = parsed.query
    return 1 if re.search(r'\.[a-zA-Z]{2,6}', query) else 0

def media_links_ratio(url):
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
    except Exception:
        return -1

def connection_errors_ratio(url):
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
            except Exception:
                errors += 1
            tested += 1
        return errors / tested if tested > 0 else 0
    except Exception:
        return -1

def mx_servers_count(url):
    try:
        if dns:
            domain = urlparse(url).netloc
            answers = dns.resolver.resolve(domain, 'MX')
            return len(answers)
        else:
            return -1
    except Exception:
        return -1
