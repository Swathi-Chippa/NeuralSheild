from urllib.parse import urlparse
import re

def extract_features(url):

    features = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1 IP address in URL
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url):
        features.append(1)
    else:
        features.append(-1)

    # 2 URL Length
    length = len(url)

    if length < 54:
        features.append(-1)
    elif length <= 75:
        features.append(0)
    else:
        features.append(1)

    # 3 URL Shortening Service
    shorteners = [
        "bit.ly","tinyurl","goo.gl","t.co","ow.ly",
        "is.gd","buff.ly","adf.ly","bit.do"
    ]

    if any(short in url for short in shorteners):
        features.append(1)
    else:
        features.append(-1)

    # 4 @ Symbol
    if "@" in url:
        features.append(1)
    else:
        features.append(-1)

    # 5 Double Slash Redirecting
    if url.rfind("//") > 6:
        features.append(1)
    else:
        features.append(-1)

    # 6 Prefix-Suffix in Domain
    if "-" in domain:
        features.append(1)
    else:
        features.append(-1)

    # 7 Subdomains
    dots = domain.count(".")

    if dots == 1:
        features.append(-1)
    elif dots == 2:
        features.append(0)
    else:
        features.append(1)

    # 8 SSL State
    if url.startswith("https"):
        features.append(-1)
    else:
        features.append(1)

    # 9 HTTPS token in domain
    if "https" in domain:
        features.append(1)
    else:
        features.append(-1)

    # Fill remaining dataset features neutrally
    while len(features) < 30:
        features.append(0)

    return features