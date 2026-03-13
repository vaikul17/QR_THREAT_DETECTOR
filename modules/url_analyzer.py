import re
import socket
import ssl
from urllib.parse import urlparse

def analyze_url(url):
    """Analyze URL for various security indicators."""
    result = {
        'uses_http': url.startswith('http://'),
        'uses_https': url.startswith('https://'),
        'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
        'long_url': len(url) > 75,
        'many_dots': url.count('.') > 3,
        'has_at': '@' in url,
        'has_double_slash': url.count('//') > 1,
        'has_https': 'https' in url.lower(),
        'has_port': bool(re.search(r':\d+', url)),
        'has_suspicious_words': any(word in url.lower() for word in ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'twitter', 'instagram', 'netflix', 'bank', 'wallet', 'crypto', 'bitcoin', 'ethereum', 'password', 'credential', 'admin', 'dashboard']),
        'has_shortener': any(domain in url for domain in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im']),
        'has_encoded_chars': any(char in url for char in ['%20', '%3D', '%2F', '%3A']),
        'has_data_uri': url.startswith('data:'),
        'has_javascript': 'javascript:' in url.lower(),
        'has_php': '.php' in url.lower(),
        'has_html': '.html' in url.lower(),
        'has_asp': '.asp' in url.lower(),
        'has_cgi': '.cgi' in url.lower(),
        'has_query_params': '?' in url and '=' in url,
        'has_fragment': '#' in url,
        'has_username': bool(re.search(r'://[\w]+:', url)),
    }
    
    try:
        parsed = urlparse(url)
        result['domain'] = parsed.netloc
        result['path'] = parsed.path
        result['query'] = parsed.query
        
        suspicious_tlds = ['.xyz', '.top', '.gq', '.ml', '.cf', '.tk', '.ga', '.work', '.click', '.link', '.review', '.country', '.science', '.cricket', '.date', '.download', '.stream', '.win', '.accountant', '.faith', '.download']
        result['suspicious_tld'] = any(parsed.netloc.lower().endswith(tld) for tld in suspicious_tlds)
        
        if parsed.netloc:
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
            result['domain_is_ip'] = bool(re.match(ip_pattern, parsed.netloc.split(':')[0].split('@')[-1]))
        
    except Exception as e:
        print(f"Error parsing URL: {e}")
    
    result['phishing_indicators'] = []
    if result['has_ip'] and result['uses_http']:
        result['phishing_indicators'].append('IP address in URL with HTTP')
    if result['has_at']:
        result['phishing_indicators'].append('@ symbol in URL')
    if result['long_url'] and result['uses_http']:
        result['phishing_indicators'].append('Long URL with HTTP')
    if result['has_suspicious_words'] and not result['uses_https']:
        result['phishing_indicators'].append('Suspicious words without HTTPS')
    if result['suspicious_tld']:
        result['phishing_indicators'].append('Suspicious TLD')
    if result['has_shortener']:
        result['phishing_indicators'].append('URL shortener detected')
    if result['has_double_slash']:
        result['phishing_indicators'].append('Multiple slashes in path')
    
    return result

def check_ssl_certificate(url):
    """Check SSL certificate of the URL."""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        context = ssl.create_default_context()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        ssock.connect((hostname, 443))
        
        cert = ssock.getpeercert()
        ssock.close()
        
        return {
            'valid': True, 
            'issuer': dict(x[0] for x in cert['issuer']), 
            'subject': dict(x[0] for x in cert['subject']), 
            'version': cert['version'], 
            'notBefore': cert['notBefore'], 
            'notAfter': cert['notAfter']
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def check_domain_age(domain):
    """Check domain age (simulated - requires external API in production)."""
    return {'age_days': None, 'registered': True}

def check_url_reputation(url):
    """Check URL reputation (simulated - requires external API in production)."""
    return {'reputation': 'unknown', 'threats': []}
