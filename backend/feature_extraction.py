import re
from urllib.parse import urlparse
import math

def entropy(string):
    "Calculates the Shannon entropy of a string"
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

class URLFeatureExtractor:
    def __init__(self, url: str):
        self.url = url
        if not self.url.startswith('http://') and not self.url.startswith('https://'):
            self.parsed_url = urlparse('http://' + self.url)
        else:
            self.parsed_url = urlparse(self.url)
        
        self.domain = self.parsed_url.netloc

    def extract_features(self) -> dict:
        features = {}
        
        # 1. URL Length
        features['url_length'] = len(self.url)
        
        # 2. Domain Length
        features['domain_length'] = len(self.domain)
        
        # 3. Presence of IP address in domain
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])|'
            r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
            r'([0-9a-fA-F]{1,4}:){1,7}:|'
            r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
            r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
            r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
            r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
            r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
            r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
            r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
            r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
            r'::(ffff(:0{1,4}){0,1}:){0,1}'
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))|'
            r'([0-9a-fA-F]{1,4}:){1,4}:'
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])))'
        )
        features['has_ip'] = 1 if ip_pattern.search(self.domain) else 0
         
        # 4. Count of '@'
        features['count_at'] = self.url.count('@')
        
        # 5. Length of path
        features['path_length'] = len(self.parsed_url.path)
        
        # 6. Extracted parameters count
        features['count_params'] = len(self.parsed_url.query.split('&')) if self.parsed_url.query else 0
        
        # 7. Entropy
        features['entropy'] = entropy(self.url)
        
        # 8. Hyphens in domain
        features['domain_hyphens'] = self.domain.count('-')
        
        # 9. HTTPS presence (if it was provided originally)
        features['has_https'] = 1 if self.url.startswith('https://') else 0
        
        # 10. Presence of subdomains (Number of dots in domain - 1)
        # e.g. www.google.com has 2 dots, so 1 subdomain (www). 
        # google.com has 1 dot, 0 subdomains.
        num_dots = self.domain.count('.')
        features['num_subdomains'] = max(0, num_dots - 1)
        
        return features

    def explain_features(self, features: dict) -> list[str]:
        """Generate human readable explanations of the risk vectors based on extracted features."""
        risk_factors = []
        
        if features['has_ip'] == 1:
            risk_factors.append("The domain uses an IP address instead of a standard domain name, a common phishing tactic to hide identity.")
            
        if features['domain_hyphens'] > 1:
            risk_factors.append(f"The domain contains {features['domain_hyphens']} hyphens; phishers often add hyphens to mimic legitimate domains (e.g., login-paypal-update.com).")
            
        if features['count_at'] > 0:
            risk_factors.append(f"The URL contains {features['count_at']} '@' symbol(s). Everything before the '@' is ignored by browsers, often used to conceal the real destination.")
            
        if features['url_length'] > 75:
            risk_factors.append(f"The URL is abnormally long ({features['url_length']} characters), which can be an attempt to hide the actual domain from users.")
            
        if features['num_subdomains'] > 2:
            risk_factors.append(f"The URL has a suspiciously high number of subdomains ({features['num_subdomains']+1}), which is often used in free hosting or dynamic DNS phishing.")
            
        if features['entropy'] > 4.5:
            risk_factors.append(f"The URL has a high entropy score ({features['entropy']:.2f}), indicating a high probability of randomly generated (DGA) characters typical of malware/phishing domains.")
            
        if features['has_https'] == 0:
            risk_factors.append("The URL does not use HTTPS, meaning the connection is insecure and unencrypted. While not always phishing, it is a high-risk factor.")
            
        if not risk_factors:
            risk_factors.append("The URL structure appears typical with no overt structural red flags.")
            
        return risk_factors

if __name__ == "__main__":
    extractor = URLFeatureExtractor("http://paypal-update.login-security-check.com@192.168.1.1/login.php?client=123")
    feats = extractor.extract_features()
    print("Features:", feats)
    print("Explanations:")
    for exp in extractor.explain_features(feats):
        print("-", exp)
