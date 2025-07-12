#!/usr/bin/env python3
"""
XSS Security Testing Tool
Developer: Eng Mokhtar Alhamadi
Twitter (X): @M_Alhamadee

This tool is designed for legitimate security testing of your own websites only.
Always ensure you have proper authorization before testing any website.
"""

import requests
import time
import random
import argparse
import sys
from urllib.parse import urljoin, urlparse
import json
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore')

# Optional Selenium imports
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("[!] Selenium not available. Install with: pip install selenium")
    print("[*] Continuing with basic HTTP testing only...")

class XSSSecurityTester:
    def __init__(self, target_url, payloads_file, verbose=False, use_selenium=False, proxy=None):
        """
        Initialize the XSS Security Tester
        
        Args:
            target_url (str): The target URL to test
            payloads_file (str): Path to the payloads file
            verbose (bool): Enable verbose output
            use_selenium (bool): Use Selenium for advanced testing
            proxy (str): Proxy configuration (http://user:pass@host:port)
        """
        self.target_url = target_url
        self.payloads_file = payloads_file
        self.verbose = verbose
        self.use_selenium = use_selenium
        self.proxy = proxy
        self.successful_payloads = []
        self.session = None
        self.driver = None
        
        # User-Agent rotation for stealth
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        self.setup_session()
        if self.use_selenium and SELENIUM_AVAILABLE:
            self.setup_selenium()
        elif self.use_selenium and not SELENIUM_AVAILABLE:
            print("[!] Selenium requested but not available. Continuing with HTTP testing only.")
            self.use_selenium = False
    
    def setup_session(self):
        """Setup requests session with retry strategy and SSL handling"""
        self.session = requests.Session()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # SSL and proxy configuration
        self.session.verify = False
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()
    
    def setup_selenium(self):
        """Setup Selenium WebDriver for advanced testing"""
        if not SELENIUM_AVAILABLE:
            print("[!] Selenium not available. Skipping browser-based testing.")
            self.use_selenium = False
            return
            
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            
            if self.proxy:
                chrome_options.add_argument(f'--proxy-server={self.proxy}')
            
            # Random user agent
            user_agent = random.choice(self.user_agents)
            chrome_options.add_argument(f'--user-agent={user_agent}')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            
        except Exception as e:
            print(f"[!] Error setting up Selenium: {e}")
            print("[!] Continuing without Selenium support...")
            self.use_selenium = False
    
    def load_payloads(self):
        """Load XSS payloads from file"""
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f.readlines() if line.strip()]
            
            if self.verbose:
                print(f"[+] Loaded {len(payloads)} payloads from {self.payloads_file}")
            
            return payloads
        
        except FileNotFoundError:
            print(f"[!] Error: Payloads file '{self.payloads_file}' not found!")
            return []
        except Exception as e:
            print(f"[!] Error loading payloads: {e}")
            return []
    
    def get_random_delay(self):
        """Generate random delay to avoid detection"""
        return random.uniform(1, 5)
    
    def get_random_headers(self):
        """Generate random headers for each request"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        return headers
    
    def discover_forms(self):
        """Discover forms on the target page"""
        try:
            headers = self.get_random_headers()
            response = self.session.get(self.target_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Simple form detection (you can enhance this with BeautifulSoup)
                if '<form' in response.text.lower():
                    if self.verbose:
                        print("[+] Forms detected on target page")
                    return True
            
            return False
        
        except Exception as e:
            if self.verbose:
                print(f"[!] Error discovering forms: {e}")
            return False
    
    def test_payload_get(self, payload):
        """Test payload via GET request"""
        try:
            headers = self.get_random_headers()
            
            # Test common GET parameters
            test_params = ['q', 'search', 'query', 'input', 'data', 'value', 'test']
            
            for param in test_params:
                test_url = f"{self.target_url}?{param}={payload}"
                
                if self.verbose:
                    print(f"[*] Testing GET: {param}={payload[:50]}...")
                
                response = self.session.get(test_url, headers=headers, timeout=10)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    if self.verbose:
                        print(f"[+] Payload reflected in response!")
                    return True
                
                # Check for XSS execution indicators
                if self.check_xss_execution(response.text, payload):
                    return True
                
                # Random delay between requests
                time.sleep(self.get_random_delay())
        
        except Exception as e:
            if self.verbose:
                print(f"[!] Error in GET test: {e}")
        
        return False
    
    def test_payload_post(self, payload):
        """Test payload via POST request"""
        try:
            headers = self.get_random_headers()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            
            # Test common POST parameters
            test_params = ['q', 'search', 'query', 'input', 'data', 'value', 'comment', 'message', 'text']
            
            for param in test_params:
                data = {param: payload}
                
                if self.verbose:
                    print(f"[*] Testing POST: {param}={payload[:50]}...")
                
                response = self.session.post(self.target_url, data=data, headers=headers, timeout=10)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    if self.verbose:
                        print(f"[+] Payload reflected in response!")
                    return True
                
                # Check for XSS execution indicators
                if self.check_xss_execution(response.text, payload):
                    return True
                
                # Random delay between requests
                time.sleep(self.get_random_delay())
        
        except Exception as e:
            if self.verbose:
                print(f"[!] Error in POST test: {e}")
        
        return False
    
    def test_payload_selenium(self, payload):
        """Test payload using Selenium for JavaScript execution detection"""
        if not self.driver:
            return False
        
        try:
            # Test GET parameter injection
            test_url = f"{self.target_url}?test={payload}"
            
            if self.verbose:
                print(f"[*] Testing with Selenium: {payload[:50]}...")
            
            self.driver.get(test_url)
            
            # Wait for potential alert or JavaScript execution
            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                if self.verbose:
                    print(f"[+] JavaScript alert detected: {alert_text}")
                return True
                
            except TimeoutException:
                pass
            
            # Check for payload in page source
            page_source = self.driver.page_source
            if payload in page_source:
                if self.verbose:
                    print("[+] Payload found in page source")
                return True
            
            # Check for XSS execution indicators
            if self.check_xss_execution(page_source, payload):
                return True
        
        except Exception as e:
            if self.verbose:
                print(f"[!] Error in Selenium test: {e}")
        
        return False
    
    def check_xss_execution(self, response_text, payload):
        """Check for indicators of XSS execution"""
        # Look for common XSS execution patterns
        xss_indicators = [
            'alert(',
            'confirm(',
            'prompt(',
            'document.cookie',
            'javascript:',
            'onerror=',
            'onload=',
            'onclick='
        ]
        
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        for indicator in xss_indicators:
            if indicator in payload_lower and indicator in response_lower:
                if self.verbose:
                    print(f"[+] XSS execution indicator found: {indicator}")
                return True
        
        return False
    
    def run_test(self):
        """Main testing function"""
        print("=" * 60)
        print("XSS Security Testing Tool")
        print("Developer: Eng Mokhtar Alhamadi")
        print("Twitter (X): @M_Alhamadee")
        print("=" * 60)
        print(f"[+] Target URL: {self.target_url}")
        print(f"[+] Payloads file: {self.payloads_file}")
        print(f"[+] Verbose mode: {self.verbose}")
        print(f"[+] Selenium mode: {self.use_selenium}")
        print("=" * 60)
        
        # Load payloads
        payloads = self.load_payloads()
        if not payloads:
            print("[!] No payloads loaded. Exiting...")
            return
        
        print(f"[+] Starting test with {len(payloads)} payloads...")
        print("[+] Testing in progress...")
        
        # Discover target structure
        self.discover_forms()
        
        # Test each payload
        for i, payload in enumerate(payloads, 1):
            if self.verbose:
                print(f"\n[*] Testing payload {i}/{len(payloads)}")
            
            success = False
            
            # Test via GET
            if self.test_payload_get(payload):
                success = True
            
            # Test via POST
            elif self.test_payload_post(payload):
                success = True
            
            # Test via Selenium if enabled
            elif self.use_selenium and self.test_payload_selenium(payload):
                success = True
            
            if success:
                self.successful_payloads.append(payload)
                if not self.verbose:
                    print(f"[+] Successful payload found: {payload[:100]}...")
            
            # Progress indicator for non-verbose mode
            if not self.verbose and i % 10 == 0:
                print(f"[*] Progress: {i}/{len(payloads)} payloads tested")
        
        self.generate_report()
    
    def generate_report(self):
        """Generate and save the final report"""
        print("\n" + "=" * 60)
        print("SECURITY TEST RESULTS")
        print("=" * 60)
        
        if self.successful_payloads:
            print(f"[+] Found {len(self.successful_payloads)} successful XSS payloads:")
            print("-" * 60)
            
            for i, payload in enumerate(self.successful_payloads, 1):
                print(f"{i}. {payload}")
            
            # Save results to file
            try:
                with open('results.txt', 'w', encoding='utf-8') as f:
                    f.write("XSS Security Test Results\n")
                    f.write("=" * 30 + "\n")
                    f.write(f"Target URL: {self.target_url}\n")
                    f.write(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Successful Payloads: {len(self.successful_payloads)}\n\n")
                    
                    for i, payload in enumerate(self.successful_payloads, 1):
                        f.write(f"{i}. {payload}\n")
                
                print(f"\n[+] Results saved to 'results.txt'")
                
            except Exception as e:
                print(f"[!] Error saving results: {e}")
        
        else:
            print("[*] No successful XSS payloads found.")
            print("[*] This could mean:")
            print("    - The target is properly secured")
            print("    - The payloads need to be customized")
            print("    - Additional testing methods are required")
        
        print("=" * 60)
    
    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        
        if self.session:
            self.session.close()

def main():
    parser = argparse.ArgumentParser(
        description='XSS Security Testing Tool - For authorized testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python xss_tester.py -u https://example.com -p payloads.txt
  python xss_tester.py -u https://example.com -p payloads.txt -v
  python xss_tester.py -u https://example.com -p payloads.txt -s --proxy http://127.0.0.1:8080
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-p', '--payloads', required=True, help='Path to payloads file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-s', '--selenium', action='store_true', help='Use Selenium for advanced testing')
    parser.add_argument('--proxy', help='Proxy server (http://user:pass@host:port)')
    
    args = parser.parse_args()
    
    # Validate URL
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print("[!] Error: Invalid URL format. Please use http:// or https://")
        sys.exit(1)
    
    # Security warning
    print("\n" + "!" * 60)
    print("SECURITY WARNING")
    print("!" * 60)
    print("This tool is for authorized security testing only!")
    print("Only test websites you own or have explicit permission to test.")
    print("Unauthorized testing may be illegal in your jurisdiction.")
    print("!" * 60)
    
    response = input("\nDo you have authorization to test this website? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Testing cancelled.")
        sys.exit(0)
    
    # Initialize and run tester
    tester = XSSSecurityTester(
        target_url=args.url,
        payloads_file=args.payloads,
        verbose=args.verbose,
        use_selenium=args.selenium,
        proxy=args.proxy
    )
    
    try:
        tester.run_test()
    except KeyboardInterrupt:
        print("\n[!] Testing interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error during testing: {e}")
    finally:
        tester.cleanup()

if __name__ == "__main__":
    main()
