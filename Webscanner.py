import requests
import re
import ssl
import certifi
from argparse import ArgumentParser
from urllib.parse import urlparse
import socket

parser = ArgumentParser(
    prog='WebScanner',
    description='This is a Website scanner that uses web requests to search for vulnerabilities.',
    epilog='Make sure to check out Stuffy24 on YOUTUBE!'
)
# set up help menu
parser.add_argument('-t', "--target", help="Use the syntax -t to specify your target. Must be in full format https://website.com", required=True)

# parsing command line arguments, needed according to argparse python page
args = parser.parse_args()

def web_url_scanner(urls, verify_ssl=True):
    sensitive_info_pattern = r"(password|api_key|email)"  # You can add more patterns as needed
    allowed_redirects = ["https://example.com", "https://www.example.com"]  # Add your whitelisted URLs
    directory_listing_patterns = ["Index of", "Parent Directory", "Directory Listing", "Directory Contents"]

    for url in urls:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

            # Set verify_ssl parameter for the requests.get() method
            response = requests.get(url, allow_redirects=True, headers=headers, verify=verify_ssl)

            # Check for sensitive information
            if re.search(sensitive_info_pattern, response.text, re.IGNORECASE):
                print(f"Potential sensitive information found in URL: {url}")

            # Check for open redirect vulnerabilities
            if response.url not in allowed_redirects:
                print(f"Open redirect vulnerability found in URL: {url}")
                print(f"Redirect URL: {response.url}")

            # Check SSL/TLS certificate validity if the response is using HTTPS
            if response.url.startswith("https") and response.raw.connection:
                cert = response.raw.connection.getpeercert()
                if ssl.match_hostname(cert, urlparse(response.url).hostname):
                    print(f"SSL/TLS certificate for {response.url} is valid.")
                else:
                    print(f"SSL/TLS certificate for {response.url} is invalid.")

            # Check for directory listing
            if response.status_code == 200 and any(pattern in response.text for pattern in directory_listing_patterns):
                print(f"Directory listing enabled for URL: {url}")

        except requests.exceptions.RequestException:
            print(f"Failed to fetch URL: {url}")

        # Handle SSL/TLS certificate verification failures
        except ssl.SSLError:
            print(f"SSL/TLS certificate for {url} is invalid or could not be verified.")

if __name__ == "__main__":
    urls = [args.target]

    # Check if the URL starts with 'https://' or 'http://' and set verify_ssl accordingly
    if urls[0].startswith("https://"):
        web_url_scanner(urls, verify_ssl=True)
    elif urls[0].startswith("http://"):
        web_url_scanner(urls, verify_ssl=False)
    else:
        print("Invalid URL. Please provide a valid URL starting with 'https://' or 'http://'.")
