import requests
from bs4 import BeautifulSoup
import re
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class TechnologyDetector:
    """
    Class for detecting technologies used by websites
    """
    
    def __init__(self):
        # Technology signatures
        self.signatures = {
            'WordPress': {
                'patterns': [
                    r'wp-content',
                    r'wp-includes',
                    r'wp-json',
                    r'WordPress'
                ],
                'headers': {
                    'X-Powered-By': r'WordPress'
                },
                'meta': {
                    'generator': r'WordPress'
                }
            },
            'Drupal': {
                'patterns': [
                    r'Drupal.settings',
                    r'drupal.js',
                    r'/sites/default/files/'
                ],
                'headers': {
                    'X-Generator': r'Drupal'
                },
                'meta': {
                    'generator': r'Drupal'
                }
            },
            'Joomla': {
                'patterns': [
                    r'/media/jui/',
                    r'/media/system/js/',
                    r'Joomla!'
                ],
                'meta': {
                    'generator': r'Joomla'
                }
            },
            'Bootstrap': {
                'patterns': [
                    r'bootstrap.css',
                    r'bootstrap.min.css',
                    r'bootstrap.js',
                    r'bootstrap.min.js'
                ]
            },
            'jQuery': {
                'patterns': [
                    r'jquery.js',
                    r'jquery.min.js',
                    r'jquery-\d+\.\d+\.\d+'
                ]
            },
            'React': {
                'patterns': [
                    r'react.js',
                    r'react.min.js',
                    r'react-dom.js',
                    r'react-dom.min.js',
                    r'_reactRootContainer'
                ]
            },
            'Angular': {
                'patterns': [
                    r'angular.js',
                    r'angular.min.js',
                    r'ng-app',
                    r'ng-controller',
                    r'ng-model'
                ]
            },
            'Vue.js': {
                'patterns': [
                    r'vue.js',
                    r'vue.min.js',
                    r'v-if',
                    r'v-for',
                    r'v-bind'
                ]
            },
            'Nginx': {
                'headers': {
                    'Server': r'nginx'
                }
            },
            'Apache': {
                'headers': {
                    'Server': r'Apache'
                }
            },
            'IIS': {
                'headers': {
                    'Server': r'Microsoft-IIS'
                }
            },
            'PHP': {
                'headers': {
                    'X-Powered-By': r'PHP'
                }
            },
            'ASP.NET': {
                'headers': {
                    'X-Powered-By': r'ASP.NET',
                    'X-AspNet-Version': r'.'
                }
            },
            'Google Analytics': {
                'patterns': [
                    r'google-analytics.com/analytics.js',
                    r'ga\(\'create\'',
                    r'gtag\(\'js\'',
                    r'GoogleAnalyticsObject'
                ]
            },
            'Cloudflare': {
                'headers': {
                    'Server': r'cloudflare',
                    'CF-RAY': r'.'
                }
            }
        }
    
    def detect_technologies(self, domain_name):
        """
        Detect technologies used by a domain
        
        Args:
            domain_name: Name of the domain to check
            
        Returns:
            Dictionary with detected technologies
        """
        # Ensure domain name has a scheme
        if not domain_name.startswith(('http://', 'https://')):
            url = f"https://{domain_name}"
        else:
            url = domain_name
        
        try:
            # Make request to the domain
            response = requests.get(url, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Initialize results
            results = {
                'url': url,
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'server': response.headers.get('Server', ''),
                'technologies': {},
                'headers': dict(response.headers),
                'meta_tags': {}
            }
            
            # Extract meta tags
            for meta in soup.find_all('meta'):
                if meta.get('name') and meta.get('content'):
                    results['meta_tags'][meta['name']] = meta['content']
            
            # Check for technologies
            html_content = response.text
            
            for tech_name, signatures in self.signatures.items():
                confidence = 0
                matches = []
                
                # Check patterns in HTML content
                if 'patterns' in signatures:
                    for pattern in signatures['patterns']:
                        if re.search(pattern, html_content, re.IGNORECASE):
                            confidence += 1
                            matches.append(f"Pattern match: {pattern}")
                
                # Check headers
                if 'headers' in signatures:
                    for header, pattern in signatures['headers'].items():
                        if header in response.headers and re.search(pattern, response.headers[header], re.IGNORECASE):
                            confidence += 2  # Headers are more reliable
                            matches.append(f"Header match: {header}={response.headers[header]}")
                
                # Check meta tags
                if 'meta' in signatures:
                    for meta_name, pattern in signatures['meta'].items():
                        for meta in soup.find_all('meta', {'name': meta_name}):
                            if meta.get('content') and re.search(pattern, meta['content'], re.IGNORECASE):
                                confidence += 2  # Meta tags are more reliable
                                matches.append(f"Meta tag match: {meta_name}={meta['content']}")
                
                # If confidence > 0, add to results
                if confidence > 0:
                    results['technologies'][tech_name] = {
                        'confidence': confidence,
                        'matches': matches
                    }
            
            return results
        
        except requests.exceptions.RequestException as e:
            print(f"Error detecting technologies for {domain_name}: {e}")
            return {
                'url': url,
                'error': str(e),
                'technologies': {}
            }
    
    def detect_from_url(self, url):
        """
        Detect technologies from a URL
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with detected technologies
        """
        # Parse URL to get domain name
        parsed_url = urlparse(url)
        domain_name = parsed_url.netloc
        
        if not domain_name:
            domain_name = url
        
        return self.detect_technologies(domain_name)

