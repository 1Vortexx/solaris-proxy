#!/usr/bin/env python3
"""
Solaris Browser Proxy Server - Render Deployment (Optimized)
A robust HTTP proxy server designed specifically for the Solaris web browser
Optimized for Render.com deployment with enhanced error handling and security
"""

import http.server
import socketserver
import urllib.request
import urllib.parse
import urllib.error
import json
import re
import gzip
import os
import ssl
import socket
import threading
import time
from urllib.parse import urlparse, parse_qs
from io import BytesIO
import logging

# Configure logging for Render
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class SolarisProxyHandler(http.server.BaseHTTPRequestHandler):
    
    def __init__(self, *args, **kwargs):
        # Set timeout for requests
        self.timeout = 30
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests with improved error handling"""
        try:
            parsed_path = urlparse(self.path)
            
            # Enhanced malformed URL detection - catch more patterns
            malformed_patterns = ['/=', '/?url=', '?url==', '&url==', 'url===', '/proxy?url=https%3A//twitter.com/=', '/proxy?url=https%3A//google.com/=']
            
            # Check for malformed URLs more thoroughly
            if (any(pattern in self.path for pattern in malformed_patterns) or 
                self.path.endswith('=') or 
                '==' in self.path or
                '/=' in self.path or
                re.search(r'url=[^&]*=
    
    def do_POST(self):
        """Handle POST requests through proxy"""
        try:
            parsed_path = urlparse(self.path)
            if parsed_path.path == '/proxy':
                self.handle_proxy_request(parsed_path, method='POST')
            else:
                self.send_error_response(404, "Endpoint not found")
        except Exception as e:
            logger.error(f"Error in POST request: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS preflight"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def _handle_relative_url(self, parsed_path):
        """Handle relative URL requests with improved conversion logic"""
        referer = self.headers.get('Referer', '')
        logger.info(f"Handling relative URL: {self.path} with referer: {referer}")
        
        if 'proxy?url=' in referer:
            try:
                # Extract the original URL from referer
                referer_parts = referer.split('proxy?url=')[1].split('&')[0]
                original_url = urllib.parse.unquote(referer_parts)
                original_domain = urlparse(original_url)
                
                # Construct the full URL
                if self.path.startswith('/'):
                    full_url = f"{original_domain.scheme}://{original_domain.netloc}{self.path}"
                else:
                    full_url = f"{original_domain.scheme}://{original_domain.netloc}/{self.path}"
                
                logger.info(f"Converting relative URL '{self.path}' to '{full_url}'")
                
                if self.is_valid_url(full_url):
                    # Redirect to proper proxy URL
                    proxy_url = f"/proxy?url={urllib.parse.quote(full_url, safe='')}"
                    self.send_response(302)
                    self.send_header('Location', proxy_url)
                    self.send_cors_headers()
                    self.end_headers()
                    return
                    
            except Exception as e:
                logger.error(f"Failed to convert relative URL: {e}")
        
        # If conversion fails, reject the request
        logger.warning(f"Rejecting unhandleable relative URL: {self.path}")
        self.send_error_response(404, f"Cannot resolve relative URL")
    
    def handle_health_check(self):
        """Enhanced health check with system info"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        
        health_data = {
            'status': 'healthy',
            'service': 'Solaris Browser Proxy',
            'version': '2.0.0',
            'environment': 'render' if 'RENDER' in os.environ else 'local',
            'timestamp': time.time(),
            'uptime': time.time() - getattr(self.server, 'start_time', time.time()),
            'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
        }
        
        self.wfile.write(json.dumps(health_data, indent=2).encode())
        logger.info("Health check requested")
    
    def handle_proxy_request(self, parsed_path, method='GET'):
        """Enhanced proxy request handling with better error management"""
        query_params = parse_qs(parsed_path.query)
        
        if 'url' not in query_params:
            logger.error("Missing 'url' parameter in proxy request")
            self.send_error_response(400, "Missing 'url' parameter")
            return
        
        target_url = query_params['url'][0]
        
        # Enhanced URL validation and cleaning
        if not target_url or target_url in ['', '=', '==']:
            logger.error(f"Empty or invalid URL detected: '{target_url}'")
            self.send_error_response(400, f"Invalid URL provided")
            return
        
        # Clean up common malformed URL patterns
        if target_url.endswith('/='):
            target_url = target_url[:-2]  # Remove trailing /=
            logger.info(f"Cleaned malformed URL, removed '/=': {target_url}")
        
        if target_url.endswith('=') and not '=' in target_url[:-1]:
            target_url = target_url[:-1]  # Remove trailing =
            logger.info(f"Cleaned malformed URL, removed trailing '=': {target_url}")
        
        # Additional validation after cleaning
        if not target_url or not self.is_valid_url(target_url):
            logger.error(f"URL validation failed after cleaning: {target_url}")
            self.send_error_response(400, "Invalid or blocked URL")
            return
        
        logger.info(f"Proxying {method} request to: {target_url}")
        
        try:
            # Create SSL context for HTTPS requests
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create the request
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length) if content_length > 0 else None
                request = urllib.request.Request(target_url, data=post_data, method='POST')
            else:
                request = urllib.request.Request(target_url)
            
            # Set headers for the request
            self._set_request_headers(request)
            
            # Create opener with SSL context
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
            
            # Make the request with timeout
            response = opener.open(request, timeout=self.timeout)
            
            with response:
                self._process_response(response, target_url)
                
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP Error for {target_url}: {e.code} {e.reason}")
            self.send_error_response(e.code, f"HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            logger.error(f"URL Error for {target_url}: {str(e.reason)}")
            self.send_error_response(502, "Connection failed")
        except socket.timeout:
            logger.error(f"Timeout for {target_url}")
            self.send_error_response(504, "Request timeout")
        except Exception as e:
            logger.error(f"Proxy error for {target_url}: {str(e)}")
            self.send_error_response(500, "Proxy error occurred")
    
    def _process_response(self, response, target_url):
        """Process and modify the response content"""
        try:
            # Get response data
            response_data = response.read()
            content_type = response.headers.get('Content-Type', '')
            content_encoding = response.headers.get('Content-Encoding', '')
            
            # Handle compressed content properly
            if content_encoding:
                logger.info(f"Decompressing content with encoding: {content_encoding}")
                if content_encoding.lower() == 'gzip':
                    try:
                        response_data = gzip.decompress(response_data)
                        logger.info("Successfully decompressed gzip content")
                    except Exception as e:
                        logger.error(f"Failed to decompress gzip content: {e}")
                elif content_encoding.lower() == 'deflate':
                    try:
                        import zlib
                        response_data = zlib.decompress(response_data)
                        logger.info("Successfully decompressed deflate content")
                    except Exception as e:
                        logger.error(f"Failed to decompress deflate content: {e}")
                elif content_encoding.lower() == 'br':
                    try:
                        import brotli
                        response_data = brotli.decompress(response_data)
                        logger.info("Successfully decompressed brotli content")
                    except ImportError:
                        logger.warning("Brotli compression detected but brotli module not available")
                    except Exception as e:
                        logger.error(f"Failed to decompress brotli content: {e}")
            
            # Send response headers first
            self.send_response(response.getcode())
            self._copy_response_headers(response)
            self.send_cors_headers()
            
            # Determine if content should be modified
            should_modify = False
            if content_type:
                if ('text/html' in content_type.lower() or 
                    'text/css' in content_type.lower() or
                    'application/javascript' in content_type.lower() or
                    'text/javascript' in content_type.lower()):
                    should_modify = True
            
            # Only try to decode and modify text content
            if should_modify:
                try:
                    # Try to decode as text
                    if isinstance(response_data, bytes):
                        # Try different encodings
                        for encoding in ['utf-8', 'iso-8859-1', 'windows-1252']:
                            try:
                                text_content = response_data.decode(encoding)
                                logger.info(f"Successfully decoded content with {encoding}")
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            # If all encodings fail, use utf-8 with error handling
                            text_content = response_data.decode('utf-8', errors='replace')
                            logger.warning("Used utf-8 with error replacement for decoding")
                    else:
                        text_content = response_data
                    
                    # Modify content based on type
                    if 'text/html' in content_type.lower():
                        modified_content = self._modify_html_for_proxy(text_content, target_url)
                        response_data = modified_content.encode('utf-8')
                        # Update content type to ensure UTF-8
                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                    elif 'text/css' in content_type.lower():
                        modified_content = self._modify_css_for_proxy(text_content, target_url)
                        response_data = modified_content.encode('utf-8')
                        self.send_header('Content-Type', 'text/css; charset=utf-8')
                    
                    logger.info(f"Content modification completed for {content_type}")
                    
                except Exception as e:
                    logger.error(f"Error modifying content: {e}")
                    # If modification fails, send original data
            
            # Set correct content length
            self.send_header('Content-Length', str(len(response_data)))
            self.end_headers()
            
            # Send the response body
            self.wfile.write(response_data)
            logger.info(f"Successfully proxied: {target_url}")
            
        except Exception as e:
            logger.error(f"Error processing response: {e}")
            raise
    
    def _modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            logger.info(f"Processing HTML content, length: {len(html_content)}")
            
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            # Use HTTPS for Render deployment
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs with better validation
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types and malformed URLs
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:', 'blob:', 'chrome:', 'moz-extension:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Skip empty URLs or just whitespace
                if not url.strip():
                    return match.group(0)
                
                # Skip URLs that end with just '=' (malformed)
                if url.strip() == '=' or url.endswith('/='):
                    logger.warning(f"Skipping malformed URL: {url}")
                    return match.group(0)
                
                # Clean up the URL
                url = url.strip()
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    try:
                        url = urllib.parse.urljoin(base_url, url)
                    except Exception as e:
                        logger.warning(f"Failed to join URL {url}: {e}")
                        return match.group(0)
                
                # Validate the resulting URL
                if not self.is_valid_url(url):
                    logger.warning(f"Invalid URL after processing: {url}")
                    return match.group(0)
                
                # Create proxy URL
                try:
                    encoded_url = urllib.parse.quote(url, safe=':/?#[]@!    def _modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            logger.info(f"Processing HTML content, length: {len(html_content)}")
            
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            # Use HTTPS for Render deployment
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:', 'blob:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                return f'{attr}="{proxy_url}"'
            
            # Replace URLs in various attributes
            url_attributes = ['href', 'src', 'action', 'data-src', 'data-url']
            pattern = f'((?:{"|".join(url_attributes)})\\s*=\\s*["\'])([^"\']+)(["\'])'
            html_content = re.sub(pattern, replace_url, html_content, flags=re.IGNORECASE)
            
            # Handle CSS url() functions
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                if not url.startswith(('http://', 'https://', 'data:', '#', 'blob:')):
                    url = urllib.parse.urljoin(base_url, url)
                    encoded_url = urllib.parse.quote(url, safe='')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'url("{proxy_url}")'
                return match.group(0)
            
            html_content = re.sub(r'url\(\s*([^)]+)\s*\)', replace_css_url, html_content, flags=re.IGNORECASE)
            
            # Add base tag for better relative URL resolution
            if '<head>' in html_content.lower():
                base_tag = f'<base href="{base_domain}/">'
                html_content = re.sub(
                    r'(<head[^>]*>)',
                    f'\\1\n{base_tag}',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error modifying HTML content: {e}")
            return html_content\'()*+,;=')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'{attr}="{proxy_url}"'
                except Exception as e:
                    logger.warning(f"Failed to encode URL {url}: {e}")
                    return match.group(0)
            
            # Replace URLs in various attributes with stricter pattern
            url_attributes = ['href', 'src', 'action', 'data-src', 'data-url', 'data-href']
            pattern = f'((?:{"|".join(url_attributes)})\\s*=\\s*["\'])([^"\'\\s>]+)(["\'])'
            html_content = re.sub(pattern, replace_url, html_content, flags=re.IGNORECASE)
            
            # Handle CSS url() functions with better validation
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                
                # Skip problematic URLs
                if (not url.strip() or 
                    url.startswith(('data:', '#', 'blob:', 'javascript:')) or
                    url.strip() == '=' or 
                    url.endswith('/=')):
                    return match.group(0)
                
                try:
                    if not url.startswith(('http://', 'https://')):
                        url = urllib.parse.urljoin(base_url, url)
                    
                    if self.is_valid_url(url):
                        encoded_url = urllib.parse.quote(url, safe=':/?#[]@!    def _modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            logger.info(f"Processing HTML content, length: {len(html_content)}")
            
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            # Use HTTPS for Render deployment
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:', 'blob:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                return f'{attr}="{proxy_url}"'
            
            # Replace URLs in various attributes
            url_attributes = ['href', 'src', 'action', 'data-src', 'data-url']
            pattern = f'((?:{"|".join(url_attributes)})\\s*=\\s*["\'])([^"\']+)(["\'])'
            html_content = re.sub(pattern, replace_url, html_content, flags=re.IGNORECASE)
            
            # Handle CSS url() functions
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                if not url.startswith(('http://', 'https://', 'data:', '#', 'blob:')):
                    url = urllib.parse.urljoin(base_url, url)
                    encoded_url = urllib.parse.quote(url, safe='')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'url("{proxy_url}")'
                return match.group(0)
            
            html_content = re.sub(r'url\(\s*([^)]+)\s*\)', replace_css_url, html_content, flags=re.IGNORECASE)
            
            # Add base tag for better relative URL resolution
            if '<head>' in html_content.lower():
                base_tag = f'<base href="{base_domain}/">'
                html_content = re.sub(
                    r'(<head[^>]*>)',
                    f'\\1\n{base_tag}',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error modifying HTML content: {e}")
            return html_content\'()*+,;=')
                        proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                        return f'url("{proxy_url}")'
                except Exception as e:
                    logger.warning(f"Failed to process CSS URL {url}: {e}")
                
                return match.group(0)
            
            html_content = re.sub(r'url\(\s*([^)]+)\s*\)', replace_css_url, html_content, flags=re.IGNORECASE)
            
            # Add JavaScript to handle dynamic URL requests and prevent CORS issues
            js_injection = '''
<script>
(function() {
    'use strict';
    
    // Override XMLHttpRequest to proxy requests
    const originalXHR = window.XMLHttpRequest;
    function ProxiedXMLHttpRequest() {
        const xhr = new originalXHR();
        const originalOpen = xhr.open;
        
        xhr.open = function(method, url, async, user, password) {
            // Only proxy absolute URLs
            if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                const proxyUrl = ''' + f'"{proxy_base}/proxy?url="' + ''' + encodeURIComponent(url);
                return originalOpen.call(this, method, proxyUrl, async, user, password);
            }
            return originalOpen.call(this, method, url, async, user, password);
        };
        
        return xhr;
    }
    
    // Copy properties from original constructor
    Object.setPrototypeOf(ProxiedXMLHttpRequest.prototype, originalXHR.prototype);
    Object.setPrototypeOf(ProxiedXMLHttpRequest, originalXHR);
    Object.defineProperty(window, 'XMLHttpRequest', {
        value: ProxiedXMLHttpRequest,
        writable: true,
        configurable: true
    });
    
    // Override fetch API
    const originalFetch = window.fetch;
    window.fetch = function(resource, options) {
        if (typeof resource === 'string' && (resource.startsWith('http://') || resource.startsWith('https://'))) {
            const proxyUrl = ''' + f'"{proxy_base}/proxy?url="' + ''' + encodeURIComponent(resource);
            return originalFetch(proxyUrl, options);
        }
        return originalFetch(resource, options);
    };
    
    console.log('Solaris proxy scripts injected');
})();
</script>
'''
            
            # Add base tag and JavaScript injection
            if '<head>' in html_content.lower():
                base_tag = f'<base href="{base_domain}/">'
                injection = f'\n{base_tag}\n{js_injection}'
                html_content = re.sub(
                    r'(<head[^>]*>)',
                    f'\\1{injection}',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            elif '<html>' in html_content.lower():
                # If no head tag, add after html tag
                html_content = re.sub(
                    r'(<html[^>]*>)',
                    f'\\1\n<head>{js_injection}</head>',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error modifying HTML content: {e}")
            return html_content
    
    def _modify_css_for_proxy(self, css_content, base_url):
        """Modify CSS content for proxy compatibility"""
        try:
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            parsed_base = urlparse(base_url)
            replacement_count = 0
            
            def replace_css_url(match):
                nonlocal replacement_count
                url = match.group(2).strip('\'"')
                
                # Skip data URLs, fragments, and empty URLs
                if url.startswith(('data:', '#', 'about:', 'blob:')) or not url.strip():
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    if url.startswith('//'):
                        url = parsed_base.scheme + ':' + url
                    elif url.startswith('/'):
                        url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
                    else:
                        url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                replacement_count += 1
                return f'url("{proxy_url}")'
            
            # Replace url() functions in CSS
            css_content = re.sub(
                r'url\(\s*(["\']?)([^)]+?)\1\s*\)',
                replace_css_url,
                css_content,
                flags=re.IGNORECASE
            )
            
            logger.info(f"CSS modification complete. Made {replacement_count} replacements.")
            return css_content
            
        except Exception as e:
            logger.error(f"Error modifying CSS content: {e}")
            return css_content
    
    def _set_request_headers(self, request):
        """Set appropriate headers for the proxied request"""
        # Set a realistic User-Agent
        user_agent = self.headers.get('User-Agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        request.add_header('User-Agent', user_agent)
        
        # Copy important headers
        headers_to_copy = [
            'Accept', 'Accept-Language', 'Accept-Encoding',
            'Cookie', 'Authorization', 'Content-Type'
        ]
        
        for header in headers_to_copy:
            if header in self.headers:
                request.add_header(header, self.headers[header])
        
        # Add compression support
        request.add_header('Accept-Encoding', 'gzip, deflate, br')
        
        # Add security headers
        request.add_header('DNT', '1')
        request.add_header('Sec-Fetch-Mode', 'navigate')
        request.add_header('Sec-Fetch-Site', 'cross-site')
    
    def _copy_response_headers(self, response):
        """Copy relevant headers from the response"""
        headers_to_copy = [
            'Content-Type', 'Set-Cookie', 'Cache-Control', 
            'Expires', 'Last-Modified', 'ETag', 'Location'
        ]
        
        for header in headers_to_copy:
            if header in response.headers:
                # Skip headers that might cause issues
                if header.lower() in ['content-length', 'content-encoding', 'transfer-encoding']:
                    continue
                self.send_header(header, response.headers[header])
        
        # Remove frame-busting headers
        frame_busting_headers = ['X-Frame-Options', 'Content-Security-Policy']
        for header in frame_busting_headers:
            if header in response.headers:
                logger.info(f"Removing frame-busting header: {header}")
    
    def send_cors_headers(self):
        """Send comprehensive CORS headers"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        self.send_header('Access-Control-Expose-Headers', 'Content-Length, Content-Type')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def is_valid_url(self, url):
        """Enhanced URL validation with security checks"""
        try:
            parsed = urlparse(url)
            
            # Only allow HTTP and HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Must have a netloc (domain)
            if not parsed.netloc:
                return False
            
            # Enhanced security: block private networks and localhost
            blocked_patterns = [
                'localhost', '127.0.0.1', '0.0.0.0', '[::]',
                '192.168.', '10.', '172.16.', '172.17.', '172.18.',
                '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                '172.29.', '172.30.', '172.31.', 'metadata.google.internal',
                '169.254.', 'link-local'
            ]
            
            domain_lower = parsed.netloc.lower()
            for blocked in blocked_patterns:
                if blocked in domain_lower:
                    logger.warning(f"Blocked potentially dangerous URL: {url}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return False
    
    def serve_status_page(self):
        """Serve an enhanced status page"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_cors_headers()
        self.end_headers()
        
        # Get the current host for display
        host = self.headers.get('Host', 'localhost:8080')
        is_render = 'RENDER' in os.environ
        protocol = 'https' if is_render else 'http'
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solaris Browser Proxy - Enhanced</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: white;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            border-radius: 24px;
            padding: 40px;
            max-width: 700px;
            width: 100%;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        h1 {{
            font-size: 2.8em;
            margin-bottom: 10px;
            text-align: center;
            background: linear-gradient(135deg, #fff 0%, #e0e6ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .subtitle {{
            text-align: center;
            opacity: 0.8;
            margin-bottom: 30px;
            font-size: 1.1em;
        }}
        .status {{
            background: rgba(76, 175, 80, 0.2);
            border: 2px solid rgba(76, 175, 80, 0.5);
            padding: 25px;
            border-radius: 16px;
            margin: 25px 0;
            text-align: center;
        }}
        .status h2 {{
            margin-bottom: 10px;
            font-size: 1.5em;
        }}
        .endpoint {{
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 12px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            font-size: 13px;
            border-left: 4px solid rgba(255, 255, 255, 0.3);
        }}
        .endpoint strong {{
            display: block;
            margin-bottom: 8px;
            font-family: 'Segoe UI', sans-serif;
            color: rgba(255, 255, 255, 0.9);
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 30px;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .card h3 {{
            margin-bottom: 15px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 1.1em;
        }}
        .card ul, .card ol {{
            line-height: 1.6;
            padding-left: 20px;
        }}
        .card li {{
            margin-bottom: 8px;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            margin: 5px 5px 0 0;
        }}
        @media (max-width: 768px) {{
            .grid {{ grid-template-columns: 1fr; }}
            .container {{ padding: 30px 20px; }}
            h1 {{ font-size: 2.2em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Solaris Browser Proxy</h1>
        <div class="subtitle">Enhanced Security & Performance</div>
        
        <div class="status">
            <h2>✅ Server Online & Ready</h2>
            <p>Proxy server is active and optimized for {'Render.com' if is_render else 'local development'}</p>
            <div style="margin-top: 15px;">
                <span class="badge">Version 2.0.0</span>
                <span class="badge">{'Production' if is_render else 'Development'}</span>
                <span class="badge">SSL Ready</span>
            </div>
        </div>
        
        <div style="margin: 30px 0;">
            <h3 style="margin-bottom: 20px; text-align: center;">📡 API Endpoints</h3>
            <div class="endpoint">
                <strong>🌐 Web Proxy:</strong>
                {protocol}://{host}/proxy?url=TARGET_URL
            </div>
            <div class="endpoint">
                <strong>❤️ Health Check:</strong>
                {protocol}://{host}/health
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>🚀 Quick Start</h3>
                <ol>
                    <li>Open your Solaris Browser client</li>
                    <li>Set proxy URL to: <code>{host}</code></li>
                    <li>Enter any website URL</li>
                    <li>Browse with enhanced privacy</li>
                </ol>
            </div>
            
            <div class="card">
                <h3>⚡ Enhanced Features</h3>
                <ul>
                    <li>Advanced CORS handling</li>
                    <li>Smart content modification</li>
                    <li>SSL/TLS support</li>
                    <li>Gzip compression handling</li>
                    <li>Security filtering</li>
                    <li>Performance optimizations</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>🔒 Security</h3>
                <ul>
                    <li>Private network blocking</li>
                    <li>Malformed URL detection</li>
                    <li>Request sanitization</li>
                    <li>Frame-busting removal</li>
                    <li>Timeout protection</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>📊 Monitoring</h3>
                <ul>
                    <li>Health check endpoint</li>
                    <li>Detailed error logging</li>
                    <li>Performance metrics</li>
                    <li>Request tracking</li>
                    <li>System information</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
        
        self.wfile.write(html.encode('utf-8'))
    
    def send_error_response(self, code, message):
        """Send enhanced JSON error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        
        error_data = {
            'error': True,
            'code': code,
            'message': message,
            'timestamp': time.time(),
            'service': 'Solaris Browser Proxy',
            'version': '2.0.0'
        }
        
        self.wfile.write(json.dumps(error_data, indent=2).encode())
    
    def log_message(self, format, *args):
        """Enhanced logging for Render deployment"""
        logger.info(f"{self.address_string()} - {format % args}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Enhanced threaded server with better configuration"""
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 100
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_time = time.time()

def create_server(host, port):
    """Create and configure the enhanced server"""
    server = ThreadedTCPServer((host, port), SolarisProxyHandler)
    
    # Set socket options for better performance
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'):
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    return server

def main():
    """Enhanced main function with better error handling"""
    # Get configuration from environment
    port = int(os.environ.get('PORT', 8080))
    host = '0.0.0.0'  # Bind to all interfaces for cloud deployment
    
    try:
        # Create and configure server
        server = create_server(host, port)
        
        # Enhanced startup logging
        logger.info("=" * 80)
        logger.info("🚀 SOLARIS BROWSER PROXY SERVER v2.0.0")
        logger.info("=" * 80)
        
        if 'RENDER' in os.environ:
            render_hostname = os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'your-app.onrender.com')
            logger.info(f"🌐 Environment: Render.com Production")
            logger.info(f"📡 External URL: https://{render_hostname}")
            logger.info(f"🔒 SSL/TLS: Enabled")
        else:
            logger.info(f"🏠 Environment: Local Development")
            logger.info(f"📡 Local URL: http://{host}:{port}")
            logger.info(f"🔒 SSL/TLS: Disabled")
        
        logger.info(f"🔧 Proxy Endpoint: /proxy?url=TARGET_URL")
        logger.info(f"❤️  Health Check: /health")
        logger.info(f"🧵 Threading: Enabled ({threading.active_count()} threads)")
        logger.info("=" * 80)
        logger.info("✅ Server is ready! Solaris Browser can now connect.")
        logger.info("🛑 Press Ctrl+C to stop the server")
        logger.info("=" * 80)
        
        # Start the server
        server.serve_forever()
        
    except KeyboardInterrupt:
        logger.info("\n" + "=" * 80)
        logger.info("🛑 Server stopped by user (Ctrl+C)")
        logger.info("=" * 80)
    except OSError as e:
        logger.error("=" * 80)
        logger.error(f"❌ Error starting server: {e}")
        if "Address already in use" in str(e):
            logger.error(f"💡 Port {port} is already in use.")
            if 'RENDER' in os.environ:
                logger.error("   This usually means another instance is starting on Render.")
                logger.error("   Wait a moment and try again, or check your Render dashboard.")
            else:
                logger.error(f"   Try using a different port: PORT=8081 python3 {__file__}")
        elif "Permission denied" in str(e):
            logger.error(f"💡 Permission denied for port {port}.")
            logger.error("   Try using a port number above 1024.")
        logger.error("=" * 80)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if 'server' in locals():
            try:
                server.shutdown()
                server.server_close()
                logger.info("🔄 Server cleanup completed")
            except:
                pass

if __name__ == "__main__":
    main(), self.path)):  # URL parameter ending with just =
                
                logger.warning(f"Malformed URL request blocked: {self.path}")
                self.send_error_response(400, "Malformed URL - request rejected")
                return
            
            # Handle relative URLs with better logic
            if (not parsed_path.path.startswith('/proxy') and 
                not parsed_path.path.startswith('/health') and 
                parsed_path.path not in ['/', '']):
                
                self._handle_relative_url(parsed_path)
                return
            
            # Route requests
            if parsed_path.path == '/proxy':
                self.handle_proxy_request(parsed_path)
            elif parsed_path.path == '/health':
                self.handle_health_check()
            elif parsed_path.path == '/' or parsed_path.path == '':
                self.serve_status_page()
            else:
                self.send_error_response(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"Error in GET request: {str(e)}")
            self.send_error_response(500, f"Internal server error")
    
    def do_POST(self):
        """Handle POST requests through proxy"""
        try:
            parsed_path = urlparse(self.path)
            if parsed_path.path == '/proxy':
                self.handle_proxy_request(parsed_path, method='POST')
            else:
                self.send_error_response(404, "Endpoint not found")
        except Exception as e:
            logger.error(f"Error in POST request: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS preflight"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def _handle_relative_url(self, parsed_path):
        """Handle relative URL requests with improved conversion logic"""
        referer = self.headers.get('Referer', '')
        logger.info(f"Handling relative URL: {self.path} with referer: {referer}")
        
        if 'proxy?url=' in referer:
            try:
                # Extract the original URL from referer
                referer_parts = referer.split('proxy?url=')[1].split('&')[0]
                original_url = urllib.parse.unquote(referer_parts)
                original_domain = urlparse(original_url)
                
                # Construct the full URL
                if self.path.startswith('/'):
                    full_url = f"{original_domain.scheme}://{original_domain.netloc}{self.path}"
                else:
                    full_url = f"{original_domain.scheme}://{original_domain.netloc}/{self.path}"
                
                logger.info(f"Converting relative URL '{self.path}' to '{full_url}'")
                
                if self.is_valid_url(full_url):
                    # Redirect to proper proxy URL
                    proxy_url = f"/proxy?url={urllib.parse.quote(full_url, safe='')}"
                    self.send_response(302)
                    self.send_header('Location', proxy_url)
                    self.send_cors_headers()
                    self.end_headers()
                    return
                    
            except Exception as e:
                logger.error(f"Failed to convert relative URL: {e}")
        
        # If conversion fails, reject the request
        logger.warning(f"Rejecting unhandleable relative URL: {self.path}")
        self.send_error_response(404, f"Cannot resolve relative URL")
    
    def handle_health_check(self):
        """Enhanced health check with system info"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        
        health_data = {
            'status': 'healthy',
            'service': 'Solaris Browser Proxy',
            'version': '2.0.0',
            'environment': 'render' if 'RENDER' in os.environ else 'local',
            'timestamp': time.time(),
            'uptime': time.time() - getattr(self.server, 'start_time', time.time()),
            'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
        }
        
        self.wfile.write(json.dumps(health_data, indent=2).encode())
        logger.info("Health check requested")
    
    def handle_proxy_request(self, parsed_path, method='GET'):
        """Enhanced proxy request handling with better error management"""
        query_params = parse_qs(parsed_path.query)
        
        if 'url' not in query_params:
            logger.error("Missing 'url' parameter in proxy request")
            self.send_error_response(400, "Missing 'url' parameter")
            return
        
        target_url = query_params['url'][0]
        logger.info(f"Proxying {method} request to: {target_url}")
        
        # Enhanced URL validation
        if not target_url or target_url in ['', '=', '==']:
            logger.error(f"Invalid URL detected: '{target_url}'")
            self.send_error_response(400, f"Invalid URL provided")
            return
        
        if not self.is_valid_url(target_url):
            logger.error(f"URL validation failed: {target_url}")
            self.send_error_response(400, "Invalid or blocked URL")
            return
        
        try:
            # Create SSL context for HTTPS requests
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create the request
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length) if content_length > 0 else None
                request = urllib.request.Request(target_url, data=post_data, method='POST')
            else:
                request = urllib.request.Request(target_url)
            
            # Set headers for the request
            self._set_request_headers(request)
            
            # Create opener with SSL context
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
            
            # Make the request with timeout
            response = opener.open(request, timeout=self.timeout)
            
            with response:
                self._process_response(response, target_url)
                
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP Error for {target_url}: {e.code} {e.reason}")
            self.send_error_response(e.code, f"HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            logger.error(f"URL Error for {target_url}: {str(e.reason)}")
            self.send_error_response(502, "Connection failed")
        except socket.timeout:
            logger.error(f"Timeout for {target_url}")
            self.send_error_response(504, "Request timeout")
        except Exception as e:
            logger.error(f"Proxy error for {target_url}: {str(e)}")
            self.send_error_response(500, "Proxy error occurred")
    
    def _process_response(self, response, target_url):
        """Process and modify the response content"""
        try:
            # Get response data
            response_data = response.read()
            content_type = response.headers.get('Content-Type', '')
            content_encoding = response.headers.get('Content-Encoding', '')
            
            # Handle compressed content properly
            if content_encoding:
                logger.info(f"Decompressing content with encoding: {content_encoding}")
                if content_encoding.lower() == 'gzip':
                    try:
                        response_data = gzip.decompress(response_data)
                        logger.info("Successfully decompressed gzip content")
                    except Exception as e:
                        logger.error(f"Failed to decompress gzip content: {e}")
                elif content_encoding.lower() == 'deflate':
                    try:
                        import zlib
                        response_data = zlib.decompress(response_data)
                        logger.info("Successfully decompressed deflate content")
                    except Exception as e:
                        logger.error(f"Failed to decompress deflate content: {e}")
                elif content_encoding.lower() == 'br':
                    try:
                        import brotli
                        response_data = brotli.decompress(response_data)
                        logger.info("Successfully decompressed brotli content")
                    except ImportError:
                        logger.warning("Brotli compression detected but brotli module not available")
                    except Exception as e:
                        logger.error(f"Failed to decompress brotli content: {e}")
            
            # Send response headers first
            self.send_response(response.getcode())
            self._copy_response_headers(response)
            self.send_cors_headers()
            
            # Determine if content should be modified
            should_modify = False
            if content_type:
                if ('text/html' in content_type.lower() or 
                    'text/css' in content_type.lower() or
                    'application/javascript' in content_type.lower() or
                    'text/javascript' in content_type.lower()):
                    should_modify = True
            
            # Only try to decode and modify text content
            if should_modify:
                try:
                    # Try to decode as text
                    if isinstance(response_data, bytes):
                        # Try different encodings
                        for encoding in ['utf-8', 'iso-8859-1', 'windows-1252']:
                            try:
                                text_content = response_data.decode(encoding)
                                logger.info(f"Successfully decoded content with {encoding}")
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            # If all encodings fail, use utf-8 with error handling
                            text_content = response_data.decode('utf-8', errors='replace')
                            logger.warning("Used utf-8 with error replacement for decoding")
                    else:
                        text_content = response_data
                    
                    # Modify content based on type
                    if 'text/html' in content_type.lower():
                        modified_content = self._modify_html_for_proxy(text_content, target_url)
                        response_data = modified_content.encode('utf-8')
                        # Update content type to ensure UTF-8
                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                    elif 'text/css' in content_type.lower():
                        modified_content = self._modify_css_for_proxy(text_content, target_url)
                        response_data = modified_content.encode('utf-8')
                        self.send_header('Content-Type', 'text/css; charset=utf-8')
                    
                    logger.info(f"Content modification completed for {content_type}")
                    
                except Exception as e:
                    logger.error(f"Error modifying content: {e}")
                    # If modification fails, send original data
            
            # Set correct content length
            self.send_header('Content-Length', str(len(response_data)))
            self.end_headers()
            
            # Send the response body
            self.wfile.write(response_data)
            logger.info(f"Successfully proxied: {target_url}")
            
        except Exception as e:
            logger.error(f"Error processing response: {e}")
            raise
    
    def _modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            logger.info(f"Processing HTML content, length: {len(html_content)}")
            
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            # Use HTTPS for Render deployment
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs with better validation
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types and malformed URLs
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:', 'blob:', 'chrome:', 'moz-extension:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Skip empty URLs or just whitespace
                if not url.strip():
                    return match.group(0)
                
                # Skip URLs that end with just '=' (malformed)
                if url.strip() == '=' or url.endswith('/='):
                    logger.warning(f"Skipping malformed URL: {url}")
                    return match.group(0)
                
                # Clean up the URL
                url = url.strip()
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    try:
                        url = urllib.parse.urljoin(base_url, url)
                    except Exception as e:
                        logger.warning(f"Failed to join URL {url}: {e}")
                        return match.group(0)
                
                # Validate the resulting URL
                if not self.is_valid_url(url):
                    logger.warning(f"Invalid URL after processing: {url}")
                    return match.group(0)
                
                # Create proxy URL
                try:
                    encoded_url = urllib.parse.quote(url, safe=':/?#[]@!    def _modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            logger.info(f"Processing HTML content, length: {len(html_content)}")
            
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            # Use HTTPS for Render deployment
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:', 'blob:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                return f'{attr}="{proxy_url}"'
            
            # Replace URLs in various attributes
            url_attributes = ['href', 'src', 'action', 'data-src', 'data-url']
            pattern = f'((?:{"|".join(url_attributes)})\\s*=\\s*["\'])([^"\']+)(["\'])'
            html_content = re.sub(pattern, replace_url, html_content, flags=re.IGNORECASE)
            
            # Handle CSS url() functions
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                if not url.startswith(('http://', 'https://', 'data:', '#', 'blob:')):
                    url = urllib.parse.urljoin(base_url, url)
                    encoded_url = urllib.parse.quote(url, safe='')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'url("{proxy_url}")'
                return match.group(0)
            
            html_content = re.sub(r'url\(\s*([^)]+)\s*\)', replace_css_url, html_content, flags=re.IGNORECASE)
            
            # Add base tag for better relative URL resolution
            if '<head>' in html_content.lower():
                base_tag = f'<base href="{base_domain}/">'
                html_content = re.sub(
                    r'(<head[^>]*>)',
                    f'\\1\n{base_tag}',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error modifying HTML content: {e}")
            return html_content\'()*+,;=')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'{attr}="{proxy_url}"'
                except Exception as e:
                    logger.warning(f"Failed to encode URL {url}: {e}")
                    return match.group(0)
            
            # Replace URLs in various attributes with stricter pattern
            url_attributes = ['href', 'src', 'action', 'data-src', 'data-url', 'data-href']
            pattern = f'((?:{"|".join(url_attributes)})\\s*=\\s*["\'])([^"\'\\s>]+)(["\'])'
            html_content = re.sub(pattern, replace_url, html_content, flags=re.IGNORECASE)
            
            # Handle CSS url() functions with better validation
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                
                # Skip problematic URLs
                if (not url.strip() or 
                    url.startswith(('data:', '#', 'blob:', 'javascript:')) or
                    url.strip() == '=' or 
                    url.endswith('/=')):
                    return match.group(0)
                
                try:
                    if not url.startswith(('http://', 'https://')):
                        url = urllib.parse.urljoin(base_url, url)
                    
                    if self.is_valid_url(url):
                        encoded_url = urllib.parse.quote(url, safe=':/?#[]@!    def _modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            logger.info(f"Processing HTML content, length: {len(html_content)}")
            
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            # Use HTTPS for Render deployment
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:', 'blob:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                return f'{attr}="{proxy_url}"'
            
            # Replace URLs in various attributes
            url_attributes = ['href', 'src', 'action', 'data-src', 'data-url']
            pattern = f'((?:{"|".join(url_attributes)})\\s*=\\s*["\'])([^"\']+)(["\'])'
            html_content = re.sub(pattern, replace_url, html_content, flags=re.IGNORECASE)
            
            # Handle CSS url() functions
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                if not url.startswith(('http://', 'https://', 'data:', '#', 'blob:')):
                    url = urllib.parse.urljoin(base_url, url)
                    encoded_url = urllib.parse.quote(url, safe='')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'url("{proxy_url}")'
                return match.group(0)
            
            html_content = re.sub(r'url\(\s*([^)]+)\s*\)', replace_css_url, html_content, flags=re.IGNORECASE)
            
            # Add base tag for better relative URL resolution
            if '<head>' in html_content.lower():
                base_tag = f'<base href="{base_domain}/">'
                html_content = re.sub(
                    r'(<head[^>]*>)',
                    f'\\1\n{base_tag}',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error modifying HTML content: {e}")
            return html_content\'()*+,;=')
                        proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                        return f'url("{proxy_url}")'
                except Exception as e:
                    logger.warning(f"Failed to process CSS URL {url}: {e}")
                
                return match.group(0)
            
            html_content = re.sub(r'url\(\s*([^)]+)\s*\)', replace_css_url, html_content, flags=re.IGNORECASE)
            
            # Add JavaScript to handle dynamic URL requests and prevent CORS issues
            js_injection = '''
<script>
(function() {
    'use strict';
    
    // Override XMLHttpRequest to proxy requests
    const originalXHR = window.XMLHttpRequest;
    function ProxiedXMLHttpRequest() {
        const xhr = new originalXHR();
        const originalOpen = xhr.open;
        
        xhr.open = function(method, url, async, user, password) {
            // Only proxy absolute URLs
            if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                const proxyUrl = ''' + f'"{proxy_base}/proxy?url="' + ''' + encodeURIComponent(url);
                return originalOpen.call(this, method, proxyUrl, async, user, password);
            }
            return originalOpen.call(this, method, url, async, user, password);
        };
        
        return xhr;
    }
    
    // Copy properties from original constructor
    Object.setPrototypeOf(ProxiedXMLHttpRequest.prototype, originalXHR.prototype);
    Object.setPrototypeOf(ProxiedXMLHttpRequest, originalXHR);
    Object.defineProperty(window, 'XMLHttpRequest', {
        value: ProxiedXMLHttpRequest,
        writable: true,
        configurable: true
    });
    
    // Override fetch API
    const originalFetch = window.fetch;
    window.fetch = function(resource, options) {
        if (typeof resource === 'string' && (resource.startsWith('http://') || resource.startsWith('https://'))) {
            const proxyUrl = ''' + f'"{proxy_base}/proxy?url="' + ''' + encodeURIComponent(resource);
            return originalFetch(proxyUrl, options);
        }
        return originalFetch(resource, options);
    };
    
    console.log('Solaris proxy scripts injected');
})();
</script>
'''
            
            # Add base tag and JavaScript injection
            if '<head>' in html_content.lower():
                base_tag = f'<base href="{base_domain}/">'
                injection = f'\n{base_tag}\n{js_injection}'
                html_content = re.sub(
                    r'(<head[^>]*>)',
                    f'\\1{injection}',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            elif '<html>' in html_content.lower():
                # If no head tag, add after html tag
                html_content = re.sub(
                    r'(<html[^>]*>)',
                    f'\\1\n<head>{js_injection}</head>',
                    html_content,
                    flags=re.IGNORECASE,
                    count=1
                )
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error modifying HTML content: {e}")
            return html_content
    
    def _modify_css_for_proxy(self, css_content, base_url):
        """Modify CSS content for proxy compatibility"""
        try:
            # Get proxy base URL
            host = self.headers.get('Host', 'localhost:8080')
            proxy_base = f"https://{host}" if 'RENDER' in os.environ else f"http://{host}"
            
            parsed_base = urlparse(base_url)
            replacement_count = 0
            
            def replace_css_url(match):
                nonlocal replacement_count
                url = match.group(2).strip('\'"')
                
                # Skip data URLs, fragments, and empty URLs
                if url.startswith(('data:', '#', 'about:', 'blob:')) or not url.strip():
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    if url.startswith('//'):
                        url = parsed_base.scheme + ':' + url
                    elif url.startswith('/'):
                        url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
                    else:
                        url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                replacement_count += 1
                return f'url("{proxy_url}")'
            
            # Replace url() functions in CSS
            css_content = re.sub(
                r'url\(\s*(["\']?)([^)]+?)\1\s*\)',
                replace_css_url,
                css_content,
                flags=re.IGNORECASE
            )
            
            logger.info(f"CSS modification complete. Made {replacement_count} replacements.")
            return css_content
            
        except Exception as e:
            logger.error(f"Error modifying CSS content: {e}")
            return css_content
    
    def _set_request_headers(self, request):
        """Set appropriate headers for the proxied request"""
        # Set a realistic User-Agent
        user_agent = self.headers.get('User-Agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        request.add_header('User-Agent', user_agent)
        
        # Copy important headers
        headers_to_copy = [
            'Accept', 'Accept-Language', 'Accept-Encoding',
            'Cookie', 'Authorization', 'Content-Type'
        ]
        
        for header in headers_to_copy:
            if header in self.headers:
                request.add_header(header, self.headers[header])
        
        # Add compression support
        request.add_header('Accept-Encoding', 'gzip, deflate, br')
        
        # Add security headers
        request.add_header('DNT', '1')
        request.add_header('Sec-Fetch-Mode', 'navigate')
        request.add_header('Sec-Fetch-Site', 'cross-site')
    
    def _copy_response_headers(self, response):
        """Copy relevant headers from the response"""
        headers_to_copy = [
            'Content-Type', 'Set-Cookie', 'Cache-Control', 
            'Expires', 'Last-Modified', 'ETag', 'Location'
        ]
        
        for header in headers_to_copy:
            if header in response.headers:
                # Skip headers that might cause issues
                if header.lower() in ['content-length', 'content-encoding', 'transfer-encoding']:
                    continue
                self.send_header(header, response.headers[header])
        
        # Remove frame-busting headers
        frame_busting_headers = ['X-Frame-Options', 'Content-Security-Policy']
        for header in frame_busting_headers:
            if header in response.headers:
                logger.info(f"Removing frame-busting header: {header}")
    
    def send_cors_headers(self):
        """Send comprehensive CORS headers"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        self.send_header('Access-Control-Expose-Headers', 'Content-Length, Content-Type')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def is_valid_url(self, url):
        """Enhanced URL validation with security checks"""
        try:
            parsed = urlparse(url)
            
            # Only allow HTTP and HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Must have a netloc (domain)
            if not parsed.netloc:
                return False
            
            # Enhanced security: block private networks and localhost
            blocked_patterns = [
                'localhost', '127.0.0.1', '0.0.0.0', '[::]',
                '192.168.', '10.', '172.16.', '172.17.', '172.18.',
                '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                '172.29.', '172.30.', '172.31.', 'metadata.google.internal',
                '169.254.', 'link-local'
            ]
            
            domain_lower = parsed.netloc.lower()
            for blocked in blocked_patterns:
                if blocked in domain_lower:
                    logger.warning(f"Blocked potentially dangerous URL: {url}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return False
    
    def serve_status_page(self):
        """Serve an enhanced status page"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_cors_headers()
        self.end_headers()
        
        # Get the current host for display
        host = self.headers.get('Host', 'localhost:8080')
        is_render = 'RENDER' in os.environ
        protocol = 'https' if is_render else 'http'
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solaris Browser Proxy - Enhanced</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: white;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            border-radius: 24px;
            padding: 40px;
            max-width: 700px;
            width: 100%;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        h1 {{
            font-size: 2.8em;
            margin-bottom: 10px;
            text-align: center;
            background: linear-gradient(135deg, #fff 0%, #e0e6ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .subtitle {{
            text-align: center;
            opacity: 0.8;
            margin-bottom: 30px;
            font-size: 1.1em;
        }}
        .status {{
            background: rgba(76, 175, 80, 0.2);
            border: 2px solid rgba(76, 175, 80, 0.5);
            padding: 25px;
            border-radius: 16px;
            margin: 25px 0;
            text-align: center;
        }}
        .status h2 {{
            margin-bottom: 10px;
            font-size: 1.5em;
        }}
        .endpoint {{
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 12px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            font-size: 13px;
            border-left: 4px solid rgba(255, 255, 255, 0.3);
        }}
        .endpoint strong {{
            display: block;
            margin-bottom: 8px;
            font-family: 'Segoe UI', sans-serif;
            color: rgba(255, 255, 255, 0.9);
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 30px;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .card h3 {{
            margin-bottom: 15px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 1.1em;
        }}
        .card ul, .card ol {{
            line-height: 1.6;
            padding-left: 20px;
        }}
        .card li {{
            margin-bottom: 8px;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            margin: 5px 5px 0 0;
        }}
        @media (max-width: 768px) {{
            .grid {{ grid-template-columns: 1fr; }}
            .container {{ padding: 30px 20px; }}
            h1 {{ font-size: 2.2em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Solaris Browser Proxy</h1>
        <div class="subtitle">Enhanced Security & Performance</div>
        
        <div class="status">
            <h2>✅ Server Online & Ready</h2>
            <p>Proxy server is active and optimized for {'Render.com' if is_render else 'local development'}</p>
            <div style="margin-top: 15px;">
                <span class="badge">Version 2.0.0</span>
                <span class="badge">{'Production' if is_render else 'Development'}</span>
                <span class="badge">SSL Ready</span>
            </div>
        </div>
        
        <div style="margin: 30px 0;">
            <h3 style="margin-bottom: 20px; text-align: center;">📡 API Endpoints</h3>
            <div class="endpoint">
                <strong>🌐 Web Proxy:</strong>
                {protocol}://{host}/proxy?url=TARGET_URL
            </div>
            <div class="endpoint">
                <strong>❤️ Health Check:</strong>
                {protocol}://{host}/health
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>🚀 Quick Start</h3>
                <ol>
                    <li>Open your Solaris Browser client</li>
                    <li>Set proxy URL to: <code>{host}</code></li>
                    <li>Enter any website URL</li>
                    <li>Browse with enhanced privacy</li>
                </ol>
            </div>
            
            <div class="card">
                <h3>⚡ Enhanced Features</h3>
                <ul>
                    <li>Advanced CORS handling</li>
                    <li>Smart content modification</li>
                    <li>SSL/TLS support</li>
                    <li>Gzip compression handling</li>
                    <li>Security filtering</li>
                    <li>Performance optimizations</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>🔒 Security</h3>
                <ul>
                    <li>Private network blocking</li>
                    <li>Malformed URL detection</li>
                    <li>Request sanitization</li>
                    <li>Frame-busting removal</li>
                    <li>Timeout protection</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>📊 Monitoring</h3>
                <ul>
                    <li>Health check endpoint</li>
                    <li>Detailed error logging</li>
                    <li>Performance metrics</li>
                    <li>Request tracking</li>
                    <li>System information</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
        
        self.wfile.write(html.encode('utf-8'))
    
    def send_error_response(self, code, message):
        """Send enhanced JSON error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        
        error_data = {
            'error': True,
            'code': code,
            'message': message,
            'timestamp': time.time(),
            'service': 'Solaris Browser Proxy',
            'version': '2.0.0'
        }
        
        self.wfile.write(json.dumps(error_data, indent=2).encode())
    
    def log_message(self, format, *args):
        """Enhanced logging for Render deployment"""
        logger.info(f"{self.address_string()} - {format % args}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Enhanced threaded server with better configuration"""
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 100
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_time = time.time()

def create_server(host, port):
    """Create and configure the enhanced server"""
    server = ThreadedTCPServer((host, port), SolarisProxyHandler)
    
    # Set socket options for better performance
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'):
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    return server

def main():
    """Enhanced main function with better error handling"""
    # Get configuration from environment
    port = int(os.environ.get('PORT', 8080))
    host = '0.0.0.0'  # Bind to all interfaces for cloud deployment
    
    try:
        # Create and configure server
        server = create_server(host, port)
        
        # Enhanced startup logging
        logger.info("=" * 80)
        logger.info("🚀 SOLARIS BROWSER PROXY SERVER v2.0.0")
        logger.info("=" * 80)
        
        if 'RENDER' in os.environ:
            render_hostname = os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'your-app.onrender.com')
            logger.info(f"🌐 Environment: Render.com Production")
            logger.info(f"📡 External URL: https://{render_hostname}")
            logger.info(f"🔒 SSL/TLS: Enabled")
        else:
            logger.info(f"🏠 Environment: Local Development")
            logger.info(f"📡 Local URL: http://{host}:{port}")
            logger.info(f"🔒 SSL/TLS: Disabled")
        
        logger.info(f"🔧 Proxy Endpoint: /proxy?url=TARGET_URL")
        logger.info(f"❤️  Health Check: /health")
        logger.info(f"🧵 Threading: Enabled ({threading.active_count()} threads)")
        logger.info("=" * 80)
        logger.info("✅ Server is ready! Solaris Browser can now connect.")
        logger.info("🛑 Press Ctrl+C to stop the server")
        logger.info("=" * 80)
        
        # Start the server
        server.serve_forever()
        
    except KeyboardInterrupt:
        logger.info("\n" + "=" * 80)
        logger.info("🛑 Server stopped by user (Ctrl+C)")
        logger.info("=" * 80)
    except OSError as e:
        logger.error("=" * 80)
        logger.error(f"❌ Error starting server: {e}")
        if "Address already in use" in str(e):
            logger.error(f"💡 Port {port} is already in use.")
            if 'RENDER' in os.environ:
                logger.error("   This usually means another instance is starting on Render.")
                logger.error("   Wait a moment and try again, or check your Render dashboard.")
            else:
                logger.error(f"   Try using a different port: PORT=8081 python3 {__file__}")
        elif "Permission denied" in str(e):
            logger.error(f"💡 Permission denied for port {port}.")
            logger.error("   Try using a port number above 1024.")
        logger.error("=" * 80)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if 'server' in locals():
            try:
                server.shutdown()
                server.server_close()
                logger.info("🔄 Server cleanup completed")
            except:
                pass

if __name__ == "__main__":
    main()
