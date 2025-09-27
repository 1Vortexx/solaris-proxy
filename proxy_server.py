#!/usr/bin/env python3
"""
Solaris Browser Proxy Server - Render Deployment
A simple HTTP proxy server designed specifically for the Solaris web browser
Optimized for Render.com deployment
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
from urllib.parse import urlparse, parse_qs
from io import BytesIO

class SolarisProxyHandler(http.server.BaseHTTPRequestHandler):
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_path = urlparse(self.path)
            
            if parsed_path.path == '/proxy':
                self.handle_proxy_request(parsed_path)
            elif parsed_path.path == '/health':
                self.handle_health_check()
            elif parsed_path.path == '/' or parsed_path.path == '':
                self.serve_status_page()
            else:
                self.send_error_response(404, "Not found")
                
        except Exception as e:
            print(f"Error in GET request: {str(e)}")
            self.send_error_response(500, f"Internal server error: {str(e)}")
    
    def do_POST(self):
        """Handle POST requests through proxy"""
        try:
            parsed_path = urlparse(self.path)
            if parsed_path.path == '/proxy':
                self.handle_proxy_request(parsed_path, method='POST')
            else:
                self.send_error_response(404, "Not found")
        except Exception as e:
            print(f"Error in POST request: {str(e)}")
            self.send_error_response(500, f"Internal server error: {str(e)}")
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS preflight"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def handle_health_check(self):
        """Handle health check requests for monitoring"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        
        health_data = {
            'status': 'healthy',
            'service': 'Solaris Browser Proxy',
            'version': '1.0.0',
            'environment': 'render' if 'RENDER' in os.environ else 'local'
        }
        
        self.wfile.write(json.dumps(health_data).encode())
        print("Health check requested")
    
    def handle_proxy_request(self, parsed_path, method='GET'):
        """Handle proxy requests to external websites"""
        query_params = parse_qs(parsed_path.query)
        
        if 'url' not in query_params:
            self.send_error_response(400, "Missing 'url' parameter")
            return
        
        target_url = query_params['url'][0]
        print(f"Proxying {method} request to: {target_url}")
        
        if not self.is_valid_url(target_url):
            self.send_error_response(400, "Invalid or blocked URL")
            return
        
        try:
            # Create the request
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length) if content_length > 0 else None
                request = urllib.request.Request(target_url, data=post_data, method='POST')
            else:
                request = urllib.request.Request(target_url)
            
            # Set headers for the request
            self.set_request_headers(request)
            
            # Make the request with timeout
            with urllib.request.urlopen(request, timeout=30) as response:
                # Get response data
                response_data = response.read()
                content_type = response.headers.get('Content-Type', '')
                
                # Handle compressed content
                if response.headers.get('Content-Encoding') == 'gzip':
                    try:
                        response_data = gzip.decompress(response_data)
                    except:
                        pass  # If decompression fails, use original data
                
                # Send response headers
                self.send_response(response.getcode())
                self.copy_response_headers(response)
                self.send_cors_headers()
                self.end_headers()
                
                # Modify content if needed
                if 'text/html' in content_type.lower():
                    try:
                        html_content = response_data.decode('utf-8', errors='ignore')
                        modified_html = self.modify_html_for_proxy(html_content, target_url)
                        response_data = modified_html.encode('utf-8')
                    except Exception as e:
                        print(f"Warning: Could not modify HTML content: {e}")
                
                elif 'text/css' in content_type.lower():
                    try:
                        css_content = response_data.decode('utf-8', errors='ignore')
                        modified_css = self.modify_css_for_proxy(css_content, target_url)
                        response_data = modified_css.encode('utf-8')
                    except Exception as e:
                        print(f"Warning: Could not modify CSS content: {e}")
                
                # Send the response body
                self.wfile.write(response_data)
                print(f"Successfully proxied: {target_url}")
                
        except urllib.error.HTTPError as e:
            print(f"HTTP Error for {target_url}: {e.code} {e.reason}")
            self.send_error_response(e.code, f"HTTP Error: {e.reason}")
        except urllib.error.URLError as e:
            print(f"URL Error for {target_url}: {str(e.reason)}")
            self.send_error_response(502, f"URL Error: {str(e.reason)}")
        except Exception as e:
            print(f"Proxy error for {target_url}: {str(e)}")
            self.send_error_response(500, f"Proxy error: {str(e)}")
    
    def set_request_headers(self, request):
        """Set appropriate headers for the proxied request"""
        # Set a realistic User-Agent
        user_agent = self.headers.get('User-Agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        request.add_header('User-Agent', user_agent)
        
        # Copy important headers
        headers_to_copy = [
            'Accept', 'Accept-Language', 'Accept-Encoding',
            'Referer', 'Cookie', 'Authorization'
        ]
        
        for header in headers_to_copy:
            if header in self.headers:
                request.add_header(header, self.headers[header])
        
        # Add compression support
        request.add_header('Accept-Encoding', 'gzip, deflate')
        
        # Add DNT header for privacy
        request.add_header('DNT', '1')
    
    def copy_response_headers(self, response):
        """Copy relevant headers from the response"""
        headers_to_copy = [
            'Content-Type', 'Set-Cookie', 'Cache-Control', 
            'Expires', 'Last-Modified', 'ETag', 'Location'
        ]
        
        for header in headers_to_copy:
            if header in response.headers:
                # Skip content-length as we might modify content
                if header.lower() == 'content-length':
                    continue
                # Skip content-encoding as we handle decompression
                if header.lower() == 'content-encoding':
                    continue
                self.send_header(header, response.headers[header])
        
        # Ensure proper content type for common file types
        content_type = response.headers.get('Content-Type', '')
        if not content_type:
            # Guess content type from URL
            if self.path.endswith('.css'):
                self.send_header('Content-Type', 'text/css')
            elif self.path.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript')
            elif self.path.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                self.send_header('Content-Type', f'image/{self.path.split(".")[-1]}')
            elif self.path.endswith('.svg'):
                self.send_header('Content-Type', 'image/svg+xml')
            elif self.path.endswith('.woff'):
                self.send_header('Content-Type', 'font/woff')
            elif self.path.endswith('.woff2'):
                self.send_header('Content-Type', 'font/woff2')
    
    def send_cors_headers(self):
        """Send CORS headers to allow browser access"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def modify_html_for_proxy(self, html_content, base_url):
        """Modify HTML content to work through the proxy"""
        try:
            # Get the current host (Render URL or localhost)
            host = self.headers.get('Host', 'localhost:8080')
            proxy_base = f"http://{host}" if not host.startswith('http') else host
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Function to replace URLs
            def replace_url(match):
                attr = match.group(1)
                url = match.group(2)
                
                # Skip certain URL types
                skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'data:', '#', 'about:']
                if any(url.lower().startswith(prefix) for prefix in skip_prefixes):
                    return match.group(0)
                
                # Convert relative URL to absolute
                if not url.startswith(('http://', 'https://')):
                    url = urllib.parse.urljoin(base_url, url)
                
                # Create proxy URL
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                return f'{attr}="{proxy_url}"'
            
            # Replace URLs in href, src, and action attributes
            html_content = re.sub(
                r'((?:href|src|action)\s*=\s*["\'])([^"\']+)(["\'])',
                replace_url,
                html_content,
                flags=re.IGNORECASE
            )
            
            # Handle CSS url() functions
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                if not url.startswith(('http://', 'https://', 'data:', '#')):
                    url = urllib.parse.urljoin(base_url, url)
                    encoded_url = urllib.parse.quote(url, safe='')
                    proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                    return f'url("{proxy_url}")'
                return match.group(0)
            
            html_content = re.sub(
                r'url\(\s*([^)]+)\s*\)',
                replace_css_url,
                html_content,
                flags=re.IGNORECASE
            )
            
            return html_content
            
        except Exception as e:
            print(f"Error modifying HTML: {e}")
            return html_content
    
    def modify_css_for_proxy(self, css_content, base_url):
        """Modify CSS content to work through the proxy"""
        try:
            # Get the current host (Render URL or localhost)
            host = self.headers.get('Host', 'localhost:8080')
            proxy_base = f"https://{host}" if not host.startswith('http') else host
            
            # Parse base URL
            parsed_base = urlparse(base_url)
            
            # Function to replace URLs in CSS
            def replace_css_url(match):
                url = match.group(1).strip('\'"')
                
                # Skip data URLs and fragments
                if url.startswith(('data:', '#', 'about:')):
                    return match.group(0)
                
                # Skip empty URLs
                if not url.strip():
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
                return f'url("{proxy_url}")'
            
            # Replace url() functions in CSS
            css_content = re.sub(
                r'url\(\s*(["\']?)([^)]+?)\1\s*\)',
                lambda m: replace_css_url(m) if m.group(2).strip() else m.group(0),
                css_content,
                flags=re.IGNORECASE
            )
            
            # Handle @import statements
            def replace_import_url(match):
                quote = match.group(1)
                url = match.group(2)
                
                if url.startswith(('data:', '#', 'about:')):
                    return match.group(0)
                
                if not url.startswith(('http://', 'https://')):
                    if url.startswith('//'):
                        url = parsed_base.scheme + ':' + url
                    elif url.startswith('/'):
                        url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
                    else:
                        url = urllib.parse.urljoin(base_url, url)
                
                encoded_url = urllib.parse.quote(url, safe='')
                proxy_url = f"{proxy_base}/proxy?url={encoded_url}"
                return f'@import {quote}{proxy_url}{quote}'
            
            # Replace @import statements
            css_content = re.sub(
                r'@import\s+(["\'])([^"\']+)\1',
                replace_import_url,
                css_content,
                flags=re.IGNORECASE
            )
            
            return css_content
            
        except Exception as e:
            print(f"Error modifying CSS: {e}")
            return css_content
    
    def is_valid_url(self, url):
        """Check if the URL is valid and allowed"""
        try:
            parsed = urlparse(url)
            
            # Only allow HTTP and HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Must have a netloc (domain)
            if not parsed.netloc:
                return False
            
            # Block certain domains for security (optional)
            blocked_domains = [
                'localhost', '127.0.0.1', '0.0.0.0',
                '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
            ]
            
            domain_lower = parsed.netloc.lower()
            for blocked in blocked_domains:
                if blocked in domain_lower:
                    return False
            
            return True
            
        except:
            return False
    
    def serve_status_page(self):
        """Serve a status page for the root URL"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_cors_headers()
        self.end_headers()
        
        # Get the current host for display
        host = self.headers.get('Host', 'localhost:8080')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solaris Browser Proxy</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 40px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
            text-align: center;
        }}
        h1 {{
            font-size: 2.5em;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #fff 0%, #e0e6ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .status {{
            background: rgba(76, 175, 80, 0.2);
            border: 1px solid rgba(76, 175, 80, 0.5);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        .endpoint {{
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-family: monospace;
            word-break: break-all;
            font-size: 14px;
        }}
        .instructions {{
            text-align: left;
            margin-top: 30px;
        }}
        .instructions h3 {{
            color: rgba(255, 255, 255, 0.9);
            margin-bottom: 15px;
        }}
        .instructions ol, .instructions ul {{
            line-height: 1.6;
            padding-left: 20px;
        }}
        .instructions li {{
            margin-bottom: 8px;
            color: rgba(255, 255, 255, 0.8);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Solaris Browser Proxy</h1>
        
        <div class="status">
            <h2>✅ Server Running</h2>
            <p>The proxy server is active and ready to handle requests.</p>
        </div>
        
        <div class="instructions">
            <h3>📡 Proxy Endpoints:</h3>
            <div class="endpoint">
                <strong>Web Proxy:</strong><br>
                https://{host}/proxy?url=TARGET_URL
            </div>
            <div class="endpoint">
                <strong>Health Check:</strong><br>
                https://{host}/health
            </div>
            
            <h3>🌐 How to Use:</h3>
            <ol>
                <li>Open the Solaris Browser HTML file</li>
                <li>Update the proxy URL to: <code>{host}</code></li>
                <li>Enter any website URL in the address bar</li>
                <li>Browse the web with enhanced privacy and security</li>
            </ol>
            
            <h3>🔧 Features:</h3>
            <ul>
                <li>CORS support for browser integration</li>
                <li>HTML content modification for seamless browsing</li>
                <li>Compression handling (gzip)</li>
                <li>Error handling and logging</li>
                <li>Health monitoring endpoint</li>
                <li>Optimized for Render.com deployment</li>
            </ul>
        </div>
    </div>
</body>
</html>"""
        
        self.wfile.write(html.encode('utf-8'))
    
    def send_error_response(self, code, message):
        """Send a JSON error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        
        error_data = {
            'error': True,
            'code': code,
            'message': message,
            'timestamp': self.date_time_string()
        }
        
        self.wfile.write(json.dumps(error_data).encode())
    
    def log_message(self, format, *args):
        """Custom log message format for Render"""
        print(f"[{self.date_time_string()}] {format % args}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Handle requests in separate threads for better performance"""
    allow_reuse_address = True

def create_server(host, port):
    """Create and configure the server"""
    server = ThreadedTCPServer((host, port), SolarisProxyHandler)
    return server

def main():
    """Main function to start the server"""
    # Get port from environment variable (Render sets this automatically)
    port = int(os.environ.get('PORT', 8080))
    host = '0.0.0.0'  # Bind to all interfaces for Render
    
    try:
        server = create_server(host, port)
        
        print("=" * 70)
        print("🚀 SOLARIS BROWSER PROXY SERVER")
        print("=" * 70)
        
        if 'RENDER' in os.environ:
            print("🌐 Environment: Render.com")
            print(f"📡 Server URL: https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'your-app.onrender.com')}")
        else:
            print("🏠 Environment: Local")
            print(f"📡 Server URL: http://{host}:{port}")
        
        print(f"🔧 Proxy endpoint: /proxy?url=TARGET_URL")
        print(f"❤️  Health check: /health")
        print("=" * 70)
        print("✅ Server is ready! You can now use the Solaris Browser.")
        print("🛑 Press Ctrl+C to stop the server")
        print("=" * 70)
        
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("🛑 Server stopped by user")
        print("=" * 70)
    except OSError as e:
        print("=" * 70)
        print(f"❌ Error starting server: {e}")
        if "Address already in use" in str(e):
            print(f"💡 Port {port} is already in use.")
            print("   On Render, this usually means another instance is starting.")
        print("=" * 70)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    finally:
        if 'server' in locals():
            server.server_close()

if __name__ == "__main__":
    main()
