import asyncio
import aiohttp
import gzip
import hashlib
import time
from urllib.parse import urljoin, urlparse, parse_qs
from aiohttp import web, ClientTimeout
from aiohttp.web_middlewares import normalize_path_middleware
import logging
import os
from typing import Optional, Dict, Any
import weakref

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MemoryCache:
    """Simple in-memory cache with TTL and size limits"""
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.access_times: Dict[str, float] = {}
    
    def _cleanup_expired(self):
        current_time = time.time()
        expired_keys = []
        for key, data in self.cache.items():
            if current_time > data['expires_at']:
                expired_keys.append(key)
        
        for key in expired_keys:
            self.cache.pop(key, None)
            self.access_times.pop(key, None)
    
    def _evict_lru(self):
        """Evict least recently used items if cache is full"""
        if len(self.cache) >= self.max_size:
            # Sort by access time and remove oldest
            sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])
            keys_to_remove = [k for k, _ in sorted_keys[:len(self.cache) - self.max_size + 10]]
            for key in keys_to_remove:
                self.cache.pop(key, None)
                self.access_times.pop(key, None)
    
    def get(self, key: str) -> Optional[bytes]:
        self._cleanup_expired()
        current_time = time.time()
        
        if key in self.cache:
            data = self.cache[key]
            if current_time <= data['expires_at']:
                self.access_times[key] = current_time
                return data['content']
            else:
                self.cache.pop(key, None)
                self.access_times.pop(key, None)
        return None
    
    def set(self, key: str, content: bytes, ttl: Optional[int] = None):
        self._cleanup_expired()
        self._evict_lru()
        
        ttl = ttl or self.default_ttl
        current_time = time.time()
        
        self.cache[key] = {
            'content': content,
            'expires_at': current_time + ttl,
            'created_at': current_time
        }
        self.access_times[key] = current_time
    
    def clear(self):
        self.cache.clear()
        self.access_times.clear()

class WebProxy:
    def __init__(self):
        self.cache = MemoryCache(max_size=500, default_ttl=300)  # 5 min default TTL
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Timeout configuration
        self.timeout = ClientTimeout(
            total=30,  # Total timeout
            connect=10,  # Connection timeout
            sock_read=20  # Socket read timeout
        )
        
        # Headers to forward from client to target
        self.forward_headers = {
            'user-agent', 'accept', 'accept-language', 'accept-encoding',
            'cache-control', 'referer', 'origin'
        }
        
        # Headers to exclude from response
        self.exclude_response_headers = {
            'connection', 'transfer-encoding', 'content-encoding',
            'content-length', 'server', 'date'
        }
    
    async def init_session(self):
        """Initialize aiohttp session with optimizations"""
        if not self.session:
            connector = aiohttp.TCPConnector(
                limit=100,  # Total connection pool size
                limit_per_host=10,  # Connections per host
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
    
    async def close_session(self):
        """Clean up session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def _get_cache_key(self, url: str, method: str, headers: dict) -> str:
        """Generate cache key for request"""
        # Include method, url, and relevant headers in cache key
        key_data = f"{method}:{url}"
        
        # Add cache-affecting headers
        cache_headers = []
        for header in ['accept', 'accept-language', 'user-agent']:
            if header in headers:
                cache_headers.append(f"{header}:{headers[header]}")
        
        if cache_headers:
            key_data += ":" + "|".join(cache_headers)
        
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _should_cache(self, method: str, status: int, headers: dict) -> bool:
        """Determine if response should be cached"""
        if method != 'GET':
            return False
        
        if status not in (200, 301, 302, 304, 404):
            return False
        
        # Check cache-control headers
        cache_control = headers.get('cache-control', '').lower()
        if 'no-cache' in cache_control or 'no-store' in cache_control:
            return False
        
        return True
    
    def _get_ttl_from_headers(self, headers: dict) -> int:
        """Extract TTL from response headers"""
        cache_control = headers.get('cache-control', '')
        
        # Look for max-age directive
        for directive in cache_control.split(','):
            directive = directive.strip().lower()
            if directive.startswith('max-age='):
                try:
                    return int(directive.split('=')[1])
                except (ValueError, IndexError):
                    pass
        
        # Default TTL based on content type
        content_type = headers.get('content-type', '').lower()
        if any(ct in content_type for ct in ['image/', 'font/', 'css', 'javascript']):
            return 3600  # 1 hour for static assets
        elif 'text/html' in content_type:
            return 300   # 5 minutes for HTML
        
        return 300  # Default 5 minutes
    
    def _compress_content(self, content: bytes, accept_encoding: str) -> tuple[bytes, dict]:
        """Compress content if client supports it"""
        if len(content) < 1024:  # Don't compress small content
            return content, {}
        
        headers = {}
        
        if 'gzip' in accept_encoding.lower():
            try:
                compressed = gzip.compress(content)
                if len(compressed) < len(content):
                    headers['Content-Encoding'] = 'gzip'
                    return compressed, headers
            except Exception as e:
                logger.warning(f"Gzip compression failed: {e}")
        
        return content, headers
    
    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle proxy request"""
        await self.init_session()
        
        # Get target URL from query parameter
        query_params = parse_qs(request.query_string)
        target_urls = query_params.get('url', [])
        
        if not target_urls:
            return web.Response(
                text="Missing 'url' parameter. Usage: /proxy?url=https://example.com",
                status=400
            )
        
        target_url = target_urls[0]
        
        # Validate URL
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return web.Response(text="Invalid URL", status=400)
            if parsed.scheme not in ('http', 'https'):
                return web.Response(text="Only HTTP/HTTPS URLs allowed", status=400)
        except Exception:
            return web.Response(text="Invalid URL format", status=400)
        
        method = request.method
        
        # Prepare headers for upstream request
        upstream_headers = {}
        for header, value in request.headers.items():
            if header.lower() in self.forward_headers:
                upstream_headers[header] = value
        
        # Check cache for GET requests
        cache_key = None
        if method == 'GET':
            cache_key = self._get_cache_key(target_url, method, upstream_headers)
            cached_content = self.cache.get(cache_key)
            if cached_content:
                logger.info(f"Cache HIT for {target_url}")
                
                # Decompress if needed and recompress based on client's Accept-Encoding
                accept_encoding = request.headers.get('Accept-Encoding', '')
                content, compression_headers = self._compress_content(cached_content, accept_encoding)
                
                response_headers = {
                    'X-Proxy-Cache': 'HIT',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': '*',
                    **compression_headers
                }
                
                return web.Response(body=content, headers=response_headers)
        
        try:
            # Make upstream request
            logger.info(f"Fetching {target_url}")
            
            # Prepare request body for POST/PUT requests
            body = None
            if method in ('POST', 'PUT', 'PATCH'):
                body = await request.read()
            
            async with self.session.request(
                method=method,
                url=target_url,
                headers=upstream_headers,
                data=body,
                allow_redirects=True,
                max_redirects=5
            ) as response:
                
                # Read response content
                content = await response.read()
                
                # Prepare response headers
                response_headers = {
                    'X-Proxy-Cache': 'MISS',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': '*',
                }
                
                # Forward selected headers from upstream response
                for header, value in response.headers.items():
                    if header.lower() not in self.exclude_response_headers:
                        response_headers[header] = value
                
                # Cache GET responses if appropriate
                if (cache_key and self._should_cache(method, response.status, response.headers)):
                    ttl = self._get_ttl_from_headers(response.headers)
                    self.cache.set(cache_key, content, ttl)
                    logger.info(f"Cached {target_url} for {ttl} seconds")
                
                # Compress response if client supports it
                accept_encoding = request.headers.get('Accept-Encoding', '')
                compressed_content, compression_headers = self._compress_content(content, accept_encoding)
                response_headers.update(compression_headers)
                
                return web.Response(
                    body=compressed_content,
                    status=response.status,
                    headers=response_headers
                )
                
        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching {target_url}")
            return web.Response(text="Request timeout", status=504)
        except aiohttp.ClientError as e:
            logger.error(f"Client error fetching {target_url}: {e}")
            return web.Response(text=f"Upstream error: {e}", status=502)
        except Exception as e:
            logger.error(f"Unexpected error fetching {target_url}: {e}")
            return web.Response(text="Internal server error", status=500)

    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.Response(text="OK", status=200)
    
    async def handle_cache_stats(self, request: web.Request) -> web.Response:
        """Cache statistics endpoint"""
        stats = {
            'cache_size': len(self.cache.cache),
            'max_size': self.cache.max_size,
            'cached_urls': list(self.cache.cache.keys())[:10]  # Show first 10
        }
        return web.json_response(stats)
    
    async def handle_cache_clear(self, request: web.Request) -> web.Response:
        """Clear cache endpoint"""
        self.cache.clear()
        return web.Response(text="Cache cleared", status=200)

async def create_app() -> web.Application:
    """Create and configure the web application"""
    proxy = WebProxy()
    
    app = web.Application(middlewares=[
        normalize_path_middleware(append_slash=False, remove_slash=True),
    ])
    
    # Routes
    app.router.add_route('*', '/proxy', proxy.handle_request)
    app.router.add_get('/health', proxy.handle_health)
    app.router.add_get('/cache/stats', proxy.handle_cache_stats)
    app.router.add_post('/cache/clear', proxy.handle_cache_clear)
    
    # Root endpoint with usage info
    async def handle_root(request):
        usage_info = """
        Web Proxy Server
        
        Usage:
        GET /proxy?url=https://example.com - Proxy GET request
        POST /proxy?url=https://example.com - Proxy POST request
        
        Management:
        GET /health - Health check
        GET /cache/stats - Cache statistics
        POST /cache/clear - Clear cache
        
        Features:
        - In-memory caching with TTL
        - Gzip compression
        - CORS headers
        - Connection pooling
        - Request/response optimization
        """
        return web.Response(text=usage_info, content_type='text/plain')
    
    app.router.add_get('/', handle_root)
    
    # Cleanup handler
    async def cleanup(app):
        await proxy.close_session()
    
    app.on_cleanup.append(cleanup)
    
    return app

def main():
    """Main entry point"""
    port = int(os.environ.get('PORT', 8080))
    
    app = create_app()
    
    logger.info(f"Starting web proxy server on port {port}")
    web.run_app(app, host='0.0.0.0', port=port)

if __name__ == '__main__':
    main()
