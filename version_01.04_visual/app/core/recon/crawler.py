"""
Advanced Recursive Web Crawler
- HTML link extraction
- JavaScript API endpoint discovery  
- Recursive crawling with depth limit
- robots.txt & sitemap.xml parsing
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Any
import logging
import time

logger = logging.getLogger(__name__)


class WebCrawler:
    """Recursive web crawler with smart endpoint discovery"""

    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_urls: int = 500,
        timeout: int = 10,
        delay: float = 0.1
    ):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.delay = delay

        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[Dict[str, Any]] = []
        self.api_endpoints: Set[str] = set()

    def crawl(self) -> Dict[str, Any]:
        """Start crawling from target URL"""
        logger.info(f"[CRAWLER] Starting crawl on {self.target_url}")

        start_time = time.time()

        # Parse robots.txt and sitemap.xml first
        self._parse_robots_txt()
        self._parse_sitemap()

        # Recursive crawl
        self._crawl_recursive(self.target_url, depth=0)

        duration = time.time() - start_time

        logger.info(f"[CRAWLER] Completed: {len(self.discovered_urls)} URLs, {len(self.api_endpoints)} API endpoints in {duration:.2f}s")

        return {
            'urls': self.discovered_urls,
            'api_endpoints': list(self.api_endpoints),
            'total_urls': len(self.discovered_urls),
            'duration': duration
        }

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl URL"""

        # Check limits
        if depth > self.max_depth:
            logger.debug(f"[CRAWLER] Max depth reached: {url}")
            return

        if len(self.visited_urls) >= self.max_urls:
            logger.debug(f"[CRAWLER] Max URLs reached")
            return

        if url in self.visited_urls:
            return

        # Only crawl same domain
        if urlparse(url).netloc != self.base_domain:
            return

        self.visited_urls.add(url)

        try:
            logger.debug(f"[CRAWLER] Visiting: {url} (depth: {depth})")

            # Rate limiting
            time.sleep(self.delay)

            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            )

            # Store URL info
            url_info = {
                'url': url,
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'depth': depth,
                'size': len(response.content)
            }
            self.discovered_urls.append(url_info)

            # Parse HTML for links
            if 'text/html' in response.headers.get('Content-Type', ''):
                links = self._extract_html_links(response.text, url)

                # Crawl discovered links
                for link in links:
                    self._crawl_recursive(link, depth + 1)

            # Parse JavaScript for API endpoints
            if 'javascript' in response.headers.get('Content-Type', ''):
                endpoints = self._extract_js_endpoints(response.text)
                self.api_endpoints.update(endpoints)

        except Exception as e:
            logger.warning(f"[CRAWLER] Error crawling {url}: {e}")

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # <a> tags
            for tag in soup.find_all('a', href=True):
                link = urljoin(base_url, tag['href'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

            # <script> tags
            for tag in soup.find_all('script', src=True):
                link = urljoin(base_url, tag['src'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

            # <link> tags (CSS)
            for tag in soup.find_all('link', href=True):
                link = urljoin(base_url, tag['href'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

            # <img> tags
            for tag in soup.find_all('img', src=True):
                link = urljoin(base_url, tag['src'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

        except Exception as e:
            logger.warning(f"[CRAWLER] Error parsing HTML: {e}")

        return links

    def _extract_js_endpoints(self, js_content: str) -> Set[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = set()

        # Common API patterns
        patterns = [
            r'["\']/api/[a-zA-Z0-9/_-]+["\'"]',  # "/api/users"
            r'["\']/v[0-9]+/[a-zA-Z0-9/_-]+["\'"]',  # "/v1/products"
            r'fetch\(["\'"]([^"\'\']+)["\'"]\)',  # fetch("/endpoint")
            r'axios\.(?:get|post|put|delete)\(["\'"]([^"\'\']+)["\'"]',  # axios.get("/endpoint")
            r'\$\.(?:get|post|ajax)\(["\'"]([^"\'\']+)["\'"]',  # $.get("/endpoint")
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Clean up match
                endpoint = match.strip('\'"\'')
                if endpoint.startswith('/'):
                    endpoints.add(endpoint)

        return endpoints

    def _parse_robots_txt(self):
        """Parse robots.txt for hidden paths"""
        robots_url = urljoin(self.target_url, '/robots.txt')

        try:
            response = requests.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                logger.info(f"[CRAWLER] Found robots.txt")

                for line in response.text.split('\n'):
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(self.target_url, path)
                            self.discovered_urls.append({
                                'url': full_url,
                                'status_code': 0,
                                'content_type': 'robots.txt',
                                'depth': 0,
                                'size': 0
                            })

        except Exception as e:
            logger.debug(f"[CRAWLER] No robots.txt: {e}")

    def _parse_sitemap(self):
        """Parse sitemap.xml for URLs"""
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap.xml.gz'
        ]

        for sitemap_path in sitemap_urls:
            sitemap_url = urljoin(self.target_url, sitemap_path)

            try:
                response = requests.get(sitemap_url, timeout=self.timeout)
                if response.status_code == 200:
                    logger.info(f"[CRAWLER] Found sitemap: {sitemap_path}")

                    # Extract <loc> URLs
                    urls = re.findall(r'<loc>([^<]+)</loc>', response.text)
                    for url in urls:
                        if urlparse(url).netloc == self.base_domain:
                            self.discovered_urls.append({
                                'url': url,
                                'status_code': 0,
                                'content_type': 'sitemap.xml',
                                'depth': 0,
                                'size': 0
                            })
                    break

            except Exception as e:
                logger.debug(f"[CRAWLER] No sitemap at {sitemap_path}: {e}")

    def _normalize_url(self, url: str) -> str:
        """Normalize URL (remove fragments, sort params)"""
        try:
            parsed = urlparse(url)

            # Remove fragment
            url = parsed._replace(fragment='').geturl()

            # Only keep same domain
            if parsed.netloc and parsed.netloc != self.base_domain:
                return ''

            return url

        except Exception:
            return ''


def crawl_target(target_url: str, max_depth: int = 3, max_urls: int = 500) -> Dict[str, Any]:
    """
    Crawl target URL and discover all endpoints

    Args:
        target_url: Target URL to crawl
        max_depth: Maximum crawl depth (default: 3)
        max_urls: Maximum URLs to crawl (default: 500)

    Returns:
        Dictionary with discovered URLs and API endpoints
    """
    crawler = WebCrawler(
        target_url=target_url,
        max_depth=max_depth,
        max_urls=max_urls
    )

    return crawler.crawl()
