"""
Smart Directory & Endpoint Discovery
- Hierarchical brute-forcing
- REST API pattern detection
- Common path enumeration
- Response-based filtering
"""

import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Any
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class SmartDiscovery:
    """Smart directory and endpoint discovery with hierarchical enumeration"""

    # REST API common patterns
    REST_PATTERNS = [
        'api', 'v1', 'v2', 'v3', 'rest', 'graphql',
        'users', 'products', 'items', 'posts', 'comments',
        'admin', 'dashboard', 'panel', 'manage',
        'auth', 'login', 'register', 'logout', 'token',
        'upload', 'download', 'files', 'media', 'images',
        'search', 'query', 'filter',
        'settings', 'config', 'profile', 'account'
    ]

    # Common file extensions
    FILE_EXTENSIONS = [
        '.php', '.asp', '.aspx', '.jsp', '.json', '.xml',
        '.html', '.htm', '.txt', '.bak', '.old', '.backup',
        '.config', '.conf', '.ini', '.yml', '.yaml'
    ]

    # Common directories
    COMMON_DIRS = [
        'admin', 'api', 'assets', 'backup', 'bin', 'config',
        'data', 'db', 'debug', 'dev', 'dist', 'docs',
        'downloads', 'files', 'images', 'includes', 'js',
        'lib', 'logs', 'media', 'old', 'public', 'src',
        'static', 'temp', 'test', 'tmp', 'uploads', 'vendor'
    ]

    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        threads: int = 10,
        timeout: int = 5
    ):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout

        self.discovered: List[Dict[str, Any]] = []
        self.tested_urls: Set[str] = set()

    def discover(self) -> Dict[str, Any]:
        """Start smart discovery"""
        logger.info(f"[DISCOVERY] Starting smart enumeration on {self.target_url}")

        start_time = time.time()

        # Phase 1: Check common directories
        logger.info(f"[DISCOVERY] Phase 1: Common directories")
        self._check_common_paths()

        # Phase 2: REST API discovery
        logger.info(f"[DISCOVERY] Phase 2: REST API patterns")
        self._discover_rest_apis()

        # Phase 3: Recursive enumeration on discovered paths
        logger.info(f"[DISCOVERY] Phase 3: Hierarchical enumeration")
        self._hierarchical_enumeration()

        # Phase 4: Common files in discovered directories
        logger.info(f"[DISCOVERY] Phase 4: Common files")
        self._discover_common_files()

        duration = time.time() - start_time

        logger.info(f"[DISCOVERY] Completed: {len(self.discovered)} endpoints in {duration:.2f}s")

        return {
            'endpoints': self.discovered,
            'total': len(self.discovered),
            'duration': duration
        }

    def _check_common_paths(self):
        """Check common directories and files"""
        paths_to_test = []

        # Common directories
        for dir_name in self.COMMON_DIRS:
            paths_to_test.append(f'/{dir_name}')
            paths_to_test.append(f'/{dir_name}/')

        # Common files
        common_files = [
            '/robots.txt', '/sitemap.xml', '/.git/config',
            '/package.json', '/composer.json', '/web.config',
            '/.env', '/.env.local', '/config.php', '/phpinfo.php',
            '/admin.php', '/login.php', '/test.php'
        ]
        paths_to_test.extend(common_files)

        self._test_paths_parallel(paths_to_test)

    def _discover_rest_apis(self):
        """Discover REST API endpoints"""
        api_paths = []

        # /api variations
        for pattern in self.REST_PATTERNS[:10]:  # Top patterns
            api_paths.append(f'/api/{pattern}')
            api_paths.append(f'/api/v1/{pattern}')
            api_paths.append(f'/api/v2/{pattern}')
            api_paths.append(f'/v1/{pattern}')
            api_paths.append(f'/{pattern}/api')

        # GraphQL
        api_paths.extend([
            '/graphql', '/graphiql', '/api/graphql',
            '/v1/graphql', '/console/graphql'
        ])

        # Swagger/OpenAPI
        api_paths.extend([
            '/swagger', '/swagger-ui', '/swagger.json',
            '/api-docs', '/api/swagger.json', '/openapi.json'
        ])

        self._test_paths_parallel(api_paths)

    def _hierarchical_enumeration(self):
        """Recursively enumerate discovered paths"""
        # Get all discovered directories
        discovered_dirs = [
            e['path'] for e in self.discovered
            if e['status_code'] in [200, 201, 301, 302, 401, 403]
            and e['path'].endswith('/')
        ]

        # For each directory, try common sub-paths
        for base_path in discovered_dirs[:20]:  # Limit to top 20
            depth = base_path.count('/')

            if depth >= self.max_depth:
                continue

            sub_paths = []
            for pattern in self.REST_PATTERNS[:15]:  # Top 15 patterns
                sub_paths.append(f'{base_path}{pattern}')
                sub_paths.append(f'{base_path}{pattern}/')

            self._test_paths_parallel(sub_paths)

    def _discover_common_files(self):
        """Discover common files in found directories"""
        discovered_dirs = [
            e['path'] for e in self.discovered
            if e['status_code'] in [200, 301, 302, 403]
            and e['path'].endswith('/')
        ]

        file_paths = []
        for base_dir in discovered_dirs[:10]:  # Top 10 directories
            for ext in self.FILE_EXTENSIONS[:10]:  # Top 10 extensions
                file_paths.append(f'{base_dir}index{ext}')
                file_paths.append(f'{base_dir}config{ext}')
                file_paths.append(f'{base_dir}test{ext}')

        self._test_paths_parallel(file_paths)

    def _test_paths_parallel(self, paths: List[str]):
        """Test multiple paths in parallel"""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._test_path, path): path
                for path in paths
                if path not in self.tested_urls
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.discovered.append(result)
                except Exception as e:
                    logger.debug(f"[DISCOVERY] Error testing path: {e}")

    def _test_path(self, path: str) -> Dict[str, Any]:
        """Test single path"""
        if path in self.tested_urls:
            return None

        self.tested_urls.add(path)
        full_url = urljoin(self.target_url, path)

        try:
            response = requests.get(
                full_url,
                timeout=self.timeout,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            )

            # Interesting status codes
            if response.status_code in [200, 201, 301, 302, 401, 403, 500]:
                logger.info(f"[DISCOVERY] Found: {path} [{response.status_code}]")

                return {
                    'path': path,
                    'full_url': full_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'server': response.headers.get('Server', ''),
                    'interesting': self._is_interesting(response)
                }

        except requests.Timeout:
            logger.debug(f"[DISCOVERY] Timeout: {path}")
        except Exception as e:
            logger.debug(f"[DISCOVERY] Error: {path} - {e}")

        return None

    def _is_interesting(self, response: requests.Response) -> bool:
        """Check if response is interesting"""
        interesting_headers = [
            'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'Server', 'X-Generator', 'X-Drupal-Cache'
        ]

        for header in interesting_headers:
            if header in response.headers:
                return True

        # Check for authentication
        if 'WWW-Authenticate' in response.headers:
            return True

        # Check content
        content_lower = response.text.lower()
        interesting_keywords = [
            'api', 'graphql', 'swagger', 'admin', 'login',
            'dashboard', 'debug', 'test', 'config'
        ]

        for keyword in interesting_keywords:
            if keyword in content_lower:
                return True

        return False


def discover_endpoints(target_url: str, max_depth: int = 3, threads: int = 10) -> Dict[str, Any]:
    """
    Smart endpoint discovery with hierarchical enumeration

    Args:
        target_url: Target URL
        max_depth: Maximum directory depth (default: 3)
        threads: Number of parallel threads (default: 10)

    Returns:
        Dictionary with discovered endpoints
    """
    discovery = SmartDiscovery(
        target_url=target_url,
        max_depth=max_depth,
        threads=threads
    )

    return discovery.discover()
