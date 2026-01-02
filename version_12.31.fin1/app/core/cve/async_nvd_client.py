# app/core/cve/async_nvd_client.py

"""
NVD API v2.0 비동기 클라이언트 (최적화 버전)
- Rate limiting 강화
- CPE 기반 검색
- 403 에러 방지
"""

import asyncio
import aiohttp
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


class AsyncNvdClient:
    """비동기 NVD API 클라이언트"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        results_per_page: int = 50,
        request_timeout: int = 15,
        rate_limit_delay: float = 0.6,
        use_local_cve_search: bool = True  # 로컬 DB 사용 여부
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.results_per_page = results_per_page
        self.request_timeout = request_timeout
        self.rate_limit_delay = rate_limit_delay
        self.use_local_cve_search = use_local_cve_search
        
        # 통계
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "api_errors": 0,
            "rate_limit_errors": 0,
            "total_cves_found": 0
        }
        
        self._last_request_time = 0
    
    
    async def _wait_for_rate_limit(self):
        """Rate limiting: API 호출 간격 제어"""
        current_time = time.time()
        elapsed = current_time - self._last_request_time
        
        if elapsed < self.rate_limit_delay:
            wait_time = self.rate_limit_delay - elapsed
            logger.debug(f"[NVD] Rate limiting: waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
        
        self._last_request_time = time.time()
    
    async def search_cves_by_cpe_local(
        self,
        cpe: str,
        base_url: str = "https://localhost:443"
    ) -> List[Dict[str, Any]]:
        """
        로컬 cve-search Docker에서 CVE 검색
        """
        # 🔥 올바른 엔드포인트: /api/cvefor/{cpe}
        from urllib.parse import quote
        cpe_encoded = quote(cpe, safe='')
        url = f"{base_url}/api/cvefor/{cpe_encoded}"
        
        logger.info(f"[CVE-SEARCH] Querying: {url}")
        
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    self.stats["total_requests"] += 1
                    
                    if response.status == 200:
                        self.stats["successful_requests"] += 1
                        data = await response.json()
                        
                        # 응답 처리
                        if isinstance(data, list):
                            logger.info(f"[CVE-SEARCH] ✅ Found {len(data)} CVEs for {cpe}")
                            return data
                        elif isinstance(data, dict) and "id" in data:
                            logger.info(f"[CVE-SEARCH] ✅ Found 1 CVE for {cpe}")
                            return [data]
                        else:
                            logger.warning(f"[CVE-SEARCH] Unexpected response format")
                            return []
                    
                    elif response.status == 404:
                        logger.info(f"[CVE-SEARCH] No CVEs found for {cpe}")
                        return []
                    
                    else:
                        self.stats["failed_requests"] += 1
                        logger.warning(f"[CVE-SEARCH] HTTP {response.status}")
                        return []
                        
        except Exception as e:
            self.stats["api_errors"] += 1
            logger.exception(f"[CVE-SEARCH] Error for {cpe}: {e}")
            return []

    
    async def search_cves_by_cpe(
        self,
        cpe: str,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        CPE 문자열로 CVE 검색 (로컬/원격 자동 선택)
        """
        # 로컬 DB 우선 사용
        if self.use_local_cve_search:
            logger.info(f"[NVD] Using local cve-search for: {cpe}")
            return await self.search_cves_by_cpe_local(cpe)
        
        # 기존 NVD API 사용
        logger.info(f"[NVD] Using NVD API for: {cpe}")
        await self._wait_for_rate_limit()
        
        params = {
            "cpeName": cpe,
            "resultsPerPage": self.results_per_page
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        all_cves = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                ) as response:
                    self.stats["total_requests"] += 1
                    
                    if response.status == 200:
                        self.stats["successful_requests"] += 1
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        all_cves.extend(vulnerabilities)
                        logger.info(f"[NVD] Found {len(vulnerabilities)} CVEs for {cpe}")
                    
                    elif response.status == 404:
                        logger.warning(f"[NVD] CPE not found in database: {cpe}")
                    
                    elif response.status == 403:
                        self.stats["rate_limit_errors"] += 1
                        logger.error(f"[NVD] 403 Forbidden - Rate limit exceeded")
                    
                    else:
                        self.stats["failed_requests"] += 1
                        logger.warning(f"[NVD] HTTP {response.status} for CPE: {cpe}")
        
        except asyncio.TimeoutError:
            self.stats["api_errors"] += 1
            logger.error(f"[NVD] Timeout for CPE: {cpe}")
        
        except Exception as e:
            self.stats["api_errors"] += 1
            logger.exception(f"[NVD] Exception for CPE {cpe}: {e}")
        
        self.stats["total_cves_found"] += len(all_cves)
        return all_cves[:max_results]
    
    
    async def search_cves_by_keyword(
        self,
        keyword: str,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """키워드로 CVE 검색"""
        logger.info(f"[NVD] Searching by keyword: {keyword}")
        await self._wait_for_rate_limit()
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": self.results_per_page
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        all_cves = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                ) as response:
                    self.stats["total_requests"] += 1
                    
                    if response.status == 200:
                        self.stats["successful_requests"] += 1
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        all_cves.extend(vulnerabilities)
                        logger.info(f"[NVD] Found {len(vulnerabilities)} CVEs for keyword: {keyword}")
                    
                    elif response.status == 403:
                        self.stats["rate_limit_errors"] += 1
                        logger.error(f"[NVD] 403 Forbidden")
                    
                    else:
                        self.stats["failed_requests"] += 1
                        logger.warning(f"[NVD] HTTP {response.status}")
        
        except asyncio.TimeoutError:
            self.stats["api_errors"] += 1
            logger.error(f"[NVD] Timeout")
        
        except Exception as e:
            self.stats["api_errors"] += 1
            logger.exception(f"[NVD] Exception: {e}")
        
        self.stats["total_cves_found"] += len(all_cves)
        return all_cves[:max_results]
    
    
    def get_stats(self) -> Dict[str, int]:
        """통계 정보 반환"""
        return self.stats.copy()
    
    
    def reset_stats(self):
        """통계 초기화"""
        for key in self.stats:
            self.stats[key] = 0
