# app/core/utils/stealth.py
# 스텔스 모드 및 Rate Limiting 대응

import time
import random
import logging
from typing import Dict, Any, Optional, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class StealthMode:
    """
    스텔스 모드: Rate Limiting 대응, User-Agent 로테이션 등
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]
    
    def __init__(
        self,
        delay_min: float = 0.5,
        delay_max: float = 2.0,
        use_proxy: bool = False,
        proxy_list: Optional[List[str]] = None
    ):
        """
        Args:
            delay_min: 최소 딜레이 (초)
            delay_max: 최대 딜레이 (초)
            use_proxy: 프록시 사용 여부
            proxy_list: 프록시 리스트 (예: ["http://proxy1:8080", "http://proxy2:8080"])
        """
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.use_proxy = use_proxy
        self.proxy_list = proxy_list or []
        self.current_ua_index = 0
        self.current_proxy_index = 0
    
    def random_delay(self):
        """랜덤 딜레이"""
        delay = random.uniform(self.delay_min, self.delay_max)
        time.sleep(delay)
        return delay
    
    def get_random_user_agent(self) -> str:
        """랜덤 User-Agent 반환"""
        return random.choice(self.USER_AGENTS)
    
    def rotate_user_agent(self) -> str:
        """User-Agent 로테이션"""
        ua = self.USER_AGENTS[self.current_ua_index]
        self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
        return ua
    
    def get_headers(self, custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        """스텔스 모드 헤더 생성"""
        headers = {
            "User-Agent": self.rotate_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """
        프록시 로테이션
        
        Returns:
            프록시 딕셔너리 또는 None
        """
        if not self.use_proxy or not self.proxy_list:
            return None
        
        proxy_url = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        
        return {
            "http": proxy_url,
            "https": proxy_url
        }


class ConnectionPool:
    """
    연결 풀링을 위한 Session 관리
    """
    
    def __init__(self, max_retries: int = 3, pool_connections: int = 10, pool_maxsize: int = 20):
        """
        Args:
            max_retries: 최대 재시도 횟수
            pool_connections: 연결 풀 크기
            pool_maxsize: 최대 연결 수
        """
        import requests
        
        self.session = requests.Session()
        
        # 재시도 전략
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        
        # HTTP 어댑터 설정
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def get_session(self):
        """Session 반환"""
        return self.session
    
    def close(self):
        """Session 종료"""
        self.session.close()


class TimeoutManager:
    """
    타임아웃 계층화 관리
    """
    
    def __init__(self, connect_timeout: float = 5.0, read_timeout: float = 10.0):
        """
        Args:
            connect_timeout: 연결 타임아웃 (초)
            read_timeout: 읽기 타임아웃 (초)
        """
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
    
    def get_timeout(self) -> tuple:
        """(connect_timeout, read_timeout) 튜플 반환"""
        return (self.connect_timeout, self.read_timeout)
    
    def get_total_timeout(self) -> float:
        """전체 타임아웃 반환"""
        return self.connect_timeout + self.read_timeout

