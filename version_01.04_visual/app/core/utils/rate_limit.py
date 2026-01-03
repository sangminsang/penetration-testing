# app/core/utils/rate_limit.py
# Rate Limiting 감지 및 대응

import time
import logging
from typing import Dict, Any, Optional, List
from collections import deque
import requests

logger = logging.getLogger(__name__)


class RateLimitDetector:
    """
    Rate Limiting 감지 및 대응 (지수 백오프 포함)
    """
    
    def __init__(self, max_requests_per_minute: int = 60, base_delay: float = 1.0):
        """
        Args:
            max_requests_per_minute: 분당 최대 요청 수
            base_delay: 기본 딜레이 (초)
        """
        self.max_requests_per_minute = max_requests_per_minute
        self.base_delay = base_delay
        self.request_times = deque(maxlen=max_requests_per_minute)
        self.blocked = False
        self.blocked_until = None
        self.retry_after = 60
        self.consecutive_failures = 0  # 연속 실패 횟수
        self.max_backoff = 300  # 최대 백오프 시간 (5분)
    
    def check_rate_limit(self, response: requests.Response) -> bool:
        """
        Rate Limiting 감지
        
        Args:
            response: HTTP 응답 객체
        
        Returns:
            Rate limit이 감지되었는지 여부
        """
        # HTTP 429 응답
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    self.retry_after = int(retry_after)
                except:
                    self.retry_after = 60
            
            self.blocked = True
            self.blocked_until = time.time() + self.retry_after
            self.record_failure()  # 지수 백오프용
            
            logger.warning(f"Rate limited (429). Retry after {self.retry_after}s (backoff: {self.get_wait_time():.1f}s)")
            return True
        
        # WAF 차단 페이지 감지
        waf_indicators = [
            "access denied",
            "blocked",
            "captcha",
            "cloudflare",
            "rate limit exceeded",
            "too many requests",
            "quota exceeded",
            "throttled"
        ]
        
        response_text_lower = response.text.lower()
        if any(indicator in response_text_lower for indicator in waf_indicators):
            logger.warning("Possible WAF/Rate limit detection")
            self.blocked = True
            self.record_failure()  # 지수 백오프용
            # 지수 백오프 시간 사용
            backoff_time = min(
                self.base_delay * (2 ** self.consecutive_failures),
                self.max_backoff
            )
            self.blocked_until = time.time() + backoff_time
            return True
        
        # 응답 헤더에서 Rate Limit 정보 확인
        rate_limit_headers = [
            "X-RateLimit-Remaining",
            "X-RateLimit-Limit",
            "X-RateLimit-Reset"
        ]
        
        for header in rate_limit_headers:
            if header in response.headers:
                remaining = response.headers.get("X-RateLimit-Remaining", "1")
                try:
                    if int(remaining) < 5:
                        logger.warning(f"Rate limit approaching. Remaining: {remaining}")
                        return True
                except:
                    pass
        
        return False
    
    def should_wait(self) -> bool:
        """대기해야 하는지 확인"""
        if not self.blocked:
            return False
        
        if self.blocked_until and time.time() < self.blocked_until:
            return True
        
        # 블록 해제
        self.blocked = False
        self.blocked_until = None
        self.record_success()  # 성공 기록 (백오프 리셋)
        return False
    
    def get_wait_time(self) -> float:
        """
        대기 시간 반환 (초)
        
        지수 백오프 전략 적용
        """
        if not self.blocked_until:
            # 지수 백오프 계산
            if self.consecutive_failures > 0:
                backoff_time = min(
                    self.base_delay * (2 ** self.consecutive_failures),
                    self.max_backoff
                )
                return backoff_time
            return 0.0
        
        wait_time = self.blocked_until - time.time()
        return max(0.0, wait_time)
    
    def record_failure(self):
        """실패 기록 (지수 백오프용)"""
        self.consecutive_failures += 1
    
    def record_success(self):
        """성공 기록 (백오프 리셋)"""
        self.consecutive_failures = 0
    
    def record_request(self):
        """요청 기록"""
        self.request_times.append(time.time())
    
    def get_current_rate(self) -> float:
        """현재 요청 속도 계산 (요청/분)"""
        if not self.request_times:
            return 0.0
        
        current_time = time.time()
        # 최근 1분간의 요청 수
        recent_requests = sum(1 for req_time in self.request_times if current_time - req_time < 60)
        
        return recent_requests

