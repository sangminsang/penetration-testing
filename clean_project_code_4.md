# Project Code Extract (Part 4/5)
<<<<<<< HEAD
- **Root:** `d:\3차 프로젝트\worker_entry`
- **Files included:** 15 (Total: 72)

---

## File 46: context_filter.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\context_filter.py`

```python
# app/core/utils/context_filter.py
# 컨텍스트 기반 필터링 강화 (False Positive 감소)

import time
import statistics
import logging
from typing import Dict, Any, Optional
import requests
import math

logger = logging.getLogger(__name__)


class ContextFilter:
    """
    컨텍스트 기반 필터링으로 False Positive 감소
    """
    
    def __init__(self, baseline_samples: int = 3):
        """
        Args:
            baseline_samples: 베이스라인 측정 샘플 수
        """
        self.baseline_samples = baseline_samples
    
    def analyze_response_time_variability(
        self,
        baseline_times: list,
        test_time: float,
        threshold: float = 2.0
    ) -> Dict[str, Any]:
        """
        응답 시간 변동성 분석
        
        베이스라인과 비교하여 통계적으로 유의미한 차이인지 확인
        """
        if not baseline_times:
            return {
                "significant": False,
                "reason": "No baseline data"
            }
        
        mean_baseline = statistics.mean(baseline_times)
        std_baseline = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
        
        # Z-score 계산
        if std_baseline > 0:
            z_score = abs(test_time - mean_baseline) / std_baseline
        else:
            z_score = abs(test_time - mean_baseline) if mean_baseline > 0 else 0
        
        # 통계적으로 유의미한 차이 (threshold 이상)
        is_significant = z_score >= threshold
        
        return {
            "significant": is_significant,
            "z_score": z_score,
            "mean_baseline": mean_baseline,
            "std_baseline": std_baseline,
            "test_time": test_time,
            "difference": abs(test_time - mean_baseline)
        }
    
    def verify_content_type(
        self,
        baseline_response: requests.Response,
        test_response: requests.Response
    ) -> Dict[str, Any]:
        """
        Content-Type 헤더 검증
        
        응답 타입이 변경되었는지 확인
        """
        baseline_ct = baseline_response.headers.get("Content-Type", "").lower()
        test_ct = test_response.headers.get("Content-Type", "").lower()
        
        # Content-Type이 다르면 의심
        type_changed = baseline_ct != test_ct
        
        # JSON 응답인지 확인
        is_json = "application/json" in test_ct
        
        return {
            "type_changed": type_changed,
            "baseline_content_type": baseline_ct,
            "test_content_type": test_ct,
            "is_json": is_json,
            "suspicious": type_changed
        }
    
    def calculate_entropy(self, text: str) -> float:
        """
        응답 엔트로피 계산
        
        높은 엔트로피 = 랜덤 데이터 (에러 메시지 가능성)
        낮은 엔트로피 = 구조화된 데이터 (정상 응답)
        """
        if not text:
            return 0.0
        
        # 문자 빈도 계산
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # 엔트로피 계산 (Shannon entropy)
        entropy = 0.0
        text_len = len(text)
        
        for count in char_freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_response_entropy(
        self,
        baseline_response: requests.Response,
        test_response: requests.Response,
        threshold: float = 1.5
    ) -> Dict[str, Any]:
        """
        응답 엔트로피 분석
        
        에러 메시지는 보통 엔트로피가 높음
        """
        baseline_entropy = self.calculate_entropy(baseline_response.text)
        test_entropy = self.calculate_entropy(test_response.text)
        
        entropy_diff = abs(test_entropy - baseline_entropy)
        
        # 엔트로피 차이가 크면 의심 (에러 메시지 가능성)
        is_suspicious = entropy_diff > threshold
        
        return {
            "baseline_entropy": baseline_entropy,
            "test_entropy": test_entropy,
            "entropy_difference": entropy_diff,
            "is_suspicious": is_suspicious,
            "threshold": threshold
        }
    
    def comprehensive_verification(
        self,
        baseline_responses: list,
        test_response: requests.Response,
        test_time: float
    ) -> Dict[str, Any]:
        """
        종합 검증
        
        모든 컨텍스트 정보를 종합하여 False Positive 여부 판단
        """
        if not baseline_responses:
            return {
                "verified": False,
                "reason": "No baseline data"
            }
        
        # 베이스라인 통계 계산
        baseline_times = [r.elapsed.total_seconds() for r in baseline_responses]
        baseline_lengths = [len(r.text) for r in baseline_responses]
        baseline_response = baseline_responses[0]  # 대표 응답
        
        # 1. 응답 시간 변동성 분석
        time_analysis = self.analyze_response_time_variability(
            baseline_times,
            test_time
        )
        
        # 2. Content-Type 검증
        content_type_analysis = self.verify_content_type(
            baseline_response,
            test_response
        )
        
        # 3. 응답 엔트로피 분석
        entropy_analysis = self.analyze_response_entropy(
            baseline_response,
            test_response
        )
        
        # 4. 응답 길이 비교
        mean_baseline_length = statistics.mean(baseline_lengths)
        test_length = len(test_response.text)
        length_diff = abs(test_length - mean_baseline_length)
        length_diff_ratio = length_diff / mean_baseline_length if mean_baseline_length > 0 else 0
        
        # 종합 판단
        confidence_score = 0.0
        
        # 시간 차이가 유의미하면 +0.3
        if time_analysis["significant"]:
            confidence_score += 0.3
        
        # Content-Type 변경되면 +0.2
        if content_type_analysis["suspicious"]:
            confidence_score += 0.2
        
        # 엔트로피 차이가 크면 +0.2
        if entropy_analysis["is_suspicious"]:
            confidence_score += 0.2
        
        # 응답 길이 차이가 크면 +0.3
        if length_diff_ratio > 0.1:  # 10% 이상 차이
            confidence_score += 0.3
        
        is_verified = confidence_score >= 0.5  # 50% 이상이면 검증됨
        
        return {
            "verified": is_verified,
            "confidence": confidence_score,
            "time_analysis": time_analysis,
            "content_type_analysis": content_type_analysis,
            "entropy_analysis": entropy_analysis,
            "length_analysis": {
                "baseline_mean": mean_baseline_length,
                "test_length": test_length,
                "difference": length_diff,
                "difference_ratio": length_diff_ratio
            }
        }

```
---

## File 47: encoding.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\encoding.py`

```python
# app/core/utils/encoding.py
# 페이로드 인코딩 다양화 (WAF 우회용)

import base64
import urllib.parse
from typing import List


class PayloadEncoder:
    """
    다양한 인코딩 기법을 제공하는 페이로드 인코더
    """
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL 인코딩"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """이중 URL 인코딩"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode 인코딩"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 인코딩"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex 인코딩"""
        return payload.encode().hex()
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML Entity 인코딩"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def mixed_case(payload: str) -> str:
        """대소문자 혼합 (SQL 키워드 우회)"""
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def comment_injection(payload: str, db_type: str = "mysql") -> str:
        """주석 삽입으로 우회"""
        if db_type == "mysql":
            return payload.replace(" ", "/**/").replace("AND", "/**/AND/**/")
        elif db_type == "mssql":
            return payload.replace(" ", "/**/").replace("--", "/*--*/")
        return payload
    
    @staticmethod
    def get_all_encodings(payload: str) -> List[str]:
        """모든 인코딩 변형 반환"""
        encodings = [
            payload,  # 원본
            PayloadEncoder.url_encode(payload),
            PayloadEncoder.double_url_encode(payload),
            PayloadEncoder.base64_encode(payload),
            PayloadEncoder.hex_encode(payload),
            PayloadEncoder.mixed_case(payload),
            PayloadEncoder.comment_injection(payload, "mysql"),
            PayloadEncoder.comment_injection(payload, "mssql"),
        ]
        return encodings


class WAFBypass:
    """
    WAF별 우회 페이로드 데이터베이스
    """
    
    # ModSecurity 우회
    MODSECURITY_BYPASS = [
        "/*!50000SELECT*/",
        "/*!50000UNION*/",
        "/**/UNION/**/SELECT",
        "UNION/*!50000SELECT*/",
    ]
    
    # Cloudflare 우회
    CLOUDFLARE_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION ALL SELECT",
        "/*!50000UNION*//*!50000SELECT*/",
    ]
    
    # AWS WAF 우회
    AWS_WAF_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION/**/SELECT",
    ]
    
    # Imperva 우회
    IMPERVA_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION/**/SELECT/**/",
    ]
    
    @staticmethod
    def get_bypass_payloads(waf_type: str = None) -> List[str]:
        """WAF 타입별 우회 페이로드 반환"""
        if waf_type == "modsecurity":
            return WAFBypass.MODSECURITY_BYPASS
        elif waf_type == "cloudflare":
            return WAFBypass.CLOUDFLARE_BYPASS
        elif waf_type == "aws":
            return WAFBypass.AWS_WAF_BYPASS
        elif waf_type == "imperva":
            return WAFBypass.IMPERVA_BYPASS
        else:
            # 모든 WAF 우회 페이로드 반환
            return (
                WAFBypass.MODSECURITY_BYPASS +
                WAFBypass.CLOUDFLARE_BYPASS +
                WAFBypass.AWS_WAF_BYPASS +
                WAFBypass.IMPERVA_BYPASS
            )

```
---

## File 48: logger.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\logger.py`

```python
# app/core/utils/logger.py
# 로깅 시스템 설정

import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(
    name: str = "scanner",
    log_file: Optional[str] = None,
    level: int = logging.INFO,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    로거 설정 및 반환
    
    Args:
        name: 로거 이름
        log_file: 로그 파일 경로 (None이면 파일 로깅 안 함)
        level: 로깅 레벨
        format_string: 로그 포맷 문자열
    
    Returns:
        설정된 Logger 객체
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 기존 핸들러 제거 (중복 방지)
    if logger.handlers:
        logger.handlers.clear()
    
    # 기본 포맷
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    formatter = logging.Formatter(format_string)
    
    # 콘솔 핸들러
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 파일 핸들러 (지정된 경우)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# 기본 로거 인스턴스
default_logger = setup_logger("scanner", log_file="logs/scanner.log")

```
---

## File 49: rate_limit.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\rate_limit.py`

```python
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

```
---

## File 50: retry.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\retry.py`

```python
# app/core/utils/retry.py
# 재시도 로직 및 지수 백오프 유틸리티

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    재시도 로직과 지수 백오프를 적용하는 데코레이터
    
    Args:
        max_attempts: 최대 시도 횟수
        initial_delay: 초기 지연 시간 (초)
        max_delay: 최대 지연 시간 (초)
        backoff_factor: 백오프 배수
        exceptions: 재시도할 예외 타입
    
    Example:
        @retry_with_backoff(max_attempts=3, initial_delay=1.0)
        def my_function():
            # ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.warning(
                            f"{func.__name__} 실패 (최대 시도 횟수 도달): {e}"
                        )
                        raise
                    
                    logger.debug(
                        f"{func.__name__} 실패 (시도 {attempt}/{max_attempts}): {e}. "
                        f"{delay:.2f}초 후 재시도..."
                    )
                    
                    time.sleep(min(delay, max_delay))
                    delay *= backoff_factor
            
            if last_exception:
                raise last_exception
            
        return wrapper
    return decorator


def retry_on_network_error(
    max_attempts: int = 3,
    initial_delay: float = 2.0
):
    """
    네트워크 오류에 대한 재시도 데코레이터 (간편 버전)
    """
    import requests
    import socket
    
    return retry_with_backoff(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        exceptions=(
            requests.exceptions.RequestException,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            OSError,
            socket.error
        )
    )

```
---

## File 51: stealth.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\stealth.py`

```python
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

```
---

## File 52: threading.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\threading.py`

```python
# app/core/utils/threading.py
# 멀티스레딩 유틸리티

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Any, Optional
import logging

logger = logging.getLogger(__name__)

# tqdm이 있으면 진행 상황 표시, 없으면 기본 출력
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    logger.warning("tqdm이 설치되지 않아 진행 상황 표시를 사용할 수 없습니다. 'pip install tqdm'으로 설치하세요.")


def parallel_execute(
    tasks: List[Callable],
    max_workers: int = 50,
    timeout: Optional[float] = None,
    show_progress: bool = True,
    desc: str = "Processing"
) -> List[Any]:
    """
    여러 작업을 병렬로 실행 (진행 상황 표시 포함)
    
    Args:
        tasks: 실행할 함수 리스트
        max_workers: 최대 워커 스레드 수 (기본값: 50)
        timeout: 각 작업의 타임아웃 (초)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        작업 결과 리스트 (순서는 보장되지 않음)
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 모든 작업 제출
        future_to_task = {executor.submit(task): task for task in tasks}
        
        # 완료된 작업부터 처리
        if show_progress and HAS_TQDM:
            iterator = tqdm(as_completed(future_to_task, timeout=timeout), 
                          total=len(future_to_task), desc=desc)
        else:
            iterator = as_completed(future_to_task, timeout=timeout)
        
        for future in iterator:
            task = future_to_task[future]
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                task_name = task.__name__ if hasattr(task, '__name__') else str(task)
                logger.error(f"작업 실행 실패 ({task_name}): {e}")
                results.append(None)
    
    return results


def parallel_map(
    func: Callable,
    items: List[Any],
    max_workers: int = 50,
    timeout: Optional[float] = None,
    show_progress: bool = True,
    desc: str = "Mapping"
) -> List[Any]:
    """
    map 함수의 병렬 버전 (진행 상황 표시 포함)
    
    Args:
        func: 각 아이템에 적용할 함수
        items: 처리할 아이템 리스트
        max_workers: 최대 워커 스레드 수 (기본값: 50)
        timeout: 각 작업의 타임아웃 (초)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        함수 적용 결과 리스트
    """
    tasks = [lambda item=item: func(item) for item in items]
    return parallel_execute(tasks, max_workers=max_workers, timeout=timeout, 
                          show_progress=show_progress, desc=desc)


def batch_process(
    items: List[Any],
    processor: Callable,
    batch_size: int = 10,
    max_workers: int = 20,
    show_progress: bool = True,
    desc: str = "Batch Processing"
) -> List[Any]:
    """
    아이템을 배치로 나누어 병렬 처리 (진행 상황 표시 포함)
    
    Args:
        items: 처리할 아이템 리스트
        processor: 각 배치를 처리할 함수 (배치 리스트를 받음)
        batch_size: 배치 크기
        max_workers: 최대 워커 스레드 수 (기본값: 20)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        처리 결과 리스트
    """
    # 배치로 나누기
    batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    
    # 각 배치를 병렬 처리
    tasks = [lambda batch=batch: processor(batch) for batch in batches]
    batch_results = parallel_execute(tasks, max_workers=max_workers, 
                                    show_progress=show_progress, desc=desc)
    
    # 결과 합치기
    results = []
    for batch_result in batch_results:
        if batch_result:
            results.extend(batch_result)
    
    return results


def parallel_scan(
    targets: List[str],
    scan_func: Callable,
    max_workers: int = 50,
    timeout: Optional[float] = 30,
    show_progress: bool = True,
    desc: str = "Scanning"
) -> List[Any]:
    """
    병렬 스캔 (진행 상황 표시)
    
    Args:
        targets: 스캔 대상 리스트
        scan_func: 각 타겟에 적용할 스캔 함수
        max_workers: 최대 워커 스레드 수 (기본값: 50)
        timeout: 각 스캔의 타임아웃 (초)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        스캔 결과 리스트
    """
    return parallel_map(
        scan_func,
        targets,
        max_workers=max_workers,
        timeout=timeout,
        show_progress=show_progress,
        desc=desc
    )

```
---

## File 53: verifier.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\verifier.py`

```python
# app/core/verifier.py
"""
Metasploit-style Vulnerability Verifier with Context-Aware Checks
- CVE 기반 취약점 검증
- 서버 환경 자동 감지 (OS/웹서버)
- 컨텍스트 기반 오탐 제거
"""

import requests
import re
import logging
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse
from packaging import version

logger = logging.getLogger(__name__)

# SSL 경고 무시 (개발 환경)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class VulnerabilityVerifier:
    """
    Metasploit-style lightweight vulnerability checker
    
    1. Generic Checks (컨텍스트 인식)
    2. Specialized CVE Checks
    """
    
    def __init__(
        self,
        target_url: str,
        endpoints: List[str],
        cves: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]]
    ):
        """
        Args:
            target_url: 타겟 URL (예: http://127.0.0.1:3000)
            endpoints: 검증할 API 엔드포인트
            cves: CVE 리스트
            technologies: 탐지된 기술 스택
        """
        self.target = target_url.rstrip("/")
        self.endpoints = endpoints
        self.cves = cves
        self.technologies = technologies
        self.results = []
        
        # 🆕 서버 컨텍스트 저장
        self.server_context = {
            "os": "unknown",         # linux, windows, unix, unknown
            "webserver": "unknown",  # apache, nginx, iis, tomcat, unknown
            "language": "unknown",   # php, python, nodejs, java, unknown
            "detected": False
        }
        
        # 기술 버전 정보 저장 (버전 비교용)
        self.tech_versions = {}
        for tech in technologies:
            product = tech.get("product", "").lower()
            ver = tech.get("version", "N/A")
            if ver != "N/A" and ver:
                self.tech_versions[product] = ver
        
        logger.info(f"[VERIFIER] Initialized for {target_url}")
        logger.info(f"[VERIFIER] Endpoints: {len(endpoints)}, CVEs: {len(cves)}, Technologies: {len(technologies)}")
    
    
    # ============================================================================
    # 🆕 Step 0: 서버 컨텍스트 자동 감지
    # ============================================================================
    
    def detect_server_context(self, web_info: Dict = None) -> Dict[str, str]:
        """
        서버 환경 자동 감지 (OS, 웹서버, 언어)
        
        Args:
            web_info: web.py에서 수집한 웹 정보
        
        Returns:
            {"os": "linux/windows", "webserver": "apache/nginx/iis", "language": "php/python"}
        """
        logger.info("[VERIFIER] 🔍 Step 0: Detecting server context...")
        
        # 1️⃣ HTTP 헤더에서 추출
        try:
            response = requests.head(self.target, timeout=5, verify=False, allow_redirects=True)
            server_header = response.headers.get("Server", "").lower()
            x_powered_by = response.headers.get("X-Powered-By", "").lower()
            
            logger.info(f"[VERIFIER] Server header: {server_header}")
            logger.info(f"[VERIFIER] X-Powered-By: {x_powered_by}")
            
            # 웹서버 감지
            if "apache" in server_header or "httpd" in server_header:
                self.server_context["webserver"] = "apache"
            elif "nginx" in server_header:
                self.server_context["webserver"] = "nginx"
            elif "microsoft-iis" in server_header or "iis" in server_header:
                self.server_context["webserver"] = "iis"
            elif "tomcat" in server_header:
                self.server_context["webserver"] = "tomcat"
            
            # OS 감지
            if "ubuntu" in server_header or "debian" in server_header:
                self.server_context["os"] = "linux"
            elif "centos" in server_header or "red hat" in server_header or "fedora" in server_header:
                self.server_context["os"] = "linux"
            elif "unix" in server_header:
                self.server_context["os"] = "unix"
            elif "win" in server_header or "microsoft" in server_header:
                self.server_context["os"] = "windows"
            
            # 언어 감지
            if "php" in x_powered_by:
                self.server_context["language"] = "php"
            elif "asp.net" in x_powered_by:
                self.server_context["language"] = "asp.net"
            elif "express" in x_powered_by or "nodejs" in x_powered_by:
                self.server_context["language"] = "nodejs"
            
        except Exception as e:
            logger.debug(f"[VERIFIER] HTTP header detection failed: {e}")
        
        # 2️⃣ 탐지된 기술에서 추출
        for tech in self.technologies:
            name = tech.get("name", "").lower()
            product = tech.get("product", "").lower()
            
            # 웹서버
            if "apache" in product or "httpd" in product:
                self.server_context["webserver"] = "apache"
            elif "nginx" in product:
                self.server_context["webserver"] = "nginx"
            elif "iis" in product:
                self.server_context["webserver"] = "iis"
            elif "tomcat" in product:
                self.server_context["webserver"] = "tomcat"
            
            # OS
            if "linux" in product or "ubuntu" in product or "debian" in product:
                self.server_context["os"] = "linux"
            elif "windows" in product:
                self.server_context["os"] = "windows"
            elif "unix" in product:
                self.server_context["os"] = "unix"
            
            # 언어
            if "php" in product:
                self.server_context["language"] = "php"
            elif "python" in product:
                self.server_context["language"] = "python"
            elif "node" in product or "nodejs" in product:
                self.server_context["language"] = "nodejs"
            elif "java" in product:
                self.server_context["language"] = "java"
        
        # 3️⃣ web_info에서 추가 정보 추출
        if web_info:
            for tech in web_info.get("web_technologies", []):
                name = tech.get("name", "").lower()
                
                if "apache" in name:
                    self.server_context["webserver"] = "apache"
                elif "nginx" in name:
                    self.server_context["webserver"] = "nginx"
                elif "iis" in name:
                    self.server_context["webserver"] = "iis"
                
                if "php" in name:
                    self.server_context["language"] = "php"
                elif "python" in name:
                    self.server_context["language"] = "python"
        
        self.server_context["detected"] = True
        
        logger.info(f"[VERIFIER] ✅ Server context detected:")
        logger.info(f"[VERIFIER]   - OS: {self.server_context['os']}")
        logger.info(f"[VERIFIER]   - Web Server: {self.server_context['webserver']}")
        logger.info(f"[VERIFIER]   - Language: {self.server_context['language']}")
        
        return self.server_context
    
    
    def get_context_aware_checks(self) -> Dict[str, Dict[str, Any]]:
        """
        서버 컨텍스트에 맞는 검사 항목 반환
        
        Returns:
            {"/path": {"keywords": [...], "severity": "...", "description": "..."}}
        """
        os_type = self.server_context.get("os", "unknown")
        webserver = self.server_context.get("webserver", "unknown")
        language = self.server_context.get("language", "unknown")
        
        # 기본 체크 항목 (모든 환경)
        checks = {
            "/.env": {
                "keywords": ["DB_PASSWORD", "API_KEY", "SECRET"],
                "severity": "critical",
                "description": "Environment configuration file exposed"
            },
            "/.git/config": {
                "keywords": ["core", "repositoryformatversion"],
                "severity": "high",
                "description": "Git repository metadata exposed"
            },
            "/admin": {
                "keywords": ["admin", "dashboard", "control panel"],
                "severity": "medium",
                "description": "Admin panel accessible"
            },
            "/backup": {
                "keywords": ["Index of", "backup", ".sql", ".zip"],
                "severity": "high",
                "description": "Backup files exposed"
            },
        }
        
        # 🆕 Windows + IIS 환경에서만 web.config 체크
        if os_type == "windows" or webserver == "iis":
            checks["/web.config"] = {
                "keywords": ["configuration", "connectionString", "appSettings"],
                "severity": "high",
                "description": "ASP.NET configuration file exposed"
            }
            checks["/Web.config"] = checks["/web.config"]  # 대소문자 구분
            logger.info("[VERIFIER] ✅ Added Windows/IIS checks: web.config")
        else:
            logger.info("[VERIFIER] ⏩ Skipped web.config (not Windows/IIS)")
        
        # 🆕 Linux + Apache 환경에서만 .htaccess 체크
        if (os_type == "linux" or os_type == "unix") or webserver == "apache":
            checks["/.htaccess"] = {
                "keywords": ["RewriteRule", "Allow from", "Deny from"],
                "severity": "medium",
                "description": "Apache configuration file exposed"
            }
            logger.info("[VERIFIER] ✅ Added Linux/Apache checks: .htaccess")
        else:
            logger.info("[VERIFIER] ⏩ Skipped .htaccess (not Linux/Apache)")
        
        # 🆕 PHP 환경에서만 PHP 관련 체크
        if language == "php":
            checks["/config.php"] = {
                "keywords": ["<?php", "DB_HOST", "mysql"],
                "severity": "high",
                "description": "PHP configuration file exposed"
            }
            checks["/phpmyadmin"] = {
                "keywords": ["phpMyAdmin", "pma_username"],
                "severity": "high",
                "description": "Database management interface exposed"
            }
            logger.info("[VERIFIER] ✅ Added PHP checks: config.php, phpmyadmin")
        else:
            logger.info("[VERIFIER] ⏩ Skipped PHP checks (not PHP environment)")
        
        # 🆕 Node.js 환경에서만 package.json 체크
        if language == "nodejs":
            checks["/package.json"] = {
                "keywords": ["dependencies", "scripts", "version"],
                "severity": "low",
                "description": "Node.js package configuration exposed"
            }
            logger.info("[VERIFIER] ✅ Added Node.js checks: package.json")
        
        logger.info(f"[VERIFIER] Total checks to perform: {len(checks)}")
        return checks
    
    
    # ============================================================================
    # Step 1: Generic HTTP Security Checks
    # ============================================================================
    
    def verify_all(self) -> List[Dict[str, Any]]:
        """
        전체 검증 실행
        
        Returns:
            검증 결과 리스트
        """
        print("=" * 70)
        print("[VERIFIER] 🎯 Starting Vulnerability Verification")
        print("=" * 70)
        
        # 🆕 Step 0: 서버 컨텍스트 감지
        self.detect_server_context()
        
        # Step 1: Generic HTTP Security Checks
        print("[VERIFIER] Step 1: Generic HTTP Security Checks...")
        sensitive_paths = self.get_context_aware_checks()
        
        for path, config in sensitive_paths.items():
            self.generic_path_check(path, config)
        
        # Step 2: Specialized CVE Verification
        print("[VERIFIER] Step 2: Specialized CVE Verification...")
        self.run_specialized_checks()
        
        # Step 3: Version-based CVE Confirmation
        print("[VERIFIER] Step 3: Version-based CVE Confirmation...")
        self.run_version_confirmation()
        
        print("=" * 70)
        print(f"[VERIFIER] ✅ Verification Complete: {len(self.results)} checks performed")
        print("=" * 70)
        
        return self.results
    
    
    def generic_path_check(self, path: str, config: Dict[str, Any]):
        """
        일반적인 경로 검사
        
        Args:
            path: 검사할 경로 (예: "/.env")
            config: {"keywords": [...], "severity": "...", "description": "..."}
        """
        result = {
            "cve_id": "GENERIC-CHECK",
            "check_type": "generic",
            "endpoint": path,
            "exploitable": False,
            "confidence": "low",
            "severity": config["severity"],
            "evidence": "",
            "method": "http-get",
            "description": config["description"],
            "safe": True
        }
        
        try:
            url = urljoin(self.target, path)
            response = requests.get(
                url,
                timeout=5,
                verify=False,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=False
            )
            
            # 성공 응답
            if response.status_code == 200:
                content = response.text.lower()
                matched_keywords = [kw for kw in config["keywords"] if kw.lower() in content]
                
                if matched_keywords:
                    result["exploitable"] = True
                    result["confidence"] = "high"
                    result["evidence"] = f"Keywords found: {', '.join(matched_keywords[:3])}"
                    print(f"[VERIFIER]   🚨 EXPLOITABLE: {path} - {config['description']}")
                else:
                    result["evidence"] = "No sensitive keywords detected"
                    print(f"[VERIFIER]   ℹ️  ACCESSIBLE: {path} (but no sensitive content)")
            
            # 리다이렉트
            elif response.status_code in [301, 302, 303, 307, 308]:
                result["evidence"] = f"Redirected (HTTP {response.status_code}) to {response.headers.get('Location', 'unknown')}"
                print(f"[VERIFIER]   ℹ️  REDIRECT: {path}")
            
            # 접근 금지
            elif response.status_code == 403:
                result["evidence"] = f"Forbidden (HTTP {response.status_code})"
                print(f"[VERIFIER]   ✅ PROTECTED: {path}")
            
            # 기타
            else:
                result["evidence"] = f"Not accessible (HTTP {response.status_code})"
                print(f"[VERIFIER]   ✅ SAFE: {path}")
        
        except requests.Timeout:
            result["evidence"] = "Request timeout"
            print(f"[VERIFIER]   ⏱️  TIMEOUT: {path}")
        
        except Exception as e:
            result["evidence"] = f"Check failed: {str(e)}"
            logger.debug(f"[VERIFIER] Generic check error for {path}: {e}")
        
        self.results.append(result)
    
    
    # ============================================================================
    # Step 2: Specialized CVE Checks
    # ============================================================================
    
    def run_specialized_checks(self):
        """
        특정 CVE에 대한 전문 검증 실행
        """
        specialized_handlers = {
            "CVE-2015-9251": self.verify_jquery_xss,
            "CVE-2019-11358": self.verify_jquery_prototype_pollution,
            "CVE-2020-11022": self.verify_jquery_html_injection,
            "CVE-2020-11023": self.verify_jquery_html_injection,
            "CVE-2022-41940": self.verify_engineio_dos,
            "CVE-2022-21676": self.verify_engineio_uncaught_exception,
            "CVE-2023-31125": self.verify_engineio_http_parsing,
        }
        
        for cve in self.cves:
            cve_id = cve.get("cve_id", "")
            
            if cve_id in specialized_handlers:
                print(f"[VERIFIER]   Verifying {cve_id}...")
                handler = specialized_handlers[cve_id]
                
                # 엔드포인트가 있으면 각각 테스트
                if self.endpoints:
                    for endpoint in self.endpoints[:5]:  # 최대 5개
                        result = handler(endpoint, cve)
                        self.results.append(result)
                else:
                    # 엔드포인트 없으면 루트 테스트
                    result = handler("/", cve)
                    self.results.append(result)
    
    
    def verify_jquery_xss(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """jQuery XSS (CVE-2015-9251)"""
        result = {
            "cve_id": "CVE-2015-9251",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "version-check + safe-payload",
            "description": "jQuery <3.0.0 Cross-site Scripting (XSS)",
            "safe": True
        }
        
        try:
            jquery_version = self.tech_versions.get("jquery", None)
            
            if not jquery_version:
                result["evidence"] = "jQuery version not detected"
                return result
            
            if self.is_vulnerable_version(jquery_version, "<", "3.0.0"):
                result["confidence"] = "medium"
                result["evidence"] = f"jQuery {jquery_version} < 3.0.0 detected"
                
                # Safe payload 테스트 (실제 악성 코드 X)
                url = urljoin(self.target, endpoint)
                test_html = "<img src=x>"
                response = requests.post(
                    url,
                    data={"content": test_html},
                    timeout=5,
                    verify=False
                )
                
                if "<img src=x>" in response.text and "sanitize" not in response.text.lower():
                    result["exploitable"] = True
                    result["confidence"] = "high"
                    result["evidence"] = "Unsafe HTML rendering detected (no sanitization)"
                else:
                    result["evidence"] = "HTML appears to be sanitized"
            else:
                result["evidence"] = f"jQuery {jquery_version} >= 3.0.0 (patched)"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
            logger.debug(f"[VERIFIER] jQuery XSS check error: {e}")
        
        return result
    
    
    def verify_jquery_prototype_pollution(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """jQuery Prototype Pollution (CVE-2019-11358)"""
        result = {
            "cve_id": "CVE-2019-11358",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "version-check + pattern-detection",
            "description": "jQuery <3.4.0 Prototype Pollution",
            "safe": True
        }
        
        try:
            jquery_version = self.tech_versions.get("jquery", None)
            
            if not jquery_version:
                result["evidence"] = "jQuery version not detected"
                return result
            
            if self.is_vulnerable_version(jquery_version, "<", "3.4.0"):
                result["exploitable"] = True
                result["confidence"] = "high"
                result["evidence"] = f"jQuery {jquery_version} < 3.4.0 detected (vulnerable to prototype pollution)"
            else:
                result["evidence"] = f"jQuery {jquery_version} >= 3.4.0 (patched)"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
        
        return result
    
    
    def verify_jquery_html_injection(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """jQuery HTML Injection (CVE-2020-11022, CVE-2020-11023)"""
        cve_id = cve.get("cve_id", "CVE-2020-11022")
        
        result = {
            "cve_id": cve_id,
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "version-check",
            "description": "jQuery <3.5.0 HTML Injection",
            "safe": True
        }
        
        try:
            jquery_version = self.tech_versions.get("jquery", None)
            
            if not jquery_version:
                result["evidence"] = "jQuery version not detected"
                return result
            
            if self.is_vulnerable_version(jquery_version, "<", "3.5.0"):
                result["exploitable"] = True
                result["confidence"] = "high"
                result["evidence"] = f"jQuery {jquery_version} < 3.5.0 detected (vulnerable to HTML injection)"
            else:
                result["evidence"] = f"jQuery {jquery_version} >= 3.5.0 (patched)"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
        
        return result
    
    
    def verify_engineio_dos(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engine.IO DoS (CVE-2022-41940)"""
        result = {
            "cve_id": "CVE-2022-41940",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "high"),
            "evidence": "",
            "method": "endpoint-detection + safe-request",
            "description": "Engine.IO <6.2.1 Denial of Service",
            "safe": True
        }
        
        try:
            url = urljoin(self.target, endpoint)
            
            # Engine.IO 엔드포인트 감지
            response = requests.get(
                url,
                params={"EIO": "4", "transport": "polling"},
                timeout=5,
                verify=False
            )
            
            if "engine.io" in response.text.lower() or response.text.startswith("0"):
                result["exploitable"] = True
                result["confidence"] = "high"
                result["evidence"] = "Engine.IO protocol detected (potentially vulnerable)"
            else:
                result["evidence"] = f"Engine.IO not responding (HTTP {response.status_code})"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
        
        return result
    
    
    def verify_engineio_uncaught_exception(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engine.IO Uncaught Exception (CVE-2022-21676)"""
        result = {
            "cve_id": "CVE-2022-21676",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "high"),
            "evidence": "",
            "method": "endpoint-detection",
            "description": "Engine.IO <4.1.2 Uncaught Exception",
            "safe": True
        }
        
        if "engine.io" in endpoint.lower():
            result["exploitable"] = True
            result["confidence"] = "medium"
            result["evidence"] = "Engine.IO endpoint detected (version check required for confirmation)"
        else:
            result["evidence"] = "Not an Engine.IO endpoint"
        
        return result
    
    
    def verify_engineio_http_parsing(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engine.IO HTTP Parsing Vulnerability (CVE-2023-31125)"""
        result = {
            "cve_id": "CVE-2023-31125",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "endpoint-detection",
            "description": "Engine.IO HTTP Request Parsing Vulnerability",
            "safe": True
        }
        
        if "engine.io" in endpoint.lower():
            result["exploitable"] = True
            result["confidence"] = "medium"
            result["evidence"] = "Engine.IO endpoint detected (potentially vulnerable)"
        else:
            result["evidence"] = "Not an Engine.IO endpoint"
        
        return result
    
    
    # ============================================================================
    # Step 3: Version-to-CVE Confirmation
    # ============================================================================
    
    def run_version_confirmation(self):
        """
        NVD 버전 정보와 탐지된 버전 비교
        """
        for cve in self.cves:
            cve_id = cve.get("cve_id", "")
            affected_products = cve.get("affected_products", [])
            
            for product_name, version_range in affected_products:
                detected_version = self.tech_versions.get(product_name, None)
                
                if detected_version:
                    result = {
                        "cve_id": cve_id,
                        "check_type": "version_confirmation",
                        "endpoint": "N/A",
                        "exploitable": False,
                        "confidence": "low",
                        "severity": cve.get("severity", "unknown"),
                        "evidence": "",
                        "method": "version_comparison",
                        "description": f"{product_name.title()} version matches CVE affected range",
                        "safe": True
                    }
                    
                    if self.version_in_range(detected_version, version_range):
                        result["exploitable"] = True
                        result["confidence"] = "high"
                        result["evidence"] = f"{product_name} {detected_version} matches affected range: {version_range}"
                        print(f"[VERIFIER]   ✅ CONFIRMED: {cve_id} affects {product_name} {detected_version}")
                    else:
                        result["evidence"] = f"{product_name} {detected_version} NOT in affected range: {version_range}"
                        print(f"[VERIFIER]   ✅ SAFE: {cve_id} does not affect {product_name} {detected_version}")
                    
                    self.results.append(result)
    
    
    # ============================================================================
    # Helper Functions
    # ============================================================================
    
    def is_vulnerable_version(self, current: str, operator: str, threshold: str) -> bool:
        """
        버전 비교
        
        Args:
            current: "2.2.4"
            operator: "<", "<=", ">", ">=", "=="
            threshold: "3.0.0"
        
        Returns:
            True if vulnerable
        """
        try:
            curr_ver = version.parse(current)
            threshold_ver = version.parse(threshold)
            
            if operator == "<":
                return curr_ver < threshold_ver
            elif operator == "<=":
                return curr_ver <= threshold_ver
            elif operator == ">":
                return curr_ver > threshold_ver
            elif operator == ">=":
                return curr_ver >= threshold_ver
            elif operator == "==":
                return curr_ver == threshold_ver
            else:
                return False
        
        except Exception as e:
            logger.debug(f"[VERIFIER] Version comparison error: {e}")
            return False
    
    
    def version_in_range(self, detected: str, version_range: str) -> bool:
        """
        CVE 버전 범위에 포함되는지 확인
        
        Args:
            detected: "2.2.4"
            version_range: "<3.0.0", ">=1.0 and <3.4.0"
        
        Returns:
            True if in range
        """
        try:
            # ">=1.0 and <3.4.0" 형식 파싱
            if " and " in version_range:
                parts = version_range.split(" and ")
                return all(self.version_in_range(detected, part.strip()) for part in parts)
            
            # "<3.0.0" 형식 파싱
            if "<=" in version_range:
                threshold = re.search(r"<=\s*(.+?)\s*$", version_range)
                if threshold:
                    return self.is_vulnerable_version(detected, "<=", threshold.group(1))
            
            if "<" in version_range:
                threshold = re.search(r"<\s*(.+?)\s*$", version_range)
                if threshold:
                    return self.is_vulnerable_version(detected, "<", threshold.group(1))
            
            return False
        
        except Exception as e:
            logger.debug(f"[VERIFIER] Version range check error: {e}")
            return False
```
---

## File 54: workflow.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\workflow.py`

```python
import asyncio
import logging
from flask import current_app

# Core modules imports
from ..core.recon.network import run_recon
from ..core.recon.web import collect_web_info
from ..core.cve.cpe_generator import batch_generate_cpes
from ..core.cve.async_nvd_client import AsyncNvdClient
from ..core.verifier import VulnerabilityVerifier
from ..core.scenario.generator import call_ollama
from ..utils.exploit import search_exploits_for_cves
from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
from ..core.cve.cache_manager import get_cache_manager

# Conditional imports for CVE matching (fallback mechanism)
try:
    from ..core.cve.matcher import search_cves_for_technologies as search_cves_func
except ImportError:
    try:
        from ..core.cve.matcher import search_cves_universal as search_cves_func
    except ImportError:
        search_cves_func = None

logger = logging.getLogger(__name__)

async def async_scan_workflow(target: str):
    """
    Executes the full vulnerability scanning workflow.
    Fixed for frontend compatibility:
    - Returns 'zapscan' instead of 'zap_scan'
    - Returns 'scenario' as a list of strings
    """
    
    logger.info("-" * 70)
    logger.info(f"[WORKFLOW] Starting comprehensive scan for: {target}")

    # --- Step 1: Network Recon ---
    print(f"[WORKFLOW] Step 1 - Running Nmap scan on {target}...")
    recon_result = run_recon(target)
    print(f"[WORKFLOW] Found {len(recon_result)} hosts")

    # --- Step 2: Web Recon ---
    print(f"[WORKFLOW] Step 2 - Running web reconnaissance...")
    web_info = {}
    try:
        web_info = collect_web_info(target)
        print(f"[WORKFLOW] Web recon completed")
    except Exception as e:
        logger.error(f"[WORKFLOW] Web recon failed: {e}")

    # --- Step 3: Cloud/Infra Info (Optional) ---
    print(f"[WORKFLOW] Step 3 - Infrastructure info...")
    cloud_info = {}
    try:
        from ..core.recon.cloud import discover_cloud_assets
        cloud_info = discover_cloud_assets(target)
    except Exception:
        pass

    # --- Step 4: CPE Generation ---
    print(f"[WORKFLOW] Step 4 - Generating CPE identifiers...")
    technologies_with_cpe = []
    
    # Process Nmap results
    if isinstance(recon_result, list):
        for host in recon_result:
            for port in host.get('ports', []):
                tech = {
                    "product": port.get('product', 'unknown'),
                    "version": port.get('version', ''),
                    "service": port.get('service', 'unknown'),
                    "port": port.get('port'),
                    "ip": host.get('ip'),
                    "source": "nmap",
                    "category": "detected"
                }
                technologies_with_cpe.append(tech)

    # Process Web Recon results
    if web_info and 'web_technologies' in web_info:
        for tech_info in web_info['web_technologies']:
            tech = {
                "product": tech_info.get('name', tech_info.get('product', 'unknown')),
                "version": tech_info.get('version', ''),
                "service": "web",
                "source": "web_recon",
                "category": "other"
            }
            technologies_with_cpe.append(tech)

    # Generate CPEs
    technologies_with_cpe = batch_generate_cpes(technologies_with_cpe)
    cpe_techs = [t for t in technologies_with_cpe if t.get('cpe')]
    print(f"[WORKFLOW] Generated CPE for {len(cpe_techs)} technologies")

    # --- Step 5: CVE Search ---
    print(f"[WORKFLOW] Step 5 - Searching for CVEs...")
    nvd_client = AsyncNvdClient(
        api_key=current_app.config.get("NVD_API_KEY"),
        base_url=current_app.config.get("NVD_BASE_URL")
    )
    cache_manager = get_cache_manager()
    
    all_cves = []
    if search_cves_func:
        print(f"[WORKFLOW] Searching CVEs for {len(cpe_techs)} technologies...")
        for tech in cpe_techs:
            prod = tech.get('product')
            ver = tech.get('version')
            try:
                cves = await search_cves_func(prod, ver, nvd_client=nvd_client, cache_manager=cache_manager)
                if cves:
                    all_cves.extend(cves)
            except Exception as e:
                # logger.error(f"[WORKFLOW] CVE search error for {prod}: {e}")
                pass

    # Deduplicate CVEs
    unique_cves = {}
    for cve in all_cves:
        if cve and isinstance(cve, dict) and cve.get('id'):
            unique_cves[cve.get('id')] = cve
    
    all_cves = list(unique_cves.values())
    print(f"[WORKFLOW] Found {len(all_cves)} unique CVEs")

    # --- Step 6: ZAP Security Scan ---
    print(f"[WORKFLOW] Step 6 - Running OWASP ZAP security scan...")
    zap_alerts = []
    try:
        zap_scanner = ZapScanner(
            api_key=current_app.config.get("ZAP_API_KEY"),
            proxy_host=current_app.config.get("ZAP_PROXY_HOST"),
            proxy_port=current_app.config.get("ZAP_PROXY_PORT")
        )
        # Use full_scan (Spider + Active Scan)
        scan_result = zap_scanner.full_scan(target)
        
        if scan_result and 'alerts' in scan_result:
            zap_alerts = format_alerts_for_dashboard(scan_result['alerts'])
    except Exception as e:
        print(f"[WORKFLOW] ZAP scan skipped: {e}")

    # --- Step 7: Vulnerability Verification ---
    print(f"[WORKFLOW] Step 7 - Verifying vulnerabilities...")
    verifications = []
    try:
        endpoints = web_info.get('api_endpoints', [])
        verifier = VulnerabilityVerifier(target, endpoints, all_cves, technologies_with_cpe)
        
        if hasattr(verifier, 'verify_vulnerabilities'):
            try:
                verifications = verifier.verify_vulnerabilities()
            except TypeError:
                verifications = verifier.verify_vulnerabilities(all_cves, web_info)
        elif hasattr(verifier, 'verify'):
            verifications = verifier.verify()
    except Exception as e:
        # logger.error(f"[WORKFLOW] Verification failed: {e}")
        pass

    # --- Step 8: Exploit Search ---
    print(f"[WORKFLOW] Step 8 - Searching for exploits...")
    exploits = []
    try:
        exploits = search_exploits_for_cves(all_cves)
        print(f"[WORKFLOW] Found {len(exploits)} exploits")
    except Exception:
        pass

    # --- Step 9: AI Scenario Generation ---
    print(f"[WORKFLOW] Step 9 - Generating AI-powered attack scenario...")
    scenario_text = ""
    scenario_object = {}
    
    try:
        # Build prompt for AI
        prompt_lines = [f"Analyze the security posture of {target}."]
        
        if technologies_with_cpe:
            tech_names = [t.get('product', 'unknown') for t in technologies_with_cpe]
            prompt_lines.append(f"Technologies: {', '.join(set(tech_names))}.")
            
        if all_cves:
            prompt_lines.append(f"Vulnerabilities: {len(all_cves)} found.")
            sorted_cves = sorted(all_cves, key=lambda x: float(x.get('cvss', 0) or 0), reverse=True)
            for cve in sorted_cves[:5]:
                cve_id = cve.get('id', 'Unknown')
                desc = cve.get('description', '')[:100].replace('\n', ' ')
                prompt_lines.append(f"- {cve_id}: {desc}...")
        
        prompt_lines.append("Based on this, create a short penetration testing scenario.")
        final_prompt = " ".join(prompt_lines)

        print(f"[WORKFLOW] Calling Ollama API...")
        try:
            scenario_text = call_ollama(final_prompt)
        except Exception:
            # Fallback if AI fails
            scenario_text = f"Attack Scenario for {target}:\n"
            scenario_text += f"1. Reconnaissance: Discovered {len(technologies_with_cpe)} technologies.\n"
            scenario_text += f"2. Vulnerability Analysis: Identified {len(all_cves)} potential vulnerabilities.\n"
            scenario_text += f"3. Exploitation: Found {len(exploits)} public exploits."

        # Structure for dashboard
        scenario_object = {
            "title": f"Penetration Test Scenario for {target}",
            "summary": scenario_text[:200] + "...",
            "content": scenario_text,
            "steps": [
                {"name": "Reconnaissance", "details": f"Found {len(technologies_with_cpe)} tech stacks"},
                {"name": "Scanning", "details": f"Detected {len(all_cves)} CVEs"},
                {"name": "Analysis", "details": "High risk vulnerabilities identified"}
            ]
        }
        print(f"[WORKFLOW] AI scenario generated successfully")

    except Exception as e:
        logger.warning(f"[WORKFLOW] AI generation failed: {e}")
        scenario_text = "AI scenario generation failed."
        scenario_object = {"content": scenario_text}

    logger.info("-" * 70)
    print(f"[WORKFLOW] SCAN COMPLETED")

    # Categorize results for dashboard
    recon_by_category = {
        "web": [], "network": [], "os": [], "database": [], "cloud": [], "container": []
    }
    
    for tech in technologies_with_cpe:
        # Default to web or network based on source
        if tech.get('service') == 'web' or tech.get('source') == 'web_recon':
            recon_by_category['web'].append(tech)
        else:
            recon_by_category['network'].append(tech)

    # Final Return Dictionary (Matching Frontend Expectations)
    return {
        "target": target,
        "technologies": technologies_with_cpe,
        "cves": all_cves,
        "zapscan": {"alerts": zap_alerts},  # FIXED: key changed from 'zap_scan' to 'zapscan'
        "verifications": verifications,
        "exploits": exploits,
        "scenario": scenario_text.split('\n') if scenario_text else [], # FIXED: converted string to list
        "ai_scenario": scenario_object, 
        "report_summary": scenario_text,
        "categorized": {
            "recon": recon_by_category
        }
    }
```
---

## File 55: models.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\models.py`
=======
- **Root:** `d:\3차 프로젝트\6트\12.26 app`
- **Files included:** 19 (Total: 92)

---

## File 58: extensions.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\extensions.py`

```python
from flask_socketio import SocketIO
socketio = SocketIO(cors_allowed_origins="*")
```
---

## File 59: loot_generator.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\loot_generator.py`

```python
import random
import datetime

def enrich_loot(base_proof: dict):
    """
    LLM이 준 proof 에 더미 데이터를 추가하거나 형식을 보정.
    """
    proof = base_proof or {}
    loot_files = proof.get("loot_files") or []
    logs = proof.get("logs") or []

    # 기본 /etc/passwd 더미가 없으면 하나 추가
    if not loot_files:
        loot_files.append({
            "path": "/etc/passwd",
            "content": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "demo:x:1000:1000:demo:/home/demo:/bin/bash\n"
            )
        })

    # 로그에 타임스탬프 추가
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    logs.append(f"[{timestamp}] Demo attack simulation completed.")

    proof["loot_files"] = loot_files
    proof["logs"] = logs
    return proof
```
---

## File 60: main.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\main.py`

```python
# main.py
from .nvd_client import NvdClient


def main():
    client = NvdClient()

    # 여기서 서비스/버전 문자열 넣어서 테스트
    # 예: service = "nginx 1.24", "apache httpd 2.4.59" 등[web:137]
    service_version = input("검색할 서비스/버전 키워드 입력 (예: 'nginx 1.24'): ").strip()

    if not service_version:
        print("키워드를 입력해주세요.")
        return

    print(f"\n[NVD 검색] 키워드: {service_version}")
    cve_list = client.search_and_summarize(service_version, max_pages=1)

    if not cve_list:
        print("검색 결과가 없습니다.")
        return

    for idx, item in enumerate(cve_list, start=1):
        print(f"\n[{idx}] CVE ID: {item['cve_id']}")
        print(f"    CVSS: {item['cvss']}")
        print(f"    DESC: {item['description'][:200]}")  # 너무 길면 앞 200자만


if __name__ == "__main__":
    main()
```
---

## File 61: models.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\models.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
from app import db
from datetime import datetime

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    data = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```
---

<<<<<<< HEAD
## File 56: routes.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\routes.py`
=======
## File 62: nmap_recon.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\nmap_recon.py`

```python
import nmap
import re

def mask_ip(ip: str) -> str:
    # 192.168.0.10 -> 192.168.0.x 형태로 마스킹
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "x"
        return ".".join(parts)
    return ip

def parse_service_version(product: str, version: str) -> str:
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    return "unknown"

def run_recon(target: str, nmap_args: str = "-sV -Pn", mask: bool = True):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=nmap_args)

    hosts = []
    for host in nm.all_hosts():
        host_ip = mask_ip(host) if mask else host
        host_data = {
            "ip": host_ip,
            "hostname": nm[host].hostname() or "",
            "state": nm[host].state(),
            "os": nm[host].get("osmatch", []),
            "ports": []
        }

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                svc = nm[host][proto][port]
                service_name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                full_version = parse_service_version(product, version)

                host_data["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": svc.get("state", ""),
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "full_version": full_version
                })

        hosts.append(host_data)

    return hosts
```
---

## File 63: nvd_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\nvd_client.py`

```python
# app/nvd_client.py
import time
import requests
import re
from typing import List, Dict, Any, Optional, Tuple

from .config import Config

# 버전 비교를 위한 라이브러리 (pip install packaging 필요)
try:
    from packaging import version
    VERSION_COMPARE_AVAILABLE = True
except ImportError:
    VERSION_COMPARE_AVAILABLE = False
    print("[WARN] packaging 모듈이 없어 버전 필터링이 비활성화됩니다. pip install packaging 권장")

# Product → (vendor, product) 매핑 테이블
# Nmap의 product 이름을 NVD CPE 표준 vendor/product로 변환
PRODUCT_TO_VENDOR_PRODUCT = {
    # 웹 서버
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "lighttpd": ("lighttpd", "lighttpd"),
    
    # 데이터베이스
    "mysql": ("mysql", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "sqlite": ("sqlite", "sqlite"),
    
    # SSH/FTP
    "openssh": ("openssh", "openssh"),
    "dropbear": ("dropbear", "dropbear"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    
    # 메일 서버
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "exim": ("exim", "exim"),
    
    # 기타
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "node.js": ("nodejs", "node"),
    "python": ("python", "python"),
    "php": ("php", "php"),
}


def normalize_product_name(product: str) -> str:
    """
    Nmap product 이름을 정규화 (소문자, 공백 제거 등).
    """
    if not product:
        return ""
    return product.lower().strip()


def map_product_to_vendor_product(product: str) -> Optional[Tuple[str, str]]:
    """
    Product 이름을 (vendor, product) 튜플로 변환.
    매핑 테이블에 없으면 None 반환.
    """
    normalized = normalize_product_name(product)
    
    # 정확한 매칭 시도
    if normalized in PRODUCT_TO_VENDOR_PRODUCT:
        return PRODUCT_TO_VENDOR_PRODUCT[normalized]
    
    # 부분 매칭 시도 (예: "Apache httpd 2.4.49" -> "apache httpd" 매칭)
    for key, value in PRODUCT_TO_VENDOR_PRODUCT.items():
        if key in normalized or normalized in key:
            return value
    
    return None


def build_cpe_string(vendor: str, product: str, version: str = "*") -> str:
    """
    CPE 2.3 형식 문자열 생성.
    형식: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    """
    # CPE 형식에 맞게 특수문자 처리
    vendor_clean = vendor.replace(" ", "_").lower()
    product_clean = product.replace(" ", "_").lower()
    version_clean = version if version else "*"
    
    return f"cpe:2.3:a:{vendor_clean}:{product_clean}:{version_clean}:*:*:*:*:*:*:*"


class NvdClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = None,
        results_per_page: int = None,
        sleep_sec: float = 0.5,
    ):
        self.api_key = api_key or Config.NVD_API_KEY
        self.base_url = base_url or Config.NVD_BASE_URL
        self.results_per_page = results_per_page or Config.NVD_RESULTS_PER_PAGE
        self.sleep_sec = sleep_sec

    def _get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        resp = requests.get(
            self.base_url,
            params=params,
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        time.sleep(self.sleep_sec)
        return resp.json()

    def search_cves_by_keyword(
        self,
        keyword: str,
        max_pages: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        keyword 로 CVE 검색 (서비스 이름, 버전 등).
        """
        all_items: List[Dict[str, Any]] = []
        start_index = 0

        for _ in range(max_pages):
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": self.results_per_page,
                "startIndex": start_index,
            }
            data = self._get(params)

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            all_items.extend(vulnerabilities)

            total_results = data.get("totalResults", 0)
            start_index += self.results_per_page
            if start_index >= total_results:
                break

        return all_items

    def search_cves_by_cpe(
        self,
        cpe_string: str,
        max_pages: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        CPE 문자열로 CVE 검색 (더 정확한 매칭).
        NVD API v2.0의 cpeMatchString 파라미터 사용.
        
        참고: NVD API v2.0 CVE 검색 엔드포인트는 cpeMatchString 파라미터를 지원합니다.
        형식: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        
        만약 cpeMatchString이 작동하지 않으면, cpeName을 시도합니다.
        """
        all_items: List[Dict[str, Any]] = []
        start_index = 0

        # NVD API v2.0에서 지원하는 파라미터 시도 순서
        # 1. cpeMatchString (공식 문서에 명시된 파라미터)
        # 2. cpeName (일부 버전에서 지원될 수 있음)
        param_names = ["cpeMatchString", "cpeName"]
        last_error = None

        for param_name in param_names:
            try:
                all_items = []
                start_index = 0
                
                for _ in range(max_pages):
                    params = {
                        param_name: cpe_string,
                        "resultsPerPage": self.results_per_page,
                        "startIndex": start_index,
                    }
                    data = self._get(params)

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    all_items.extend(vulnerabilities)

                    total_results = data.get("totalResults", 0)
                    start_index += self.results_per_page
                    if start_index >= total_results:
                        break

                # 성공적으로 결과를 받았으면 반환
                if all_items or param_name == param_names[-1]:
                    print(f"[DEBUG] CPE 검색 성공 (파라미터: {param_name}): {len(all_items)}개 CVE 발견")
                    return all_items
                    
            except requests.exceptions.HTTPError as e:
                last_error = e
                print(f"[DEBUG] CPE 검색 실패 (파라미터: {param_name}): {e}")
                # 다음 파라미터 시도
                continue
            except Exception as e:
                last_error = e
                print(f"[DEBUG] CPE 검색 오류 (파라미터: {param_name}): {e}")
                continue

        # 모든 파라미터 시도 실패
        print(f"[WARN] CPE 검색 완전 실패: {cpe_string}, 마지막 오류: {last_error}")
        return []

    def cvss_to_severity(self, score: float) -> str:
        """
        CVSS 점수를 위험도 라벨로 변환.
        
        공식 기준:
        - FIRST CVSS v3.1 Specification (Table 14):
          https://www.first.org/cvss/v3-1/specification-document
        - NVD Vulnerability Metrics:
          https://nvd.nist.gov/vuln-metrics/cvss
        """
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        else:
            return "None"

    def is_version_vulnerable(self, target_version: str, cpe_match: dict) -> bool:
        """
        타겟 버전이 CVE의 영향 범위에 포함되는지 확인.
        NVD configurations의 versionStartIncluding/versionEndExcluding 등을 파싱.
        강화된 버전: 버전 정보가 없거나 불확실하면 False 반환 (보수적 접근).
        """
        if not target_version:
            # 타겟 버전이 없으면 매칭 불가
            return False

        if not VERSION_COMPARE_AVAILABLE:
            # packaging 모듈이 없으면 버전 비교 불가
            # CPE에 version이 "*"이거나 없으면 True, 있으면 정확히 일치해야 함
            cpe_version = cpe_match.get("version", "*")
            if cpe_version == "*" or cpe_version == "-":
                return True
            # 정확한 버전 비교는 불가하므로 False 반환 (보수적)
            return False

        try:
            target_ver = version.parse(target_version)
        except Exception as e:
            # 버전 파싱 실패 시 False 반환 (보수적 접근)
            print(f"[DEBUG] 버전 파싱 실패: {target_version}, err={e}")
            return False

        start_inc = cpe_match.get("versionStartIncluding")
        start_exc = cpe_match.get("versionStartExcluding")
        end_inc = cpe_match.get("versionEndIncluding")
        end_exc = cpe_match.get("versionEndExcluding")

        # 버전 범위 정보가 없으면 CPE의 version 필드 확인
        if not any([start_inc, start_exc, end_inc, end_exc]):
            cpe_version = cpe_match.get("version", "*")
            if cpe_version == "*" or cpe_version == "-":
                return True
            # 정확한 버전 비교 시도
            try:
                cpe_ver = version.parse(cpe_version)
                return target_ver == cpe_ver
            except:
                # 파싱 실패 시 문자열 비교
                return target_version == cpe_version

        # 하한선 체크
        if start_inc:
            try:
                if target_ver < version.parse(start_inc):
                    return False
            except Exception as e:
                print(f"[DEBUG] start_inc 파싱 실패: {start_inc}, err={e}")

        if start_exc:
            try:
                if target_ver <= version.parse(start_exc):
                    return False
            except Exception as e:
                print(f"[DEBUG] start_exc 파싱 실패: {start_exc}, err={e}")

        # 상한선 체크
        if end_inc:
            try:
                if target_ver > version.parse(end_inc):
                    return False
            except Exception as e:
                print(f"[DEBUG] end_inc 파싱 실패: {end_inc}, err={e}")

        if end_exc:
            try:
                if target_ver >= version.parse(end_exc):
                    return False
            except Exception as e:
                print(f"[DEBUG] end_exc 파싱 실패: {end_exc}, err={e}")

        # 모든 범위 체크를 통과하면 취약
        return True

    def extract_cve_summary(
        self, vuln_item: Dict[str, Any], target_version: str = None, 
        target_vendor: str = None, target_product: str = None
    ) -> Dict[str, Any]:
        """
        NVD v2 응답에서 CVE ID, 설명, CVSS 점수 + Severity + 버전 필터링.
        강화된 버전: vendor/product 매칭도 확인.
        """
        cve = vuln_item.get("cve", {})
        cve_id = cve.get("id")

        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        metrics = vuln_item.get("cve", {}).get("metrics", {})
        cvss_score = None

        # v31, v30, v2 순으로 스코어 추출
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        cvss_val = float(cvss_score) if cvss_score is not None else 0.0
        severity = self.cvss_to_severity(cvss_val)

        # ===== 강화된 버전 필터링 =====
        is_vulnerable = False  # 기본값을 False로 변경 (보수적 접근)

        configurations = cve.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable"):
                        continue
                    
                    # CPE 문자열에서 vendor/product 추출
                    cpe_uri = cpe_match.get("criteria", "")
                    if target_vendor and target_product:
                        # vendor/product 매칭 확인
                        vendor_match = target_vendor.lower() in cpe_uri.lower()
                        product_match = target_product.lower() in cpe_uri.lower()
                        if not (vendor_match and product_match):
                            continue
                    
                    # 버전 매칭 확인
                    if target_version:
                        if self.is_version_vulnerable(target_version, cpe_match):
                            is_vulnerable = True
                            break
                    else:
                        # 버전이 없으면 CPE 매칭만으로 판단
                        is_vulnerable = True
                        break
                    
                if is_vulnerable:
                    break
            if is_vulnerable:
                break

        return {
            "cve_id": cve_id,
            "description": desc_text,
            "cvss": cvss_val,
            "severity": severity,
            "is_vulnerable": is_vulnerable,
        }

    def search_and_summarize(
        self, keyword: str, max_pages: int = 1, target_version: str = None
    ) -> List[Dict[str, Any]]:
        """
        keyword로 검색하고, 각 CVE를 요약 리스트로 반환.
        target_version이 주어지면 버전 필터링 수행.
        """
        vulns = self.search_cves_by_keyword(keyword, max_pages=max_pages)
        result = []

        for v in vulns:
            summary = self.extract_cve_summary(v, target_version=target_version)
            result.append(summary)

        return result

    def search_hybrid(
        self,
        product: str,
        version: str = None,
        keyword_fallback: str = None,
        max_pages: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        하이브리드 검색: CPE 기반 검색을 우선 시도, 실패 시 키워드 검색으로 폴백.
        
        Args:
            product: Nmap에서 감지한 product 이름 (예: "Apache httpd")
            version: 감지한 버전 (예: "2.4.49")
            keyword_fallback: CPE 검색 실패 시 사용할 키워드 (None이면 product+version 조합)
            max_pages: 최대 검색 페이지 수
        
        Returns:
            필터링된 CVE 리스트
        """
        # 1단계: Product → Vendor/Product 매핑
        vendor_product = map_product_to_vendor_product(product)
        
        if not vendor_product:
            # 매핑 실패 시 키워드 검색으로 폴백
            print(f"[DEBUG] Product 매핑 실패: {product}, 키워드 검색으로 폴백")
            keyword = keyword_fallback or product
            if version:
                keyword = f"{keyword} {version}"
            return self.search_and_summarize(keyword, max_pages=max_pages, target_version=version)
        
        vendor, mapped_product = vendor_product
        print(f"[DEBUG] Product 매핑 성공: {product} -> vendor={vendor}, product={mapped_product}")
        
        # 2단계: CPE 문자열 생성 및 검색 시도
        cpe_string = build_cpe_string(vendor, mapped_product, version or "*")
        print(f"[DEBUG] CPE 검색 시도: {cpe_string}")
        
        try:
            vulns = self.search_cves_by_cpe(cpe_string, max_pages=max_pages)
            
            if vulns:
                print(f"[DEBUG] CPE 검색 성공: {len(vulns)}개 CVE 발견")
                result = []
                for v in vulns:
                    summary = self.extract_cve_summary(
                        v,
                        target_version=version,
                        target_vendor=vendor,
                        target_product=mapped_product,
                    )
                    result.append(summary)
                return result
            else:
                print(f"[DEBUG] CPE 검색 결과 없음, 키워드 검색으로 폴백")
        except Exception as e:
            print(f"[WARN] CPE 검색 중 오류: {e}, 키워드 검색으로 폴백")
        
        # 3단계: CPE 검색 실패 시 키워드 검색으로 폴백
        keyword = keyword_fallback or product
        if version:
            # 버전이 있으면 메이저.마이너만 추가
            ver_parts = version.split(".")
            if len(ver_parts) >= 2:
                short_ver = ".".join(ver_parts[:2])
                keyword = f"{keyword} {short_ver}"
            else:
                keyword = f"{keyword} {version}"
        
        print(f"[DEBUG] 키워드 검색으로 폴백: {keyword}")
        vulns = self.search_cves_by_keyword(keyword, max_pages=max_pages)
        result = []
        
        for v in vulns:
            summary = self.extract_cve_summary(
                v,
                target_version=version,
                target_vendor=vendor,
                target_product=mapped_product,
            )
            result.append(summary)
        
        return result
```
---

## File 64: routes.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\routes.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.models import Project, ScanResult
from app import db
import re

bp = Blueprint("main", __name__)

@bp.route('/')
def index():
    return redirect(url_for('main.projects'))

@bp.route('/projects')
def projects():
    all_projects = Project.query.all()
    return render_template('projects.html', projects=all_projects)

@bp.route('/project/new', methods=['POST'])
def create_project():
    name, target = request.form.get('name'), request.form.get('target')
    if name and target:
        db.session.add(Project(name=name, target=target))
        db.session.commit()
    return redirect(url_for('main.projects'))

@bp.route('/project/delete/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    ScanResult.query.filter_by(project_id=project_id).delete()
    db.session.delete(project)
    db.session.commit()
    return redirect(url_for('main.projects'))

@bp.route('/live-scan/<int:project_id>')
def live_scan(project_id):
    project = Project.query.get_or_404(project_id)
<<<<<<< HEAD
    return render_template('live_scan_v2.html', project=project)
=======
    return render_template('live_scan.html', project=project)
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

@bp.route('/url-tree/<int:project_id>')
def url_tree(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('url_tree.html', project=project)

@bp.route('/api/project/<int:project_id>/tree-data')
def get_tree_data(project_id):
    last_scan = ScanResult.query.filter_by(project_id=project_id).order_by(ScanResult.timestamp.desc()).first()
    project = Project.query.get(project_id)
    tree = {"name": project.target, "children": []}
    
    if not last_scan or not last_scan.data.get('urls'):
        return jsonify(tree)

    # 고유 URL 정렬
    urls = sorted(list(set(last_scan.data['urls'])))
    for url in urls:
        # 경로 추출 (도메인 이후 부분)
        path_str = url.replace(project.target, "").strip("/")
        if not path_str: continue
        
        parts = [p for p in path_str.split('/') if p]
        curr = tree['children']
        for p in parts:
            node = next((item for item in curr if item["name"] == p), None)
            if not node:
                new_node = {"name": p, "children": []}
                curr.append(new_node)
                curr = new_node["children"]
            else:
                curr = node["children"]
    return jsonify(tree)
```
---

<<<<<<< HEAD
## File 57: intelligence.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\services\intelligence.py`
=======
## File 65: searchsploit_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\searchsploit_client.py`

```python
# app/searchsploit_client.py

import json
import subprocess
from typing import List, Dict


def search_exploits_for_cves(cve_ids: List[str], max_per_cve: int = 5) -> Dict[str, List[Dict]]:
    """
    여러 CVE ID에 대해 searchsploit --json을 호출하고,
    각 CVE별로 'title' 과 'id' 만 추출해서 반환.

    반환 예:
    {
      "CVE-2021-41773": [
        {"title": "Apache HTTP Server 2.4.49 - Path Traversal & RCE", "id": "50383"},
        {"title": "Apache 2.4.49/2.4.50 - Traversal Shell (Metasploit)", "id": "50406"},
      ],
      ...
    }
    """
    results: Dict[str, List[Dict]] = {}
    for cve in cve_ids:
        exploits = search_exploits_for_single_cve(cve, max_per_cve=max_per_cve)
        if exploits:
            results[cve] = exploits
    return results


def search_exploits_for_single_cve(cve_id: str, max_per_cve: int = 5) -> List[Dict]:
    """
    단일 CVE에 대해 searchsploit --json 실행.

    출력 예:
    [
        {"title": "...", "id": "50383"},
        ...
    ]
    """
    cmd = ["searchsploit", "--json", cve_id]

    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[WARN] searchsploit 실패: {cve_id}, err={e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"[WARN] searchsploit JSON 파싱 실패: {cve_id}")
        return []

    # searchsploit --json 구조는 보통:
    # { "RESULTS_EXPLOIT": [ { "Title": "...", "EDB-ID": "50383", ... }, ... ],
    #   "RESULTS_SHELLCODE": [ ... ] }
    exploits = []

    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        arr = data.get(key) or []
        if not isinstance(arr, list):
            continue
        for item in arr:
            title = item.get("Title") or item.get("title")
            edb_id = item.get("EDB-ID") or item.get("id")
            if not title or not edb_id:
                continue
            exploits.append({"title": title, "id": str(edb_id)})

    # 상위 N개만
    return exploits[:max_per_cve]
```
---

## File 66: intelligence.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\services\intelligence.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
import re

class IntelligenceEngine:
    """
    스캔 데이터 정제 및 검증 힌트 생성 엔진
    """

    def __init__(self):
        self.tech_stack = {} 

    def _normalize_name(self, name):
        return str(name).lower().strip()

    def _generate_manual_hint(self, tech_name, category, version, url="TARGET_URL"):
        """
        기술 스택에 따른 실무자용 수동 검증 명령어 생성
        """
        tech_lower = tech_name.lower()
        cat_lower = category.lower()
        hints = []

        # 1. 웹 서버 / 언어 관련 (HTTP 헤더 검증)
        if cat_lower in ['web server', 'language', 'operating system']:
            hints.append(f"curl -I -v {url}")
            hints.append(f"whatweb -v {url}")

        # 2. 데이터베이스 (SQL Injection 검증)
        if 'sql' in tech_lower or cat_lower == 'database':
            hints.append(f"sqlmap -u \"{url}\" --batch --dbs")
            hints.append("Manual Check: Add ' OR 1=1 -- to input fields")

        # 3. CMS (WordPress, Drupal 등)
        if 'wordpress' in tech_lower:
            hints.append(f"wpscan --url {url} --enumerate u,p,t")
        elif 'joomla' in tech_lower:
            hints.append(f"joomscan -u {url}")

        # 4. Nginx/Apache 구체적 버전
        if 'nginx' in tech_lower:
            hints.append(f"nikto -h {url} -Tuning b")
        
        # 5. PHP
        if 'php' in tech_lower:
            hints.append(f"curl -X GET {url} -H 'X-Powered-By: verify'")

        if not hints:
            hints.append(f"nuclei -u {url} -t http/technologies")

        return hints

    def add_finding(self, tech_name, version, category, source_tool, evidence, confidence="High"):
        if not tech_name or tech_name.lower() == 'unknown':
            return

        key = self._normalize_name(tech_name)
        
        if version and version.lower() in ['n/a', 'unknown', 'none']:
            version = ""
            
        evidence_str = f"[{source_tool}] {evidence}" if evidence else f"[{source_tool}] Detected"

        if key not in self.tech_stack:
            self.tech_stack[key] = {
                "name": tech_name,
                "version": version,
                "category": category,
                "sources": [source_tool],
                "evidence": [evidence_str],
                "confidence": confidence,
                "hints": [] # 힌트 리스트 초기화
            }
        else:
            existing = self.tech_stack[key]
            if source_tool not in existing["sources"]:
                existing["sources"].append(source_tool)
            if evidence_str not in existing["evidence"]:
                existing["evidence"].append(evidence_str)
            if not existing["version"] and version:
                existing["version"] = version
            elif version and len(version) > len(existing["version"]):
                existing["version"] = version

    def refine_data(self, scan_results, target_url="http://localhost"):
        """
        데이터 정제 메인 함수
        """
        self.tech_stack = {} 

        # 1. 헤더 분석
        headers = scan_results.get('headers', {})
        if isinstance(headers, dict):
            if 'server' in headers:
                self.add_finding("Web Server", headers['server'], "Web Server", "Header", f"Server: {headers['server']}")
            if 'x-powered-by' in headers:
                self.add_finding("Language", headers['x-powered-by'], "Language", "Header", f"X-Powered-By: {headers['x-powered-by']}")

        # 2. 통합 리스트 (Nuclei, WhatWeb 등)
        tech_list = scan_results.get('webtechnologies', [])
        if isinstance(tech_list, list):
            for tech in tech_list:
                if not isinstance(tech, dict): continue
                self.add_finding(
                    tech.get('name'), 
                    tech.get('version', ''), 
                    tech.get('category', 'Generic'), 
                    tech.get('source', 'Scanner'),
                    tech.get('evidence')
                )

        # 3. 데이터 후처리 (힌트 생성)
        final_list = []
        for tech in self.tech_stack.values():
            # 힌트 생성 (현재 타겟 URL 기준)
            tech['hints'] = self._generate_manual_hint(tech['name'], tech['category'], tech['version'], target_url)
            final_list.append(tech)
            
        return final_list
```
---

<<<<<<< HEAD
## File 58: live_scan.css
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\static\css\live_scan.css`
=======
## File 67: live_scan.css
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\css\live_scan.css`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1800px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.2);
    padding: 30px;
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 3px solid #1976d2;
}

header h1 {
    font-size: 2.5em;
    color: #1976d2;
    margin-bottom: 10px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
}

header p {
    color: #666;
    font-size: 1.1em;
}

/* Control Panel */
.control-panel {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 20px;
    border-radius: 12px;
    margin-bottom: 25px;
}

.input-row {
    display: flex;
    gap: 15px;
    align-items: center;
}

.input-row input[type="text"] {
    flex: 1;
    padding: 12px 20px;
    font-size: 16px;
    border: 2px solid rgba(255,255,255,0.3);
    border-radius: 8px;
    background: rgba(255,255,255,0.95);
}

.checkbox-label {
    color: white;
    font-size: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
    width: 20px;
    height: 20px;
    cursor: pointer;
}

.btn-primary, .btn-secondary {
    padding: 12px 28px;
    font-size: 16px;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s;
    white-space: nowrap;
}

.btn-primary {
    background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
    color: #1a1a1a;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(67, 233, 123, 0.4);
}

.btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
}

.btn-secondary {
    background: white;
    color: #667eea;
    border: 2px solid white;
}

.btn-secondary:hover {
    background: rgba(255,255,255,0.9);
}

/* Statistics Cards */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 25px;
}

.stat-card {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 25px;
    border-radius: 12px;
    color: white;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.card-blue { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.card-green { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
.card-red { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }

.stat-icon {
    font-size: 3em;
}

.stat-content h3 {
    font-size: 2.5em;
    margin-bottom: 5px;
}

.stat-content p {
    font-size: 1em;
    opacity: 0.9;
}

/* Activity Banner */
.activity-banner {
    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 15px 25px;
    border-radius: 8px;
    margin-bottom: 25px;
    font-size: 1.1em;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 15px;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.85; }
}

.activity-icon {
    font-size: 1.5em;
}

/* Main Content Layout */
.main-content {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 25px;
    margin-bottom: 25px;
}

.panel {
    background: #fafafa;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.panel h2 {
    font-size: 1.4em;
    color: #333;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 2px solid #e0e0e0;
}

/* Force Graph */
.graph-panel {
    min-height: 600px;
}

.graph-container {
    background: white;
    border-radius: 8px;
    border: 2px solid #e0e0e0;
    overflow: hidden;
}

/* Sidebar */
.sidebar {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

/* Progress Panel */
.progress-panel {
    flex: 1;
}

.progress-bars {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.progress-item {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.progress-label {
    font-weight: 600;
    color: #555;
    font-size: 0.95em;
}

.progress-bar-container {
    position: relative;
    background: #e0e0e0;
    border-radius: 20px;
    height: 24px;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    border-radius: 20px;
    transition: width 0.3s ease;
}

.progress-text {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 0.85em;
    font-weight: 600;
    color: #333;
}

/* Log Panel */
.log-panel {
    flex: 1;
    max-height: 400px;
}

.log-container {
    background: #1e1e1e;
    border-radius: 8px;
    padding: 15px;
    max-height: 300px;
    overflow-y: auto;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
}

.log-entry {
    display: flex;
    gap: 10px;
    padding: 8px;
    margin-bottom: 5px;
    border-radius: 4px;
    animation: slideIn 0.3s ease;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateX(-10px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

.log-icon {
    font-size: 1.2em;
}

.log-message {
    flex: 1;
    color: #e0e0e0;
}

.log-info { background: rgba(33, 150, 243, 0.2); }
.log-success { background: rgba(76, 175, 80, 0.2); }
.log-critical { background: rgba(211, 47, 47, 0.3); }
.log-high { background: rgba(245, 124, 0, 0.3); }
.log-medium { background: rgba(251, 192, 45, 0.2); }
.log-error { background: rgba(244, 67, 54, 0.3); }

/* Legend */
.legend {
    background: #f5f5f5;
    padding: 20px;
    border-radius: 8px;
}

.legend h3 {
    font-size: 1.2em;
    margin-bottom: 15px;
    color: #333;
}

.legend-items {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 14px;
}

.node-sample {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    border: 2px solid #333;
}

/* Scrollbar */
.log-container::-webkit-scrollbar {
    width: 8px;
}

.log-container::-webkit-scrollbar-track {
    background: #2d2d2d;
    border-radius: 4px;
}

.log-container::-webkit-scrollbar-thumb {
    background: #667eea;
    border-radius: 4px;
}

/* Responsive */
@media (max-width: 1200px) {
    .main-content {
        grid-template-columns: 1fr;
    }

    .sidebar {
        flex-direction: row;
    }
}

@media (max-width: 768px) {
    .input-row {
        flex-direction: column;
    }

    .sidebar {
        flex-direction: column;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }
}
```
---

<<<<<<< HEAD
## File 59: style.css
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\static\css\style.css`
=======
## File 68: style.css
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\css\style.css`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```css
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.card {
  border-radius: 0.5rem;
}

.badge-severity-critical {
  background-color: #dc3545;
}

.badge-severity-high {
  background-color: #fd7e14;
}

.badge-severity-medium {
  background-color: #ffc107;
  color: #000;
}

.badge-severity-low {
  background-color: #0d6efd;
}

.terminal-text {
  background-color: #000;
  color: #0f0;
  padding: 1rem;
  border-radius: 0.5rem;
  font-family: "Fira Code", monospace;
  font-size: 0.9rem;
  max-height: 100%;
  overflow-y: auto;
}

/* 타이핑 효과를 JS로 구현할 것이라, 여기서는 기본 스타일만 */

/* 취약 버전 범위 스타일 */
td small {
  font-size: 0.85rem;
  color: #6c757d;
}

/* 테이블 반응형 */
table {
  font-size: 0.9rem;
}

@media (max-width: 1200px) {
  table {
    font-size: 0.8rem;
  }
}

/* CVE 테이블 링크 호버 효과 */
table tbody tr:hover {
  background-color: rgba(255, 255, 255, 0.1);
}
/* ✅ 마크다운 렌더링 스타일 */
.markdown-content {
    line-height: 1.6;
}

.markdown-content h1 {
    color: #e74c3c;
    border-bottom: 2px solid #e74c3c;
    padding-bottom: 10px;
    margin-top: 20px;
}

.markdown-content h2 {
    color: #3498db;
    border-bottom: 1px solid #3498db;
    padding-bottom: 8px;
    margin-top: 18px;
}

.markdown-content h3 {
    color: #2ecc71;
    margin-top: 15px;
}

.markdown-content ul {
    margin-left: 20px;
}

.markdown-content li {
    margin-bottom: 8px;
}

.markdown-content code {
    background: #2c3e50;
    color: #e74c3c;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
}

.markdown-content pre {
    background: #2c3e50;
    color: #ecf0f1;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
}

.markdown-content blockquote {
    border-left: 4px solid #3498db;
    padding-left: 15px;
    color: #95a5a6;
    font-style: italic;
}

.markdown-content strong {
    color: #e74c3c;
    font-weight: bold;
}

/* ✅ 검증 상태 배지 */
.verification-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 0.85em;
    font-weight: bold;
    white-space: nowrap;
}

.verified-exploitable {
    background: #e74c3c;
    color: white;
}

.verified-safe {
    background: #2ecc71;
    color: white;
}

.not-verified {
    background: #95a5a6;
    color: white;
}

/* ✅ 모달 스타일 */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0, 0, 0, 0.8);
}

.modal-content {
    background-color: #1e2a38;
    margin: 5% auto;
    padding: 30px;
    border: 1px solid #3498db;
    border-radius: 10px;
    width: 80%;
    max-width: 1000px;
    color: #ecf0f1;
}

.close {
    color: #95a5a6;
    float: right;
    font-size: 32px;
    font-weight: bold;
    cursor: pointer;
}

.close:hover,
.close:focus {
    color: #e74c3c;
}

.tech-category {
    margin-bottom: 25px;
}

.tech-category h3 {
    color: #3498db;
    border-bottom: 1px solid #3498db;
    padding-bottom: 8px;
    margin-bottom: 12px;
}

.tech-category ul {
    list-style: none;
    padding-left: 0;
}

.tech-category li {
    padding: 8px;
    margin: 5px 0;
    background: #2c3e50;
    border-radius: 5px;
    border-left: 3px solid #3498db;
}

.tech-category li .tech-name {
    font-weight: bold;
    color: #3498db;
}

.tech-category li .tech-version {
    color: #e74c3c;
    margin-left: 10px;
}

.tech-category li .tech-source {
    color: #95a5a6;
    font-size: 0.85em;
    margin-left: 10px;
}

/* ✅ 버튼 스타일 */
.secondary-btn {
    background: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    margin-top: 10px;
    font-size: 0.95em;
    transition: background 0.3s;
}

.secondary-btn:hover {
    background: #2980b9;
}

/* ✅ 민감 파일 리스트 스타일 */
.loot-subsection {
    margin-bottom: 20px;
}

.loot-subsection h3 {
    color: #e74c3c;
    margin-bottom: 10px;
}

#sensitive-files-list {
    list-style: none;
    padding: 0;
}

#sensitive-files-list li {
    padding: 8px;
    margin: 5px 0;
    background: #2c3e50;
    border-radius: 5px;
    border-left: 3px solid #e74c3c;
}

#sensitive-files-list .file-path {
    color: #3498db;
    font-weight: bold;
}

#sensitive-files-list .file-status {
    color: #e74c3c;
    margin-left: 10px;
}

#sensitive-files-list .file-note {
    color: #95a5a6;
    font-size: 0.9em;
    margin-left: 10px;
}
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #ecf0f1;
    line-height: 1.6;
}

header {
    background: linear-gradient(90deg, #0f3460 0%, #16213e 100%);
    padding: 30px;
    text-align: center;
    border-bottom: 3px solid #e94560;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
}

header h1 {
    font-size: 2.5em;
    color: #e94560;
    font-weight: 700;
    letter-spacing: 2px;
}

main {
    max-width: 1400px;
    margin: 30px auto;
    padding: 0 20px;
}

.input-section {
    display: flex;
    gap: 15px;
    margin-bottom: 30px;
    background: #0f3460;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
}

#target-input {
    flex: 1;
    padding: 12px 15px;
    border: 2px solid #16213e;
    background: #1a1a2e;
    color: #ecf0f1;
    border-radius: 5px;
    font-size: 1em;
    transition: all 0.3s ease;
}

#target-input:focus {
    outline: none;
    border-color: #e94560;
    box-shadow: 0 0 10px rgba(233, 69, 96, 0.3);
}

#scan-btn {
    padding: 12px 30px;
    background: linear-gradient(90deg, #e94560 0%, #f39c12 100%);
    color: white;
    border: none;
    border-radius: 5px;
    font-size: 1em;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    box-shadow: 0 4px 15px rgba(233, 69, 96, 0.3);
}

#scan-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(233, 69, 96, 0.4);
}

#scan-btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
}

.dashboard {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
    margin-bottom: 30px;
}

@media (max-width: 1200px) {
    .dashboard {
        grid-template-columns: 1fr;
    }
}

.section {
    background: #0f3460;
    padding: 25px;
    border-radius: 8px;
    border-left: 4px solid #e94560;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    margin-bottom: 25px;
}

.section h2 {
    font-size: 1.5em;
    margin-bottom: 20px;
    color: #e94560;
    font-weight: 700;
    border-bottom: 2px solid #16213e;
    padding-bottom: 10px;
}

.info-text {
    font-size: 0.9em;
    color: #95a5a6;
    margin-bottom: 15px;
}

.highlight {
    color: #3498db;
    font-weight: bold;
}

.secondary {
    color: #7f8c8d;
}

.tech-list {
    list-style: none;
    padding: 0;
}

.tech-list li {
    padding: 10px;
    margin: 8px 0;
    background: #1a1a2e;
    border-left: 3px solid #3498db;
    border-radius: 5px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.tech-name {
    color: #3498db;
    font-weight: bold;
    flex: 1;
}

.tech-version {
    color: #e74c3c;
    margin: 0 15px;
    font-weight: bold;
}

.tech-source {
    color: #7f8c8d;
    font-size: 0.85em;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

thead {
    background: #16213e;
    border-bottom: 2px solid #e94560;
}

th {
    padding: 15px;
    text-align: left;
    color: #e94560;
    font-weight: 700;
}

td {
    padding: 12px 15px;
    border-bottom: 1px solid #16213e;
}

tr:hover {
    background: rgba(233, 69, 96, 0.1);
}

.exploitable-row {
    background: rgba(231, 76, 60, 0.1) !important;
}

.cve-link {
    color: #3498db;
    text-decoration: none;
    font-weight: bold;
    transition: color 0.3s ease;
}

.cve-link:hover {
    color: #e94560;
}

.cvss-badge {
    padding: 5px 10px;
    border-radius: 5px;
    font-weight: bold;
    font-size: 0.85em;
}

.cvss-badge.critical {
    background: #e74c3c;
    color: white;
}

.cvss-badge.high {
    background: #e67e22;
    color: white;
}

.cvss-badge.medium {
    background: #f39c12;
    color: white;
}

.cvss-badge.low {
    background: #2ecc71;
    color: white;
}

.description-cell {
    font-size: 0.85em;
    color: #bdc3c7;
    max-width: 300px;
}

/* Markdown 스타일 */
.markdown-content h1,
.markdown-content h2,
.markdown-content h3,
.markdown-content h4,
.markdown-content h5,
.markdown-content h6 {
    margin-top: 20px;
    margin-bottom: 10px;
    font-weight: 700;
    color: #e94560;
}

.markdown-content h2 {
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
    color: #3498db;
}

.markdown-content h3 {
    color: #2ecc71;
}

.markdown-content ul,
.markdown-content ol {
    margin-left: 20px;
    margin-bottom: 15px;
}

.markdown-content li {
    margin-bottom: 8px;
    color: #ecf0f1;
}

.markdown-content strong {
    color: #e74c3c;
    font-weight: bold;
}

.markdown-content em {
    color: #f39c12;
    font-style: italic;
}

.markdown-content code {
    background: #1a1a2e;
    color: #2ecc71;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
}

.markdown-content pre {
    background: #1a1a2e;
    color: #2ecc71;
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #e94560;
    overflow-x: auto;
    margin: 15px 0;
}

.markdown-content pre code {
    background: none;
    color: inherit;
    padding: 0;
}

.markdown-content blockquote {
    border-left: 4px solid #3498db;
    padding-left: 15px;
    color: #95a5a6;
    font-style: italic;
    margin-left: 0;
}

/* Loot 리스트 */
#sensitive-files-list {
    list-style: none;
    padding: 0;
}

#sensitive-files-list li {
    padding: 12px;
    margin: 8px 0;
    background: #1a1a2e;
    border-left: 3px solid #e74c3c;
    border-radius: 5px;
    color: #ecf0f1;
}

#sensitive-files-list li.exploitable {
    border-left-color: #e74c3c;
    background: rgba(231, 76, 60, 0.1);
}

#sensitive-files-list li.warning {
    border-left-color: #f39c12;
    background: rgba(243, 156, 18, 0.1);
}

.file-path {
    color: #3498db;
    font-weight: bold;
    display: inline-block;
    margin-right: 10px;
}

.file-status {
    color: #e74c3c;
    font-weight: bold;
    display: inline-block;
    margin-right: 10px;
}

.file-note {
    color: #7f8c8d;
    font-size: 0.85em;
    display: block;
    margin-top: 5px;
}

/* 모달 */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0, 0, 0, 0.8);
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.modal-content {
    background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
    margin: 5% auto;
    padding: 30px;
    border: 2px solid #e94560;
    border-radius: 10px;
    width: 90%;
    max-width: 1000px;
    color: #ecf0f1;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
}

.close {
    color: #95a5a6;
    float: right;
    font-size: 32px;
    font-weight: bold;
    cursor: pointer;
    transition: color 0.3s ease;
}

.close:hover {
    color: #e94560;
}

.tech-category {
    margin-bottom: 25px;
}

.tech-category h3 {
    color: #3498db;
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
    margin-bottom: 15px;
}

.tech-category ul {
    list-style: none;
    padding: 0;
}

.tech-category li {
    padding: 10px;
    margin: 8px 0;
    background: #1a1a2e;
    border-left: 3px solid #3498db;
    border-radius: 5px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.no-data {
    color: #95a5a6;
    text-align: center;
    padding: 20px;
    font-style: italic;
}

.error-message {
    color: #e74c3c;
    background: rgba(231, 76, 60, 0.1);
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #e74c3c;
}

.loading {
    color: #3498db;
    font-weight: bold;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.secondary-btn {
    background: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 0.95em;
    transition: all 0.3s ease;
    display: inline-block;
    margin-top: 10px;
}

.secondary-btn:hover {
    background: #2980b9;
    transform: translateY(-2px);
    box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
}
/* 화이트해커용 근거 박스 스타일 */
.tech-card {
    background: #2d2d2d; border-left: 4px solid #007bff;
    margin-bottom: 10px; padding: 12px; border-radius: 4px;
}
.evidence-btn {
    background: #444; color: #aaa; border: none; font-size: 11px;
    cursor: pointer; padding: 2px 8px; margin-top: 5px; border-radius: 3px;
}
.evidence-btn:hover { background: #555; color: #fff; }
.evidence-content {
    display: none; background: #1a1a1a; color: #00ff00;
    padding: 8px; margin-top: 8px; font-family: monospace; font-size: 12px;
    border-radius: 3px; border: 1px dashed #333;
}
.source-badge {
    background: #0056b3; font-size: 10px; padding: 1px 5px;
    border-radius: 4px; margin-left: 5px;
}
```
---

<<<<<<< HEAD
## File 60: url_tree.css
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\static\css\url_tree.css`
=======
## File 69: url_tree.css
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\css\url_tree.css`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1600px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    padding: 30px;
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 2px solid #e0e0e0;
}

header h1 {
    font-size: 2.5em;
    color: #333;
    margin-bottom: 10px;
}

header p {
    color: #666;
    font-size: 1.1em;
}

.control-panel {
    background: #f5f5f5;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 30px;
}

.input-group {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
}

.input-group input {
    flex: 1;
    padding: 12px 20px;
    font-size: 16px;
    border: 2px solid #ddd;
    border-radius: 6px;
    transition: border-color 0.3s;
}

.input-group input:focus {
    outline: none;
    border-color: #667eea;
}

.button-group {
    display: flex;
    gap: 10px;
    justify-content: center;
}

.btn-primary, .btn-secondary {
    padding: 12px 24px;
    font-size: 16px;
    font-weight: 600;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.3s;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
    background: #fff;
    color: #667eea;
    border: 2px solid #667eea;
}

.btn-secondary:hover {
    background: #667eea;
    color: white;
}

.loading {
    text-align: center;
    padding: 40px;
    background: #f9f9f9;
    border-radius: 8px;
    margin: 20px 0;
}

.spinner {
    border: 4px solid #f3f3f3;
    border-top: 4px solid #667eea;
    border-radius: 50%;
    width: 50px;
    height: 50px;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.stats-container {
    margin: 20px 0;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 25px;
    border-radius: 8px;
    text-align: center;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.stat-card h3 {
    font-size: 2.5em;
    margin-bottom: 10px;
}

.stat-card p {
    font-size: 1.1em;
    opacity: 0.9;
}

.legend {
    background: #f9f9f9;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
}

.legend h3 {
    font-size: 1.2em;
    margin-bottom: 15px;
    color: #333;
}

.legend-items {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
}

.color-box {
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 2px solid #333;
}

.tree-container {
    overflow: auto;
    background: #fafafa;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #e0e0e0;
}

.node circle {
    cursor: pointer;
}

.node text {
    font: 12px sans-serif;
    font-weight: 500;
}

.link {
    fill: none;
    stroke: #ccc;
    stroke-width: 2px;
}

@media (max-width: 768px) {
    .container {
        padding: 15px;
    }

    header h1 {
        font-size: 1.8em;
    }

    .input-group {
        flex-direction: column;
    }

    .button-group {
        flex-direction: column;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }
}
```
---
<<<<<<< HEAD
=======

## File 70: dashboard.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\js\dashboard.js`

```javascript
(() => {
    // 1. 소켓 안전 연결 (전역 window 객체 공유)
    if (!window.socket) {
        window.socket = io();
    }
    const socket = window.socket;

    document.addEventListener('DOMContentLoaded', () => {
        // 2. 안전장치: 대시보드 요소 확인
        const scanBtn = document.getElementById('scan-btn');
        const targetInput = document.getElementById('target-input');

        // 요소가 없으면 조용히 종료 (상세 페이지 등에서 에러 방지)
        if (!scanBtn || !targetInput) {
            // console.log('[INFO] Dashboard skipped (Not on dashboard page)');
            return;
        }

        console.log('[INIT] Dashboard initialized');

        // 3. 스캔 시작 로직
        scanBtn.addEventListener('click', () => {
            const target = targetInput.value.trim();
            if (!target) {
                alert('Please enter a valid URL');
                return;
            }

            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

            socket.emit('create_project', { target: target });
        });
    });

    // 4. 소켓 이벤트 리스너
    socket.on('project_created', (data) => {
        if (data.project_id) {
            console.log(`[SUCCESS] Project created: ${data.project_id}`);
            window.location.href = `/live-scan/${data.project_id}`;
        }
    });

    socket.on('error', (data) => {
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) { // 버튼이 있는 경우에만 처리
            console.error('[ERROR]', data.message);
            scanBtn.disabled = false;
            scanBtn.innerHTML = 'Start Scan';
            alert('Error: ' + data.message);
        }
    });
})();
```
---

## File 71: live_scan.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\js\live_scan.js`

```javascript
console.log("⚡ LIVE SCAN JS RELOADED - Clean Version");

// 1. Socket Connection
if (!window.socket) {
    console.log("[DEBUG] Creating new socket connection...");
    window.socket = io();
} else {
    console.log("[DEBUG] Reusing existing socket connection");
}

const liveSocket = window.socket;

// URL Parsing for Project ID
const pathParts = window.location.pathname.split('/');
let pid = pathParts.pop();
if (!pid) pid = pathParts.pop(); // handle trailing slash
const projectId = pid;

let scanActive = false;
let foundTechnologies = {};

// 2. Initialize
document.addEventListener("DOMContentLoaded", function() {
    console.log("[DEBUG] DOMContentLoaded event fired");

    const startBtn = document.getElementById("start-scan-btn");
    
    // [FIX] Restore from LocalStorage (새로고침 시 결과 유지)
    const savedResults = localStorage.getItem("scanResults");
    if (savedResults) {
        try {
            foundTechnologies = JSON.parse(savedResults);
            Object.values(foundTechnologies).forEach(tech => renderTechCard(tech));
            console.log("[DEBUG] Restored previous results from LocalStorage");
        } catch(e) {
            console.error("[ERROR] Failed to restore LocalStorage", e);
            localStorage.removeItem("scanResults");
        }
    }

    if (startBtn) {
        // Remove existing listeners by cloning
        const newBtn = startBtn.cloneNode(true);
        startBtn.parentNode.replaceChild(newBtn, startBtn);
        
        newBtn.addEventListener("click", startScan);
    } else {
        console.error("[ERROR] Start button 'start-scan-btn' NOT FOUND in DOM!");
    }
});

// 3. Socket Events
liveSocket.on("connect", () => {
    console.log("[DEBUG] Socket connected successfully ID:", liveSocket.id);
});

liveSocket.on("scan_progress", (data) => {
    const term = document.getElementById("log-terminal");
    if (!term) return;

    const line = document.createElement("div");
    line.className = "log-line";
    
    let colorClass = "text-light";
    if (data.stage === "error") colorClass = "text-danger";
    else if (data.stage === "success") colorClass = "text-success";
    else if (data.stage === "recon") colorClass = "text-info";

    line.innerHTML = `<span class="text-muted">[${new Date().toLocaleTimeString()}]</span> <span class="${colorClass}">${data.current_item}</span>`;
    
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;

    const progBar = document.getElementById("scan-progress-bar");
    if (progBar) {
        progBar.style.width = data.progress + "%";
        progBar.setAttribute("aria-valuenow", data.progress);
    }
});

liveSocket.on("technology_detected", (tech) => {
    console.log("[DEBUG] Tech detected:", tech.name);
    const techKey = tech.name.toLowerCase();
    
    foundTechnologies[techKey] = tech;
    
    // [FIX] Save to LocalStorage
    localStorage.setItem("scanResults", JSON.stringify(foundTechnologies));

    renderTechCard(tech);
});

liveSocket.on("scan_completed", () => {
    console.log("[DEBUG] Scan completed");
    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-success">Completed</span>';
    
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = false;
    
    scanActive = false;
});

// 4. Core Functions
function startScan() {
    if (scanActive) return;

    const targetUrlElem = document.getElementById("target-url");
    if (!targetUrlElem) return alert("Error: Target URL element not found.");

    const targetUrl = targetUrlElem.textContent.trim();
    if (!targetUrl) return alert("Target URL is empty!");

    // [FIX] Reset Previous Data
    localStorage.removeItem("scanResults");
    foundTechnologies = {};
    const grid = document.getElementById("tech-grid");
    if(grid) grid.innerHTML = "";
    
    const term = document.getElementById("log-terminal");
    if(term) term.innerHTML = '<div class="text-info">Requesting scan start...</div>';

    // UI Updates
    scanActive = true;
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = true;

    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-warning text-dark">Scanning...</span>';

    console.log("[DEBUG] Emitting start_scan event...");
    liveSocket.emit("start_scan", { target: targetUrl, project_id: projectId });
}

function renderTechCard(tech) {
    const grid = document.getElementById("tech-grid");
    if (!grid) return;

    // Check Duplicate
    if (document.getElementById(`tech-card-${tech.name}`)) return;

    const col = document.createElement("div");
    col.className = "col-md-3 mb-3";
    col.innerHTML = `
        <div class="card h-100 shadow-sm tech-card" id="tech-card-${tech.name}" 
             onclick="window.showTechDetail('${tech.name}')" 
             style="cursor: pointer; transition: transform 0.2s;">
            <div class="card-body text-center">
                <h5 class="card-title fw-bold text-primary">${tech.name}</h5>
                <p class="card-text text-muted small">${tech.version || "Version Detected"}</p>
                <span class="badge bg-secondary">${tech.source || "Detected"}</span>
            </div>
        </div>
    `;
    grid.appendChild(col);
}

// Global function for onclick in HTML
window.showTechDetail = function(techName) {
    console.log("[DEBUG] Opening detail for:", techName);
    const tech = foundTechnologies[techName.toLowerCase()];
    if (!tech) return;

    const modalEl = document.getElementById("techModal");
    if (!modalEl) return;

    const modalTitle = document.getElementById("techModalLabel");
    const modalBody = modalEl.querySelector(".modal-body");

    modalTitle.innerHTML = `${tech.name} <span class="badge bg-primary ms-2">${tech.version || "N/A"}</span>`;

    let evidenceList = tech.evidence || [];
    if (typeof evidenceList === 'string') evidenceList = evidenceList.split('\n');
    else if (!Array.isArray(evidenceList)) evidenceList = [evidenceList];

    let hints = tech.hints || ["No specific verification hints available."];
    
    // Safe HTML Generation
    let evidenceHtml = evidenceList.map(ev => {
        return `<tr><td class="text-primary fw-bold">Scanner</td><td class="font-monospace small">${ev}</td></tr>`;
    }).join('');

    let hintsText = Array.isArray(hints) ? hints.join('\n') : hints;

    modalBody.innerHTML = `
        <div class="container-fluid">
            <div class="row mb-3">
                <div class="col-md-6"><small class="text-muted text-uppercase">Confidence</small><br>
                    <span class="fw-bold ${tech.confidence === 'High' ? 'text-success' : 'text-warning'}">${tech.confidence || "Medium"}</span>
                </div>
                <div class="col-md-6"><small class="text-muted text-uppercase">Source</small><br>
                    <span class="fw-bold">${tech.source}</span>
                </div>
            </div>
            <hr>
            <h6 class="fw-bold text-dark mb-2">Evidence</h6>
            <div class="table-responsive mb-3">
                <table class="table table-sm table-bordered">
                    <thead class="table-light"><tr><th>Source</th><th>Raw Evidence</th></tr></thead>
                    <tbody>${evidenceHtml}</tbody>
                </table>
            </div>
            <h6 class="fw-bold text-dark mb-2">Manual Verification</h6>
            <div class="bg-dark text-light p-3 rounded position-relative font-monospace small">
                <button class="btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2 copy-btn">Copy</button>
                <div id="hint-content">${hintsText}</div>
            </div>
        </div>
    `;

    // Show Modal
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
};

// 5. Global Event Listener (Cleanup & Fixes)
document.addEventListener("click", function(e) {
    // Copy Button
    const copyBtn = e.target.closest(".copy-btn");
    if (copyBtn) {
        const content = document.getElementById("hint-content");
        if (content) {
            navigator.clipboard.writeText(content.innerText).then(() => {
                const original = copyBtn.innerHTML;
                copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => copyBtn.innerHTML = original, 1500);
            });
        }
    }
});
```
---

## File 72: url_tree.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\js\url_tree.js`

```javascript
class URLTreeVisualizer {
    constructor(containerId) {
        this.container = d3.select(`#${containerId}`);
        this.margin = {top: 20, right: 120, bottom: 20, left: 120};
        this.width = 1400 - this.margin.right - this.margin.left;
        this.height = 800 - this.margin.top - this.margin.bottom;
        this.duration = 750;
        this.i = 0;

        this.tree = d3.tree().size([this.height, this.width]);

        this.svg = this.container.append("svg")
            .attr("width", this.width + this.margin.right + this.margin.left)
            .attr("height", this.height + this.margin.top + this.margin.bottom)
            .append("g")
            .attr("transform", `translate(${this.margin.left},${this.margin.top})`);
    }

    async loadData(targetUrl) {
        try {
            const response = await fetch('/api/url-tree', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: targetUrl})
            });
            const data = await response.json();

            if (data.tree) {
                this.root = d3.hierarchy(data.tree);
                this.root.x0 = this.height / 2;
                this.root.y0 = 0;

                this.root.children.forEach(d => this.collapse(d));
                this.update(this.root);
                return data;
            }
        } catch (error) {
            console.error('Error loading tree data:', error);
            throw error;
        }
    }

    collapse(d) {
        if (d.children) {
            d._children = d.children;
            d._children.forEach(child => this.collapse(child));
            d.children = null;
        }
    }

    update(source) {
        const treeData = this.tree(this.root);
        const nodes = treeData.descendants();
        const links = treeData.descendants().slice(1);

        nodes.forEach(d => { d.y = d.depth * 180; });

        const node = this.svg.selectAll('g.node')
            .data(nodes, d => d.id || (d.id = ++this.i));

        const nodeEnter = node.enter().append('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(${source.y0},${source.x0})`)
            .on('click', (event, d) => this.click(d));

        nodeEnter.append('circle')
            .attr('r', 1e-6)
            .style('fill', d => d._children ? '#90caf9' : '#fff')
            .style('stroke', d => this.getNodeColor(d.data))
            .style('stroke-width', '3px');

        nodeEnter.append('text')
            .attr('dy', '.35em')
            .attr('x', d => d.children || d._children ? -13 : 13)
            .attr('text-anchor', d => d.children || d._children ? 'end' : 'start')
            .text(d => d.data.name)
            .style('fill-opacity', 1e-6);

        const nodeUpdate = nodeEnter.merge(node);

        nodeUpdate.transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${d.y},${d.x})`);

        nodeUpdate.select('circle')
            .attr('r', 6)
            .style('fill', d => d._children ? '#90caf9' : '#fff')
            .style('stroke', d => this.getNodeColor(d.data))
            .attr('cursor', 'pointer');

        nodeUpdate.select('text')
            .style('fill-opacity', 1);

        const nodeExit = node.exit().transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${source.y},${source.x})`)
            .remove();

        nodeExit.select('circle')
            .attr('r', 1e-6);

        nodeExit.select('text')
            .style('fill-opacity', 1e-6);

        const link = this.svg.selectAll('path.link')
            .data(links, d => d.id);

        const linkEnter = link.enter().insert('path', 'g')
            .attr('class', 'link')
            .attr('d', d => {
                const o = {x: source.x0, y: source.y0};
                return this.diagonal(o, o);
            });

        const linkUpdate = linkEnter.merge(link);

        linkUpdate.transition()
            .duration(this.duration)
            .attr('d', d => this.diagonal(d, d.parent));

        link.exit().transition()
            .duration(this.duration)
            .attr('d', d => {
                const o = {x: source.x, y: source.y};
                return this.diagonal(o, o);
            })
            .remove();

        nodes.forEach(d => {
            d.x0 = d.x;
            d.y0 = d.y;
        });
    }

    diagonal(s, d) {
        return `M ${s.y} ${s.x}
                C ${(s.y + d.y) / 2} ${s.x},
                  ${(s.y + d.y) / 2} ${d.x},
                  ${d.y} ${d.x}`;
    }

    click(d) {
        if (d.children) {
            d._children = d.children;
            d.children = null;
        } else {
            d.children = d._children;
            d._children = null;
        }
        this.update(d);
    }

    getNodeColor(nodeData) {
        if (nodeData.status_code) {
            if (nodeData.status_code >= 200 && nodeData.status_code < 300) return '#4caf50';
            if (nodeData.status_code >= 300 && nodeData.status_code < 400) return '#ff9800';
            if (nodeData.status_code >= 400 && nodeData.status_code < 500) return '#f44336';
            if (nodeData.status_code >= 500) return '#9c27b0';
        }
        return '#1976d2';
    }

    expandAll() {
        this.root.children.forEach(d => this.expandRecursive(d));
        this.update(this.root);
    }

    collapseAll() {
        this.root.children.forEach(d => this.collapse(d));
        this.update(this.root);
    }

    expandRecursive(d) {
        if (d._children) {
            d.children = d._children;
            d._children = null;
        }
        if (d.children) {
            d.children.forEach(child => this.expandRecursive(child));
        }
    }
}

let treeVisualizer;

async function scanAndVisualize() {
    const targetUrl = document.getElementById('targetUrl').value;
    if (!targetUrl) {
        alert('Please enter a target URL');
        return;
    }

    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('treeContainer').innerHTML = '';
    document.getElementById('statsContainer').innerHTML = '';

    try {
        treeVisualizer = new URLTreeVisualizer('treeContainer');
        const data = await treeVisualizer.loadData(targetUrl);

        document.getElementById('statsContainer').innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>${data.total_urls}</h3>
                    <p>Total URLs</p>
                </div>
                <div class="stat-card">
                    <h3>${data.tree_nodes || data.statistics?.total_nodes || 'N/A'}</h3>
                    <p>Tree Nodes</p>
                </div>
                <div class="stat-card">
                    <h3>${data.max_depth || data.statistics?.max_depth || 'N/A'}</h3>
                    <p>Max Depth</p>
                </div>
            </div>
        `;

        document.getElementById('loadingIndicator').style.display = 'none';
    } catch (error) {
        document.getElementById('loadingIndicator').style.display = 'none';
        alert('Error loading tree: ' + error.message);
    }
}

function expandAll() {
    if (treeVisualizer) {
        treeVisualizer.expandAll();
    }
}

function collapseAll() {
    if (treeVisualizer) {
        treeVisualizer.collapseAll();
    }
}
```
---

## File 73: base.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\base.html`

```html
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>CVE Recon & AI Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body class="bg-dark text-light">
  <nav class="navbar navbar-dark bg-black border-bottom border-secondary mb-3">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">CVE Attack Simulation Dashboard</span>
    </div>
  </nav>

  <div class="container-fluid">
    {% block content %}{% endblock %}
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>
```
---

## File 74: dashboard copy.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\dashboard copy.html`

```html
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Dashboard</title>
    <!-- Socket.IO Library 추가 -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; line-height: 1.6; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        header { text-align: center; padding: 40px 0 20px; border-bottom: 2px solid #0f3460; margin-bottom: 30px; }
        h1 { font-size: 2.5em; color: #00d4ff; text-shadow: 0 0 10px rgba(0, 212, 255, 0.5); margin-bottom: 10px; }
        .scan-section { margin-bottom: 30px; background: rgba(15, 52, 96, 0.5); border: 1px solid #0f3460; border-radius: 8px; padding: 20px; backdrop-filter: blur(10px); }
        .scan-controls { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
        input[type="text"], input[type="url"] { flex: 1; min-width: 300px; padding: 12px 15px; background: rgba(255, 255, 255, 0.1); border: 1px solid #0f3460; border-radius: 6px; color: #e0e0e0; font-size: 14px; }
        input[type="text"]:focus, input[type="url"]:focus { outline: none; border-color: #00d4ff; box-shadow: 0 0 10px rgba(0, 212, 255, 0.3); }
        button { padding: 12px 30px; background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%); border: none; border-radius: 6px; color: #000; font-weight: bold; cursor: pointer; transition: all 0.3s ease; font-size: 14px; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3); }
        button:disabled { background: #666; cursor: not-allowed; opacity: 0.6; }
        .loading { display: flex; align-items: center; justify-content: center; gap: 10px; padding: 20px; color: #00d4ff; }
        .spinner { border: 3px solid rgba(0, 212, 255, 0.2); border-top: 3px solid #00d4ff; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        
        /* [NEW] 실시간 로그 박스 스타일 */
        #live-log-container { display: none; margin-top: 20px; background: rgba(0, 0, 0, 0.8); border: 1px solid #0f3460; border-radius: 8px; padding: 15px; }
        #live-scan-log { height: 200px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.9em; color: #00ff88; }
        .log-info { color: #00d4ff; }
        .log-success { color: #00ff88; font-weight: bold; }
        .log-error { color: #ff4444; }

        .section-title { font-size: 1.5em; color: #00d4ff; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #0f3460; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: rgba(0, 212, 255, 0.1); border: 1px solid #00d4ff; border-radius: 6px; padding: 15px; text-align: center; }
        .stat-label { font-size: 0.9em; color: #aaa; margin-bottom: 8px; }
        .stat-value { font-size: 2em; font-weight: bold; color: #00d4ff; }
        .severity-high { color: #ff4444; }
        .severity-medium { color: #ffaa00; }
        .severity-low { color: #00ff88; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        thead { background: rgba(0, 212, 255, 0.15); }
        th { padding: 12px; text-align: left; color: #00d4ff; font-weight: bold; border-bottom: 2px solid #0f3460; }
        td { padding: 12px; border-bottom: 1px solid rgba(0, 212, 255, 0.1); }
        tr:hover { background: rgba(0, 212, 255, 0.05); }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; margin-right: 5px; }
        .badge-high { background: rgba(255, 68, 68, 0.3); color: #ff4444; border: 1px solid #ff4444; }
        .badge-medium { background: rgba(255, 170, 0, 0.3); color: #ffaa00; border: 1px solid #ffaa00; }
        .badge-low { background: rgba(0, 255, 136, 0.3); color: #00ff88; border: 1px solid #00ff88; }
        .badge-info { background: rgba(0, 212, 255, 0.3); color: #00d4ff; border: 1px solid #00d4ff; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 2px solid #0f3460; flex-wrap: wrap; }
        .tab-button { padding: 10px 20px; background: transparent; border: none; border-bottom: 3px solid transparent; color: #aaa; cursor: pointer; font-weight: bold; transition: all 0.3s ease; }
        .tab-button.active { color: #00d4ff; border-bottom-color: #00d4ff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .cve-item { background: rgba(0, 0, 0, 0.3); border-left: 4px solid #00d4ff; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
        .cve-id { font-weight: bold; color: #00d4ff; font-family: monospace; }
        .cve-description { margin-top: 8px; color: #bbb; font-size: 0.95em; }
        .alert-item { background: rgba(0, 0, 0, 0.3); border-left: 4px solid #ffaa00; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
        .alert-item.high { border-left-color: #ff4444; }
        .alert-item.low { border-left-color: #00ff88; }
        .tech-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .tech-card { background: rgba(0, 212, 255, 0.1); border: 1px solid #00d4ff; border-radius: 6px; padding: 15px; }
        .tech-name { font-weight: bold; color: #00d4ff; margin-bottom: 8px; }
        .tech-version { color: #aaa; font-size: 0.9em; margin-bottom: 5px; }
        .tech-source { font-size: 0.85em; color: #888; }
        .scenario-box { background: rgba(0, 0, 0, 0.5); border: 1px solid #0f3460; border-radius: 6px; padding: 20px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; font-size: 0.95em; color: #00ff88; max-height: 500px; overflow-y: auto; }
        .error-message { background: rgba(255, 68, 68, 0.2); border: 1px solid #ff4444; border-radius: 6px; padding: 15px; color: #ff8888; margin-bottom: 20px; }
        .success-message { background: rgba(0, 255, 136, 0.2); border: 1px solid #00ff88; border-radius: 6px; padding: 15px; color: #00ff88; margin-bottom: 20px; }
        .empty-state { text-align: center; padding: 40px; color: #aaa; }
        .footer { text-align: center; padding: 20px; color: #666; border-top: 2px solid #0f3460; margin-top: 40px; }
        .severity-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .severity-indicator.high { background: #ff4444; }
        .severity-indicator.medium { background: #ffaa00; }
        .severity-indicator.low { background: #00ff88; }
        .scroll-table { overflow-x: auto; }
        .json-viewer { background: rgba(0, 0, 0, 0.5); border: 1px solid #0f3460; border-radius: 6px; padding: 15px; font-family: 'Courier New', monospace; font-size: 0.9em; color: #00d4ff; max-height: 400px; overflow-y: auto; }
        .filter-buttons { margin-bottom: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; background: rgba(0, 212, 255, 0.3); color: #00d4ff; border: 1px solid #00d4ff; border-radius: 6px; cursor: pointer; transition: all 0.3s ease; }
        .filter-btn.active { background: #00d4ff; color: #000; }
        .filter-btn:hover { background: rgba(0, 212, 255, 0.5); }
        @media (max-width: 768px) {
            h1 { font-size: 1.8em; }
            .scan-controls { flex-direction: column; }
            input[type="text"], input[type="url"] { min-width: auto; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .tech-list { grid-template-columns: 1fr; }
            .tabs { flex-wrap: wrap; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Scan Dashboard</h1>
            <p>Comprehensive vulnerability assessment and analysis</p>
        </header>

        <!-- Scan Controls -->
        <div class="scan-section">
            <div class="scan-controls">
                <input type="url" id="targetInput" placeholder="Enter target URL (e.g., http://127.0.0.1:3000)" value="http://127.0.0.1:3000">
                <button id="scanButton" onclick="startScan()">🚀 Start Scan</button>
            </div>
            
            <div id="loadingIndicator" class="loading" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning in progress... This may take several minutes</span>
            </div>
            
            <!-- [NEW] 실시간 로그 박스 -->
            <div id="live-log-container">
                <div style="margin-bottom: 5px; color: #aaa; font-size: 0.8em; border-bottom: 1px solid #333; padding-bottom: 5px;">
                    ⚡ LIVE SCAN LOGS
                </div>
                <div id="live-scan-log"></div>
            </div>

            <div id="errorMessage" class="error-message" style="display: none;"></div>
            <div id="successMessage" class="success-message" style="display: none;"></div>
        </div>

        <!-- Summary Stats -->
        <div class="scan-section" id="statsSection" style="display: none;">
            <h2 class="section-title">Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Technologies Detected</div>
                    <div class="stat-value" id="techCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">CVEs Found</div>
                    <div class="stat-value" id="cveCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">ZAP Alerts</div>
                    <div class="stat-value" id="zapCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities Verified</div>
                    <div class="stat-value" id="verifyCount">0</div>
                </div>
            </div>

            <!-- Alert Breakdown -->
            <div style="margin-top: 20px;">
                <h3 style="color: #00d4ff; margin-bottom: 10px;">Alert Severity Breakdown</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">High Risk</div>
                        <div class="stat-value severity-high" id="highCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Medium Risk</div>
                        <div class="stat-value severity-medium" id="mediumCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Low Risk</div>
                        <div class="stat-value severity-low" id="lowCount">0</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Tabs -->
        <div class="scan-section" id="resultsSection" style="display: none;">
            <div class="tabs">
                <button class="tab-button active" onclick="switchTab(event, 'technologies')">Technologies</button>
                <button class="tab-button" onclick="switchTab(event, 'cves')">CVEs</button>
                <button class="tab-button" onclick="switchTab(event, 'zap-alerts')">ZAP Alerts</button>
                <button class="tab-button" onclick="switchTab(event, 'verification')">Verification</button>
                <button class="tab-button" onclick="switchTab(event, 'scenario')">AI Scenario</button>
                <button class="tab-button" onclick="switchTab(event, 'raw-data')">Raw Data</button>
            </div>

            <!-- Technologies Tab -->
            <div id="technologies" class="tab-content active">
                <h2 class="section-title">Detected Technologies</h2>
                <div id="techContainer" class="tech-list"></div>
            </div>

            <!-- CVEs Tab -->
            <div id="cves" class="tab-content">
                <h2 class="section-title">CVE Vulnerabilities</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS</th>
                                <th>Description</th>
                                <th>Product</th>
                            </tr>
                        </thead>
                        <tbody id="cveTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- ZAP Alerts Tab -->
            <div id="zap-alerts" class="tab-content">
                <h2 class="section-title">OWASP ZAP Security Alerts</h2>
                <!-- Filter Buttons -->
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterZapAlerts(event, 'all')">All</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'High')">High</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Medium')">Medium</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Low')">Low</button>
                </div>
                <div id="zapContainer"></div>
            </div>

            <!-- Verification Tab -->
            <div id="verification" class="tab-content">
                <h2 class="section-title">Vulnerability Verification Results</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Endpoint</th>
                                <th>Status</th>
                                <th>Confidence</th>
                                <th>Exploitable</th>
                            </tr>
                        </thead>
                        <tbody id="verificationTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- AI Scenario Tab -->
            <div id="scenario" class="tab-content">
                <h2 class="section-title">🤖 AI-Powered Attack Scenario</h2>
                <div id="scenarioContainer" class="scenario-box"></div>
            </div>

            <!-- Raw Data Tab -->
            <div id="raw-data" class="tab-content">
                <h2 class="section-title">Raw API Response</h2>
                <div id="rawDataContainer" class="json-viewer"></div>
            </div>
        </div>

        <footer class="footer">
            <p>Security Scan Dashboard | Powered by Nmap, CVE Database, and OWASP ZAP</p>
        </footer>
    </div>

    <!-- 메인 로직은 dashboard.js에 위임하되, 전역 변수 설정 -->
    <script>
        let currentScanData = null;
        let allZapAlerts = [];
        let currentZapFilter = 'all';
    </script>
    
    <!-- 기존 JS 파일 로드 -->
    <script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>
```
---

## File 75: dashboard.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\dashboard.html`

```html
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 40px 0 20px;
            border-bottom: 2px solid #0f3460;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 2.5em;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            margin-bottom: 10px;
        }

        .scan-section {
            margin-bottom: 30px;
            background: rgba(15, 52, 96, 0.5);
            border: 1px solid #0f3460;
            border-radius: 8px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }

        .scan-controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        input[type="text"],
        input[type="url"] {
            flex: 1;
            min-width: 300px;
            padding: 12px 15px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #0f3460;
            border-radius: 6px;
            color: #e0e0e0;
            font-size: 14px;
        }

        input[type="text"]:focus,
        input[type="url"]:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
        }

        button {
            padding: 12px 30px;
            background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
            border: none;
            border-radius: 6px;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3);
        }

        button:disabled {
            background: #666;
            cursor: not-allowed;
            opacity: 0.6;
        }

        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 20px;
            color: #00d4ff;
        }

        .spinner {
            border: 3px solid rgba(0, 212, 255, 0.2);
            border-top: 3px solid #00d4ff;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .section-title {
            font-size: 1.5em;
            color: #00d4ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #0f3460;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .stat-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }

        .stat-label {
            font-size: 0.9em;
            color: #aaa;
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00d4ff;
        }

        .severity-high {
            color: #ff4444;
        }

        .severity-medium {
            color: #ffaa00;
        }

        .severity-low {
            color: #00ff88;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        thead {
            background: rgba(0, 212, 255, 0.15);
        }

        th {
            padding: 12px;
            text-align: left;
            color: #00d4ff;
            font-weight: bold;
            border-bottom: 2px solid #0f3460;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid rgba(0, 212, 255, 0.1);
        }

        tr:hover {
            background: rgba(0, 212, 255, 0.05);
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }

        .badge-high {
            background: rgba(255, 68, 68, 0.3);
            color: #ff4444;
            border: 1px solid #ff4444;
        }

        .badge-medium {
            background: rgba(255, 170, 0, 0.3);
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }

        .badge-low {
            background: rgba(0, 255, 136, 0.3);
            color: #00ff88;
            border: 1px solid #00ff88;
        }

        .badge-info {
            background: rgba(0, 212, 255, 0.3);
            color: #00d4ff;
            border: 1px solid #00d4ff;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #0f3460;
            flex-wrap: wrap;
        }

        .tab-button {
            padding: 10px 20px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            color: #aaa;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }

        .tab-button.active {
            color: #00d4ff;
            border-bottom-color: #00d4ff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .cve-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid #00d4ff;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .cve-id {
            font-weight: bold;
            color: #00d4ff;
            font-family: monospace;
        }

        .cve-description {
            margin-top: 8px;
            color: #bbb;
            font-size: 0.95em;
        }

        .alert-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid #ffaa00;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .alert-item.high {
            border-left-color: #ff4444;
        }

        .alert-item.low {
            border-left-color: #00ff88;
        }

        .tech-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .tech-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 6px;
            padding: 15px;
        }

        .tech-name {
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 8px;
        }

        .tech-version {
            color: #aaa;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .tech-source {
            font-size: 0.85em;
            color: #888;
        }

        .scenario-box {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #0f3460;
            border-radius: 6px;
            padding: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            color: #00ff88;
            max-height: 500px;
            overflow-y: auto;
        }

        .error-message {
            background: rgba(255, 68, 68, 0.2);
            border: 1px solid #ff4444;
            border-radius: 6px;
            padding: 15px;
            color: #ff8888;
            margin-bottom: 20px;
        }

        .success-message {
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid #00ff88;
            border-radius: 6px;
            padding: 15px;
            color: #00ff88;
            margin-bottom: 20px;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #aaa;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 2px solid #0f3460;
            margin-top: 40px;
        }

        .severity-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .severity-indicator.high {
            background: #ff4444;
        }

        .severity-indicator.medium {
            background: #ffaa00;
        }

        .severity-indicator.low {
            background: #00ff88;
        }

        .scroll-table {
            overflow-x: auto;
        }

        .json-viewer {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #0f3460;
            border-radius: 6px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #00d4ff;
            max-height: 400px;
            overflow-y: auto;
        }

        .filter-buttons {
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 8px 16px;
            background: rgba(0, 212, 255, 0.3);
            color: #00d4ff;
            border: 1px solid #00d4ff;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .filter-btn.active {
            background: #00d4ff;
            color: #000;
        }

        .filter-btn:hover {
            background: rgba(0, 212, 255, 0.5);
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 1.8em;
            }

            .scan-controls {
                flex-direction: column;
            }

            input[type="text"],
            input[type="url"] {
                min-width: auto;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .tech-list {
                grid-template-columns: 1fr;
            }

            .tabs {
                flex-wrap: wrap;
            }
        }
    
/* Deep Fingerprinting Trace Styles */
.layer-card {
    background: rgba(0, 0, 0, 0.3);
    border-left: 4px solid #00d4ff;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    transition: all 0.3s ease;
    position: relative;
}

.layer-card.analyzing {
    border-left-color: #ffaa00;
    animation: pulse 1.5s infinite;
}

.layer-card.completed {
    border-left-color: #00ff88;
}

.layer-card.failed {
    border-left-color: #ff4444;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
}

.layer-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}

.layer-title {
    font-size: 1.3em;
    color: #00d4ff;
    font-weight: bold;
}

.layer-status {
    display: inline-block;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 0.85em;
    font-weight: bold;
}

.layer-status.analyzing {
    background: rgba(255, 170, 0, 0.2);
    color: #ffaa00;
    border: 1px solid #ffaa00;
}

.layer-status.completed {
    background: rgba(0, 255, 136, 0.2);
    color: #00ff88;
    border: 1px solid #00ff88;
}

.layer-status.failed {
    background: rgba(255, 68, 68, 0.2);
    color: #ff4444;
    border: 1px solid #ff4444;
}

.layer-description {
    color: #aaa;
    font-size: 0.95em;
    margin-bottom: 15px;
}

.layer-metrics {
    display: flex;
    gap: 20px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}

.layer-metric {
    display: flex;
    align-items: center;
    gap: 8px;
}

.layer-metric-label {
    color: #888;
    font-size: 0.9em;
}

.layer-metric-value {
    color: #00d4ff;
    font-weight: bold;
}

.tech-list-horizontal {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 15px;
}

.tech-badge {
    background: rgba(0, 212, 255, 0.15);
    border: 1px solid #00d4ff;
    border-radius: 6px;
    padding: 8px 15px;
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 150px;
}

.tech-badge.verified {
    border-color: #00ff88;
    background: rgba(0, 255, 136, 0.15);
}

.tech-badge-name {
    color: #00d4ff;
    font-weight: bold;
    font-size: 0.95em;
}

.tech-badge.verified .tech-badge-name {
    color: #00ff88;
}

.tech-badge-meta {
    color: #888;
    font-size: 0.8em;
}

.tech-badge-version {
    color: #ffaa00;
    font-size: 0.85em;
    font-weight: bold;
}

.confidence-bar-container {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    height: 8px;
    overflow: hidden;
    margin-top: 5px;
}

.confidence-bar {
    height: 100%;
    background: linear-gradient(90deg, #ff4444 0%, #ffaa00 50%, #00ff88 100%);
    transition: width 0.3s ease;
    border-radius: 10px;
}

.layer-timeline-connector {
    width: 2px;
    height: 30px;
    background: linear-gradient(180deg, #00d4ff 0%, transparent 100%);
    margin: 0 auto;
}
</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 Security Scan Dashboard</h1>
            <p>Comprehensive vulnerability assessment and analysis</p>
        </header>

        <!-- Scan Controls -->
        <div class="scan-section">
            <div class="scan-controls">
                <input type="url" id="targetInput" placeholder="Enter target URL (e.g., http://127.0.0.1:3000)" value="http://127.0.0.1:3000">
                <button id="scanButton" onclick="startScan()">🚀 Start Scan</button>
            </div>
            <div id="loadingIndicator" class="loading" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning in progress... This may take several minutes</span>
            </div>
            <div id="errorMessage" class="error-message" style="display: none;"></div>
            <div id="successMessage" class="success-message" style="display: none;"></div>
        </div>

        <!-- Summary Stats -->
        <div class="scan-section" id="statsSection" style="display: none;">
            <h2 class="section-title">📊 Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Technologies Detected</div>
                    <div class="stat-value" id="techCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">CVEs Found</div>
                    <div class="stat-value" id="cveCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">ZAP Alerts</div>
                    <div class="stat-value" id="zapCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities Verified</div>
                    <div class="stat-value" id="verifyCount">0</div>
                </div>
            </div>

            <!-- Alert Breakdown -->
            <div style="margin-top: 20px;">
                <h3 style="color: #00d4ff; margin-bottom: 10px;">Alert Severity Breakdown</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">High Risk</div>
                        <div class="stat-value severity-high" id="highCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Medium Risk</div>
                        <div class="stat-value severity-medium" id="mediumCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Low Risk</div>
                        <div class="stat-value severity-low" id="lowCount">0</div>
                    </div>
                </div>
            </div>
        </div>

    
    <!-- Deep Fingerprinting Trace Section -->
    <div class="scan-section" id="deep-fingerprint-section" style="display: none;">
        <h2 class="section-title">🔍 Deep Fingerprinting Trace</h2>
        <p style="color: #aaa; margin-bottom: 20px;">
            Multi-layer technology detection with progressive confidence building
        </p>

        <!-- Timeline Visualization -->
        <div id="fingerprint-timeline" style="margin-bottom: 30px;">
            <!-- Layer cards will be dynamically inserted here -->
        </div>

        <!-- Summary Stats -->
        <div class="stats-grid" style="margin-top: 20px;">
            <div class="stat-card">
                <div class="stat-label">Total Layers</div>
                <div class="stat-value" id="fp-total-layers">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Technologies Found</div>
                <div class="stat-value" id="fp-total-techs">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Duration</div>
                <div class="stat-value" id="fp-duration">0s</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Confidence</div>
                <div class="stat-value" id="fp-avg-confidence">0%</div>
            </div>
        </div>
    </div>

    <!-- Results Tabs -->
        <div class="scan-section" id="resultsSection" style="display: none;">
            <div class="tabs">
                <button class="tab-button active" onclick="switchTab(event, 'technologies')">🔧 Technologies</button>
                <button class="tab-button" onclick="switchTab(event, 'cves')">🚨 CVEs</button>
                <button class="tab-button" onclick="switchTab(event, 'zap-alerts')">⚠️ ZAP Alerts</button>
                <button class="tab-button" onclick="switchTab(event, 'verification')">✅ Verification</button>
                <button class="tab-button" onclick="switchTab(event, 'scenario')">🤖 AI Scenario</button>
                <button class="tab-button" onclick="switchTab(event, 'raw-data')">📋 Raw Data</button>
            </div>

            <!-- Technologies Tab -->
            <div id="technologies" class="tab-content active">
                <h2 class="section-title">Detected Technologies</h2>
                <div id="techContainer" class="tech-list"></div>
            </div>

            <!-- CVEs Tab -->
            <div id="cves" class="tab-content">
                <h2 class="section-title">CVE Vulnerabilities</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS</th>
                                <th>Description</th>
                                <th>Product</th>
                            </tr>
                        </thead>
                        <tbody id="cveTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- ZAP Alerts Tab -->
            <div id="zap-alerts" class="tab-content">
                <h2 class="section-title">OWASP ZAP Security Alerts</h2>
                
                <!-- Filter Buttons -->
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterZapAlerts(event, 'all')">All</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'High')">High</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Medium')">Medium</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Low')">Low</button>
                </div>

                <div id="zapContainer"></div>
            </div>

            <!-- Verification Tab -->
            <div id="verification" class="tab-content">
                <h2 class="section-title">Vulnerability Verification Results</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Endpoint</th>
                                <th>Status</th>
                                <th>Confidence</th>
                                <th>Exploitable</th>
                            </tr>
                        </thead>
                        <tbody id="verificationTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- AI Scenario Tab -->
            <div id="scenario" class="tab-content">
                <h2 class="section-title">🤖 AI-Powered Attack Scenario</h2>
                <div id="scenarioContainer" class="scenario-box"></div>
            </div>

            <!-- Raw Data Tab -->
            <div id="raw-data" class="tab-content">
                <h2 class="section-title">Raw API Response</h2>
                <div id="rawDataContainer" class="json-viewer"></div>
            </div>
        </div>

        <footer class="footer">
            <p>Security Scan Dashboard | Powered by Nmap, CVE Database, and OWASP ZAP</p>
        </footer>
    </div>

    <script>
        let currentScanData = null;
        let allZapAlerts = [];
        let currentZapFilter = 'all';

        async function startScan() {
            const target = document.getElementById('targetInput').value.trim();
            
            if (!target) {
                showError('Please enter a target URL');
                return;
            }

            const scanButton = document.getElementById('scanButton');
            scanButton.disabled = true;
            document.getElementById('loadingIndicator').style.display = 'flex';
            document.getElementById('errorMessage').style.display = 'none';
            document.getElementById('successMessage').style.display = 'none';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ target })
                });

                if (!response.ok) {
                    throw new Error(`HTTP Error: ${response.status}`);
                }

                const data = await response.json();
                currentScanData = data;
                allZapAlerts = data.zap_scan?.alerts || [];

                displayResults(data);
                showSuccess('✅ Scan completed successfully!');
            } catch (error) {
                console.error('Scan error:', error);
                showError(`❌ Scan failed: ${error.message}`);
            } finally {
                scanButton.disabled = false;
                document.getElementById('loadingIndicator').style.display = 'none';
            }
        }

        function displayResults(data) {
            // Show sections
            document.getElementById('statsSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'block';

            // Update stats
            document.getElementById('techCount').textContent = data.technologies?.length || 0;
            document.getElementById('cveCount').textContent = data.cves?.length || 0;
            document.getElementById('zapCount').textContent = data.zap_scan?.alerts?.length || 0;
            document.getElementById('verifyCount').textContent = data.verifications?.length || 0;

            // Severity breakdown
            const zapAlerts = data.zap_scan?.alerts || [];
            const highCount = zapAlerts.filter(a => a.risk === 'High').length;
            const mediumCount = zapAlerts.filter(a => a.risk === 'Medium').length;
            const lowCount = zapAlerts.filter(a => a.risk === 'Low').length;

            document.getElementById('highCount').textContent = highCount;
            document.getElementById('mediumCount').textContent = mediumCount;
            document.getElementById('lowCount').textContent = lowCount;

            // Display technologies
            displayTechnologies(data.technologies || []);

            // Display CVEs
            displayCVEs(data.cves || []);

            // Display ZAP Alerts
            displayZapAlerts(data.zap_scan?.alerts || []);

            // Display Verification Results
            displayVerification(data.verifications || []);

            // Display AI Scenario
            displayScenario(data.scenario || []);

            // Display Raw Data
            displayRawData(data);
        }

        function displayTechnologies(techs) {
            const container = document.getElementById('techContainer');
            
            if (techs.length === 0) {
                container.innerHTML = '<div class="empty-state">No technologies detected</div>';
                return;
            }

            container.innerHTML = techs.map(tech => `
                <div class="tech-card">
                    <div class="tech-name">${tech.product || 'Unknown'}</div>
                    <div class="tech-version">Version: ${tech.version || 'N/A'}</div>
                    <div class="tech-source">Source: <span class="badge badge-info">${tech.source || 'unknown'}</span></div>
                    ${tech.cpe ? `<div class="tech-source" style="margin-top: 10px; word-break: break-all;"><strong>CPE:</strong> <code style="color: #00ff88; font-size: 0.85em;">${tech.cpe}</code></div>` : ''}
                </div>
            `).join('');
        }

        function displayCVEs(cves) {
            const table = document.getElementById('cveTable');
            
            if (cves.length === 0) {
                table.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px;">No CVEs found</td></tr>';
                return;
            }

            table.innerHTML = cves.map(cve => `
                <tr>
                    <td><span class="cve-id">${cve.cve_id || 'N/A'}</span></td>
                    <td><span class="badge ${cve.cvss >= 7 ? 'badge-high' : cve.cvss >= 4 ? 'badge-medium' : 'badge-low'}">${cve.cvss || 'N/A'}</span></td>
                    <td>${truncate(cve.description || '', 100)}</td>
                    <td>${cve.product || 'N/A'}</td>
                </tr>
            `).join('');
        }

        function displayZapAlerts(alerts) {
            const container = document.getElementById('zapContainer');
            
            let filteredAlerts = alerts;
            if (currentZapFilter !== 'all') {
                filteredAlerts = alerts.filter(a => a.risk === currentZapFilter);
            }

            if (filteredAlerts.length === 0) {
                container.innerHTML = `<div class="empty-state">No ZAP alerts found for filter: ${currentZapFilter}</div>`;
                return;
            }

            container.innerHTML = filteredAlerts.slice(0, 50).map(alert => `
                <div class="alert-item ${alert.risk?.toLowerCase() || 'low'}">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span class="severity-indicator ${alert.risk?.toLowerCase() || 'low'}"></span>
                        <strong>${alert.name || 'Unknown Alert'}</strong>
                        <span class="badge ${alert.risk === 'High' ? 'badge-high' : alert.risk === 'Medium' ? 'badge-medium' : 'badge-low'}">${alert.risk || 'Unknown'}</span>
                    </div>
                    <div style="color: #bbb; font-size: 0.9em; margin-bottom: 5px; word-break: break-all;">
                        <strong>URL:</strong> ${alert.url || 'N/A'}
                    </div>
                    <div style="color: #999; font-size: 0.85em;">
                        ${truncate(alert.description || '', 200)}
                    </div>
                </div>
            `).join('');

            if (filteredAlerts.length > 50) {
                container.innerHTML += `<div style="text-align: center; color: #aaa; padding: 20px;">... and ${filteredAlerts.length - 50} more alerts</div>`;
            }
        }

        function displayVerification(verifications) {
            const table = document.getElementById('verificationTable');
            
            if (verifications.length === 0) {
                table.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 20px;">No verification results</td></tr>';
                return;
            }

            table.innerHTML = verifications.map(v => `
                <tr>
                    <td><span class="cve-id">${v.cve_id || 'N/A'}</span></td>
                    <td>${v.endpoint || 'N/A'}</td>
                    <td><span class="badge badge-info">${v.status || 'N/A'}</span></td>
                    <td>
                        <span class="badge ${v.confidence === 'high' ? 'badge-high' : v.confidence === 'medium' ? 'badge-medium' : 'badge-low'}">
                            ${v.confidence || 'N/A'}
                        </span>
                    </td>
                    <td>${v.exploitable ? '<span class="badge badge-high">Yes</span>' : '<span class="badge badge-low">No</span>'}</td>
                </tr>
            `).join('');
        }

        function displayScenario(scenario) {
            const container = document.getElementById('scenarioContainer');
            
            if (!scenario || scenario.length === 0) {
                container.textContent = 'No AI scenario generated';
                return;
            }

            container.textContent = Array.isArray(scenario) ? scenario.join('\n') : scenario;
        }

        function displayRawData(data) {
            const container = document.getElementById('rawDataContainer');
            container.textContent = JSON.stringify(data, null, 2);
        }

        function switchTab(event, tabName) {
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });

            // Remove active class from all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Add active class to clicked button and corresponding content
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        function filterZapAlerts(event, severity) {
            currentZapFilter = severity;
            
            // Update button styles
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');

            // Display filtered alerts
            displayZapAlerts(allZapAlerts);
        }

        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }

        function showSuccess(message) {
            const successDiv = document.getElementById('successMessage');
            successDiv.textContent = message;
            successDiv.style.display = 'block';
        }

        function truncate(str, length) {
            if (str.length <= length) return str;
            return str.substring(0, length) + '...';
        }

        console.log('🔐 Security Dashboard loaded and ready for scanning');
    </script>
    <script src="/static/js/dashboard.js?v=20260103c"></script>
</body>
</html>
```
---

## File 76: live_scan.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\live_scan.html`

```html
{% extends "base.html" %}

{% block content %}
<style>
    /* UI 먹통 방지: 모달을 최상위 레이어로 강제 승격 */
    .modal-backdrop { z-index: 10050 !important; }
    .modal { z-index: 10055 !important; }
    .modal-dialog { z-index: 10060 !important; }
    .modal-content { z-index: 10065 !important; }
    /* 결과 카드가 모달 위를 덮지 못하게 설정 */
    .tech-card { position: relative; z-index: 1; }
</style>

<div class="container-fluid mt-4">
    <div class="row">
        <!-- Sidebar: Control Panel & Log -->
        <div class="col-md-4">
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-primary">Live Scanner Control</h6>
                    <div id="scan-status"><span class="badge bg-secondary">Ready</span></div>
                </div>
                <div class="card-body">
                    <h5 class="mb-3">Target: <span id="target-url" class="text-info">{{ project.target }}</span></h5>
                    
                    <div class="progress mb-3" style="height: 20px;">
                        <div id="scan-progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%"></div>
                    </div>

                    <button id="start-scan-btn" class="btn btn-primary w-100 btn-lg mb-3">
                        <i class="fas fa-radar"></i> Start Deep Recon
                    </button>

                    <div class="terminal-window bg-dark text-light p-3 rounded" style="height: 400px; overflow-y: auto; font-family: monospace; font-size: 0.85rem;" id="log-terminal">
                        <div class="text-muted">Waiting for command...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content: Stats & Grid -->
        <div class="col-md-8">
            <!-- Stats Row -->
            <div class="row">
                <!-- Open Ports -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-primary shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">Open Ports</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-ports">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-network-wired fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tech Stack -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-success shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-success text-uppercase mb-1">Tech Stack</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-tech">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-layer-group fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerabilities -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-warning shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">Vulnerabilities</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-vulns">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-exclamation-triangle fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sitemap -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-info shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-info text-uppercase mb-1">Sitemap</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-urls">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-sitemap fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tech Grid -->
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Detected Technologies & Vulnerabilities</h6>
                </div>
                <div class="card-body">
                    <div class="row" id="tech-grid">
                        <!-- Tech Cards Injected Here -->
                    </div>
                </div>
            </div>

            <!-- Structure Map Placeholder -->
            <div class="card shadow">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Target Structure Map</h6>
                </div>
                <div class="card-body text-center py-5 text-muted">
                    <i class="fas fa-sitemap fa-3x mb-3"></i><br>
                    Structure map will be implemented in Phase 2.
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Technology Detail Modal -->
<div class="modal fade" id="techModal" tabindex="-1" aria-labelledby="techModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header bg-light">
                <h5 class="modal-title fw-bold" id="techModalLabel">Technology Detail</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <!-- Modal content will be dynamically injected via JS -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script src="{{ url_for('static', filename='js/live_scan.js') }}?version=2"></script>
{% endblock %}
```
---
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
