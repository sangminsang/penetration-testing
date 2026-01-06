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

