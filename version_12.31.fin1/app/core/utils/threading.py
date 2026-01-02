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

