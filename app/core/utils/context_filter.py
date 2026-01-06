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

