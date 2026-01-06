# app/core/utils/confidence.py
# 결과 신뢰도 스코어링 시스템

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def calculate_confidence_score(finding: Dict[str, Any]) -> int:
    """
    발견된 취약점의 신뢰도 계산 (0~100)
    
    가중치 기반 점수 계산으로 개선
    
    Args:
        finding: 발견된 취약점 정보
    
    Returns:
        신뢰도 점수 (0~100)
    """
    # 가중치 정의
    weights = {
        'exploit_verified': 35,
        'multiple_sources': 15,
        'nse_scripts': 12,
        'web_vuln_verified': 20,
        'high_version_accuracy': 8,
        'banner_grabbed': 10
    }
    
    score = 50  # 기본 점수
    
    # 가점 요소 (최대 50점)
    
    # 1. 실제 익스플로잇 검증 완료
    if finding.get("exploit_verified") or finding.get("exploitable"):
        score += weights['exploit_verified']
        logger.debug("익스플로잇 검증 완료: +35점")
    
    # 2. 여러 소스에서 확인
    sources = finding.get("sources", [])
    if isinstance(sources, list) and len(sources) > 1:
        score += weights['multiple_sources']
        logger.debug(f"여러 소스 확인 ({len(sources)}개): +15점")
    elif isinstance(sources, str):
        # 문자열이면 여러 키워드 확인
        source_keywords = ["nse_script", "exploit", "version_match", "banner"]
        found_keywords = sum(1 for keyword in source_keywords if keyword in sources.lower())
        if found_keywords > 1:
            score += weights['multiple_sources']
    
    # 3. NSE 스크립트로 확인
    if finding.get("nse_scripts") or "nse_script" in str(finding.get("sources", "")).lower():
        score += weights['nse_scripts']
        logger.debug("NSE 스크립트 확인: +12점")
    
    # 4. 실제 웹 취약점 테스트로 확인
    if finding.get("vulnerability_test") or finding.get("web_vuln_verified"):
        score += weights['web_vuln_verified']
        logger.debug("웹 취약점 테스트 확인: +20점")
    
    # 5. 버전 정확도
    if finding.get("version") and finding.get("version_accuracy", 0) > 0.8:
        score += weights['high_version_accuracy']
        logger.debug("높은 버전 정확도: +8점")
    
    # 6. 배너 그랩핑으로 확인
    if finding.get("banner") or finding.get("banner_grabbed"):
        score += weights['banner_grabbed']
        logger.debug("배너 그랩핑 확인: +10점")
    
    # 감점 요소 (최대 -40점)
    
    # 1. 단순 버전 매칭만
    detection_method = finding.get("detection_method", "")
    if detection_method == "version_match" and not finding.get("exploit_verified"):
        score -= 25  # 기존 -30에서 -25로 조정
        logger.debug("단순 버전 매칭만: -25점")
    
    # 2. 불확실한 정보
    if finding.get("uncertain") or finding.get("low_confidence"):
        score -= 15  # 기존 -20에서 -15로 조정
        logger.debug("불확실한 정보: -15점")
    
    # 3. 오래된 정보
    if finding.get("old_data") or finding.get("stale"):
        score -= 10
        logger.debug("오래된 정보: -10점")
    
    # 4. 추측 기반
    if finding.get("guessed") or finding.get("assumed"):
        score -= 12  # 기존 -15에서 -12로 조정
        logger.debug("추측 기반: -12점")
    
    # 점수 범위 제한 (0~100)
    score = max(0, min(100, score))
    
    return score


def get_confidence_level(score: int) -> str:
    """
    신뢰도 점수를 레벨로 변환
    
    Args:
        score: 신뢰도 점수 (0~100)
    
    Returns:
        신뢰도 레벨 ("VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW")
    """
    if score >= 80:
        return "VERY_HIGH"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "VERY_LOW"


def enhance_finding_with_confidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    발견된 취약점에 신뢰도 정보 추가
    
    Args:
        finding: 발견된 취약점 정보
    
    Returns:
        신뢰도 정보가 추가된 취약점 정보
    """
    score = calculate_confidence_score(finding)
    level = get_confidence_level(score)
    
    finding["confidence_score"] = score
    finding["confidence_level"] = level
    
    return finding


def filter_by_confidence(
    findings: List[Dict[str, Any]],
    min_score: int = 40
) -> List[Dict[str, Any]]:
    """
    신뢰도 점수로 필터링
    
    Args:
        findings: 발견된 취약점 리스트
        min_score: 최소 신뢰도 점수
    
    Returns:
        필터링된 취약점 리스트
    """
    filtered = []
    
    for finding in findings:
        # 신뢰도 점수 계산 (없으면 추가)
        if "confidence_score" not in finding:
            finding = enhance_finding_with_confidence(finding)
        
        if finding.get("confidence_score", 0) >= min_score:
            filtered.append(finding)
    
    return filtered


def sort_by_confidence(
    findings: List[Dict[str, Any]],
    reverse: bool = True
) -> List[Dict[str, Any]]:
    """
    신뢰도 점수로 정렬
    
    Args:
        findings: 발견된 취약점 리스트
        reverse: 내림차순 여부 (True면 높은 점수부터)
    
    Returns:
        정렬된 취약점 리스트
    """
    # 신뢰도 점수 계산 (없으면 추가)
    enhanced = [enhance_finding_with_confidence(f) for f in findings]
    
    # 정렬
    sorted_findings = sorted(
        enhanced,
        key=lambda x: x.get("confidence_score", 0),
        reverse=reverse
    )
    
    return sorted_findings

