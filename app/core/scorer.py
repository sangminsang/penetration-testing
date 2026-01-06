# app/core/scorer.py
"""
보안 점수 계산 시스템
A~F 등급 및 위험도 평가
"""

from typing import Dict, List, Any, Tuple


def calculate_security_score(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    취약점 리스트를 기반으로 보안 점수 계산
    
    Args:
        vulnerabilities: CVE 취약점 리스트
        
    Returns:
        {
            'score': int (0-100),
            'grade': str (A~F),
            'risk_level': str (Safe/Low/Medium/High/Critical),
            'severity_counts': dict,
            'recommendations': list
        }
    """
    # 심각도별 카운트
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'NONE': 0
    }
    
    # 취약점 분류
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'NONE').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['NONE'] += 1
    
    # 점수 계산 (100점 만점)
    score = 100
    score -= severity_counts['CRITICAL'] * 20  # Critical: -20점
    score -= severity_counts['HIGH'] * 10      # High: -10점
    score -= severity_counts['MEDIUM'] * 3     # Medium: -3점
    score -= severity_counts['LOW'] * 1        # Low: -1점
    
    # 최소 0점
    score = max(0, score)
    
    # 등급 계산 (A~F)
    if score >= 90:
        grade = 'A'
        risk_level = 'Safe'
    elif score >= 80:
        grade = 'B'
        risk_level = 'Low Risk'
    elif score >= 70:
        grade = 'C'
        risk_level = 'Medium Risk'
    elif score >= 60:
        grade = 'D'
        risk_level = 'High Risk'
    elif score >= 50:
        grade = 'E'
        risk_level = 'Critical Risk'
    else:
        grade = 'F'
        risk_level = 'Severe Risk'
    
    # 권장사항 생성
    recommendations = []
    
    if severity_counts['CRITICAL'] > 0:
        recommendations.append(f"🚨 {severity_counts['CRITICAL']}개의 치명적 취약점을 즉시 패치하세요.")
    
    if severity_counts['HIGH'] > 0:
        recommendations.append(f"⚠️ {severity_counts['HIGH']}개의 높은 위험 취약점을 우선 처리하세요.")
    
    if severity_counts['MEDIUM'] > 3:
        recommendations.append(f"📋 {severity_counts['MEDIUM']}개의 중간 위험 취약점을 검토하세요.")
    
    if score < 70:
        recommendations.append("🔒 WAF(웹 방화벽) 설정을 강화하세요.")
        recommendations.append("🔍 정기적인 보안 스캔을 수행하세요.")
    
    if not recommendations:
        recommendations.append("✅ 현재 보안 상태가 양호합니다. 정기 점검을 유지하세요.")
    
    return {
        'score': score,
        'grade': grade,
        'risk_level': risk_level,
        'severity_counts': severity_counts,
        'recommendations': recommendations,
        'total_vulnerabilities': len(vulnerabilities)
    }


def get_grade_color(grade: str) -> str:
    """등급별 색상 코드 반환"""
    colors = {
        'A': '#28a745',  # Green
        'B': '#5cb85c',  # Light Green
        'C': '#ffc107',  # Yellow
        'D': '#fd7e14',  # Orange
        'E': '#dc3545',  # Red
        'F': '#721c24'   # Dark Red
    }
    return colors.get(grade, '#6c757d')


def get_risk_level_badge(risk_level: str) -> str:
    """위험도별 뱃지 클래스 반환"""
    badges = {
        'Safe': 'success',
        'Low Risk': 'info',
        'Medium Risk': 'warning',
        'High Risk': 'danger',
        'Critical Risk': 'danger',
        'Severe Risk': 'dark'
    }
    return badges.get(risk_level, 'secondary')


def calculate_epss_priority(cve_data: Dict[str, Any]) -> float:
    """
    EPSS(Exploit Prediction Scoring System) 기반 우선순위 계산
    
    Args:
        cve_data: CVE 정보 (cvss, epss 포함)
        
    Returns:
        priority_score: 0.0 ~ 10.0 (높을수록 위험)
    """
    cvss = cve_data.get('cvss', 0.0)
    epss = cve_data.get('epss', 0.0)  # 0.0 ~ 1.0
    
    # CVSS(이론적 위험) 70% + EPSS(실제 공격 확률) 30%
    priority = (cvss * 0.7) + (epss * 10 * 0.3)
    
    return round(priority, 2)


def categorize_by_priority(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    """
    취약점을 우선순위별로 분류
    
    Returns:
        {
            'immediate': [...],  # 즉시 처리 (CVSS>=7 and EPSS>=0.1)
            'high': [...],       # 높은 우선순위
            'medium': [...],     # 중간 우선순위
            'low': [...]         # 낮은 우선순위
        }
    """
    categorized = {
        'immediate': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    for vuln in vulnerabilities:
        cvss = vuln.get('cvss', 0.0)
        epss = vuln.get('epss', 0.0)
        
        # 우선순위 계산
        if cvss >= 7.0 and epss >= 0.1:
            categorized['immediate'].append(vuln)
        elif cvss >= 7.0 or epss >= 0.2:
            categorized['high'].append(vuln)
        elif cvss >= 4.0 or epss >= 0.05:
            categorized['medium'].append(vuln)
        else:
            categorized['low'].append(vuln)
    
    return categorized
