"""
보고서 생성기

스캔 결과, CVE 매핑, AI 분석 결과를 종합하여 최종 보안 진단 보고서를 생성합니다.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from app.config import Config

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    보고서 생성기 클래스
    
    모든 스캔 결과와 AI 분석을 종합하여 최종 보고서를 생성합니다.
    """
    
    def __init__(self, output_dir: str = None):
        """
        보고서 생성기 초기화
        
        Args:
            output_dir: 보고서 저장 디렉토리
        """
        self.output_dir = Path(output_dir or Config.SCAN_RESULTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_full_report(
        self,
        scan_results: Dict[str, Any],
        cve_mapping: Dict[str, Any],
        ai_scenario: Dict[str, Any],
        attack_results: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        전체 보고서 생성
        
        Args:
            scan_results: 통합된 스캔 결과
            cve_mapping: CVE 매핑 결과
            ai_scenario: AI가 생성한 공격 시나리오
            attack_results: 공격 실행 결과 (선택적)
        
        Returns:
            최종 보고서
            {
                'summary': {...},
                'vulnerabilities': [...],
                'recommendations': [...],
                'attack_scenario': {...},
                'execution_results': {...}
            }
        """
        logger.info("전체 보고서 생성 시작")
        
        report = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'target_url': scan_results.get('target_url', ''),
                'report_version': '1.0'
            },
            'executive_summary': self._generate_executive_summary(
                scan_results, cve_mapping
            ),
            'scan_results': {
                'nmap': scan_results.get('nmap', {}),
                'nuclei': scan_results.get('nuclei', {}),
                'zap': scan_results.get('zap', {})
            },
            'vulnerabilities': self._compile_vulnerabilities(
                scan_results, cve_mapping
            ),
            'cve_mapping': cve_mapping,
            'attack_scenario': ai_scenario,
            'recommendations': self._generate_recommendations(
                scan_results, cve_mapping, ai_scenario
            )
        }
        
        # 공격 실행 결과가 있으면 추가
        if attack_results:
            report['attack_execution'] = attack_results
        
        # 보고서 저장
        report_file = self._save_report(report)
        report['report_file'] = str(report_file)
        
        logger.info(f"전체 보고서 생성 완료: {report_file}")
        
        return report
    
    def _generate_executive_summary(
        self,
        scan_results: Dict[str, Any],
        cve_mapping: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        요약 정보 생성
        
        Args:
            scan_results: 스캔 결과
            cve_mapping: CVE 매핑 결과
        
        Returns:
            요약 정보
        """
        summary = scan_results.get('summary', {})
        
        # 위험도별 취약점 개수 계산
        vulnerabilities = scan_results.get('vulnerabilities', [])
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'target_url': scan_results.get('target_url', ''),
            'scan_date': datetime.utcnow().isoformat(),
            'hosts_discovered': summary.get('hosts', 0),
            'ports_open': summary.get('ports', 0),
            'vulnerabilities_found': summary.get('vulnerabilities', 0),
            'alerts_found': summary.get('alerts', 0),
            'cves_mapped': cve_mapping.get('total_cves', 0),
            'severity_breakdown': severity_counts,
            'overall_risk': self._calculate_overall_risk(severity_counts)
        }
    
    def _calculate_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """
        전체 위험도 계산
        
        Args:
            severity_counts: 위험도별 개수
        
        Returns:
            전체 위험도 ('Critical', 'High', 'Medium', 'Low')
        """
        if severity_counts.get('critical', 0) > 0:
            return 'Critical'
        elif severity_counts.get('high', 0) > 5:
            return 'High'
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) > 10:
            return 'Medium'
        else:
            return 'Low'
    
    def _compile_vulnerabilities(
        self,
        scan_results: Dict[str, Any],
        cve_mapping: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        취약점 정보 통합
        
        Args:
            scan_results: 스캔 결과
            cve_mapping: CVE 매핑 결과
        
        Returns:
            통합된 취약점 목록
        """
        vulnerabilities = []
        
        # 스캔 결과에서 취약점 수집
        for vuln in scan_results.get('vulnerabilities', []):
            vuln_info = {
                'name': vuln.get('name', ''),
                'url': vuln.get('url', ''),
                'severity': vuln.get('severity', 'medium'),
                'source': vuln.get('source', 'unknown'),
                'description': vuln.get('description', ''),
                'evidence': vuln.get('evidence', ''),
                'cve': vuln.get('cve', []),
                'cwe': vuln.get('cwe', []),
                'solution': vuln.get('solution', '')
            }
            vulnerabilities.append(vuln_info)
        
        # CVE 매핑 정보 추가
        cpe_to_cves = cve_mapping.get('cpe_to_cves', {})
        for cpe, cves in cpe_to_cves.items():
            for cve in cves:
                # 이미 추가된 CVE는 스킵
                if not any(v.get('cve_id') == cve.get('cve_id') for v in vulnerabilities):
                    vulnerabilities.append({
                        'name': cve.get('cve_id', ''),
                        'severity': self._cvss_to_severity(cve.get('cvss_score', 0.0)),
                        'source': 'nvd',
                        'description': cve.get('description', ''),
                        'cve': [cve.get('cve_id', '')],
                        'cvss_score': cve.get('cvss_score', 0.0),
                        'references': cve.get('references', [])
                    })
        
        return vulnerabilities
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """
        CVSS 점수를 위험도로 변환
        
        Args:
            cvss_score: CVSS 점수
        
        Returns:
            위험도 ('critical', 'high', 'medium', 'low')
        """
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(
        self,
        scan_results: Dict[str, Any],
        cve_mapping: Dict[str, Any],
        ai_scenario: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        권장 사항 생성
        
        Args:
            scan_results: 스캔 결과
            cve_mapping: CVE 매핑 결과
            ai_scenario: AI 시나리오
        
        Returns:
            권장 사항 목록
        """
        recommendations = []
        
        # 위험도가 높은 취약점에 대한 권장 사항
        critical_vulns = [
            v for v in scan_results.get('vulnerabilities', [])
            if v.get('severity', '').lower() == 'critical'
        ]
        
        if critical_vulns:
            recommendations.append({
                'priority': 'high',
                'title': 'Critical 취약점 즉시 조치 필요',
                'description': f'{len(critical_vulns)}개의 Critical 취약점이 발견되었습니다. 즉시 패치 및 조치가 필요합니다.',
                'actions': [
                    '발견된 Critical 취약점에 대한 패치 적용',
                    '영향받는 시스템의 접근 제한',
                    '추가 모니터링 강화'
                ]
            })
        
        # CVE 매핑 결과 기반 권장 사항
        total_cves = cve_mapping.get('total_cves', 0)
        if total_cves > 0:
            recommendations.append({
                'priority': 'medium',
                'title': 'CVE 기반 보안 업데이트',
                'description': f'{total_cves}개의 알려진 CVE가 발견되었습니다. 관련 소프트웨어 업데이트를 권장합니다.',
                'actions': [
                    '발견된 CVE에 대한 보안 패치 확인',
                    '영향받는 소프트웨어 버전 업데이트',
                    'CVE 데이터베이스 정기 모니터링'
                ]
            })
        
        # AI 시나리오 기반 권장 사항
        if ai_scenario.get('selected_chains'):
            recommendations.append({
                'priority': 'high',
                'title': '공격 체인 방어 강화',
                'description': 'AI 분석 결과, 여러 취약점이 연계되어 공격 체인을 형성할 수 있습니다.',
                'actions': [
                    '공격 체인의 각 단계에 대한 방어 조치',
                    '네트워크 세그멘테이션 강화',
                    '침입 탐지 시스템(IDS) 규칙 업데이트'
                ]
            })
        
        return recommendations
    
    def _save_report(self, report: Dict[str, Any]) -> Path:
        """
        보고서를 파일로 저장
        
        Args:
            report: 보고서 데이터
        
        Returns:
            저장된 파일 경로
        """
        target_url = report['metadata'].get('target_url', 'unknown')
        safe_url = target_url.replace('://', '_').replace('/', '_').replace('.', '_')
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        filename = f"report_{safe_url}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        return filepath

