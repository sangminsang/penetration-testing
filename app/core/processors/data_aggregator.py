"""
데이터 집계 모듈

여러 스캔 결과를 통합하고 정제합니다.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from app.config import Config

logger = logging.getLogger(__name__)


class DataAggregator:
    """
    데이터 집계 클래스
    
    Nmap, Nuclei, ZAP 스캔 결과를 통합하고 정제합니다.
    """
    
    def __init__(self, scan_results_dir: str = None):
        """
        데이터 집계기 초기화
        
        Args:
            scan_results_dir: 스캔 결과 파일이 저장된 디렉토리
        """
        self.scan_results_dir = Path(scan_results_dir or Config.SCAN_RESULTS_DIR)
        self.scan_results_dir.mkdir(parents=True, exist_ok=True)
    
    def aggregate_scan_results(
        self,
        nmap_file: str = None,
        nuclei_file: str = None,
        zap_file: str = None
    ) -> Dict[str, Any]:
        """
        스캔 결과 파일들을 통합 (개선된 버전: 중복 제거, Source 추적, CPE 예외 처리)
        
        Args:
            nmap_file: Nmap 결과 파일 경로
            nuclei_file: Nuclei 결과 파일 경로
            zap_file: ZAP 결과 파일 경로
        
        Returns:
            통합된 스캔 결과 (Unified Schema)
            {
                'metadata': {...},
                'infrastructure': {...},
                'vulnerabilities': [...],  # 중복 제거됨, sources 필드 포함
                'summary': {...}
            }
        """
        import time
        from urllib.parse import urlparse
        
        # 통합 리포트 구조 초기화
        integrated_report = {
            'metadata': {
                'target_url': '',
                'target_host': '',
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'report_version': '2.0'
            },
            'infrastructure': {
                'ip_addresses': [],
                'open_ports': [],
                'services': []
            },
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'total_ports': 0,
                'total_services': 0,
                'sources': {
                    'nmap': False,
                    'nuclei': False,
                    'zap': False
                }
            }
        }
        
        # 1. Nmap 결과 파싱 (Infrastructure 정보)
        if nmap_file and Path(nmap_file).exists():
            try:
                logger.info(f"Nmap 결과 파싱 중: {nmap_file}")
                with open(nmap_file, 'r', encoding='utf-8') as f:
                    nmap_data = json.load(f)
                
                # 타겟 URL 추출
                target_url = nmap_data.get('target', '')
                if target_url:
                    integrated_report['metadata']['target_url'] = target_url
                    parsed = urlparse(target_url)
                    integrated_report['metadata']['target_host'] = parsed.hostname or parsed.netloc.split(':')[0]
                
                # Nmap JSON 구조에서 Infrastructure 정보 추출
                hosts = nmap_data.get('hosts', [])
                for host in hosts:
                    # IP 주소 추출
                    host_ip = host.get('ip', '')
                    if host_ip and host_ip not in integrated_report['infrastructure']['ip_addresses']:
                        integrated_report['infrastructure']['ip_addresses'].append(host_ip)
                    
                    # 포트 및 서비스 정보 추출
                    ports = host.get('ports', [])
                    for port_info in ports:
                        if port_info.get('state') == 'open':
                            port_data = {
                                'port': port_info.get('port'),
                                'protocol': port_info.get('protocol', 'tcp'),
                                'state': port_info.get('state', 'open'),
                                'service': port_info.get('service', '')
                            }
                            
                            if port_info.get('product'):
                                port_data['product'] = port_info.get('product')
                            if port_info.get('version'):
                                port_data['version'] = port_info.get('version')
                            
                            # CPE 정보 (있으면 추가, 없어도 에러 없이 진행)
                            cpe_list = port_info.get('cpe', [])
                            if cpe_list:
                                port_data['cpe'] = cpe_list if isinstance(cpe_list, list) else [cpe_list]
                            
                            integrated_report['infrastructure']['open_ports'].append(port_data)
                            
                            # 서비스 정보 추가
                            if port_data.get('service'):
                                service_info = {
                                    'name': port_data['service'],
                                    'port': port_data['port'],
                                    'protocol': port_data['protocol']
                                }
                                if port_data.get('product'):
                                    service_info['product'] = port_data['product']
                                if port_data.get('version'):
                                    service_info['version'] = port_data['version']
                                if port_data.get('cpe'):
                                    service_info['cpe'] = port_data['cpe']
                                
                                integrated_report['infrastructure']['services'].append(service_info)
                
                integrated_report['summary']['sources']['nmap'] = True
                integrated_report['summary']['total_ports'] = len(integrated_report['infrastructure']['open_ports'])
                integrated_report['summary']['total_services'] = len(integrated_report['infrastructure']['services'])
                logger.info(f"Nmap 파싱 완료: {len(integrated_report['infrastructure']['ip_addresses'])}개 IP, "
                          f"{len(integrated_report['infrastructure']['open_ports'])}개 포트")
                
            except Exception as e:
                logger.error(f"Nmap 결과 파싱 실패: {e}", exc_info=True)
        
        # 2. Nuclei 결과 파싱 (Vulnerabilities) - JSONL 형식 지원
        if nuclei_file and Path(nuclei_file).exists():
            try:
                logger.info(f"Nuclei 결과 파싱 중: {nuclei_file}")
                with open(nuclei_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                
                # JSONL 형식 파싱 (각 줄이 JSON 객체)
                nuclei_vulns = []
                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        vuln_data = json.loads(line)
                        nuclei_vulns.append(vuln_data)
                    except json.JSONDecodeError:
                        continue
                
                # 또는 표준 JSON 형식 (기존 형식 호환)
                if not nuclei_vulns:
                    with open(nuclei_file, 'r', encoding='utf-8') as f:
                        nuclei_data = json.load(f)
                        if isinstance(nuclei_data, dict) and 'vulnerabilities' in nuclei_data:
                            nuclei_vulns = nuclei_data.get('vulnerabilities', [])
                        elif isinstance(nuclei_data, list):
                            nuclei_vulns = nuclei_data
                
                for vuln in nuclei_vulns:
                    # Nuclei JSONL 구조 파싱
                    if isinstance(vuln, dict):
                        info = vuln.get('info', {})
                        # Nuclei 결과에서 CVE ID 추출 (강화: 여러 필드명 지원)
                        cve_list = []
                        
                        # 1단계: 이미 추출된 'cve' 필드가 있는지 확인 (nuclei_scanner.py에서 저장한 경우)
                        if 'cve' in vuln and vuln.get('cve'):
                            cve_list = vuln.get('cve', [])
                        # 2단계: 'cve' 필드가 없으면 원본 구조에서 추출 시도
                        elif isinstance(info, dict):
                            classification = info.get('classification', {})
                            # classification.cve-id, classification.cve 모두 지원
                            cve_list = classification.get('cve-id', []) or classification.get('cve', [])
                        else:
                            # info가 없는 경우 루트 레벨에서 직접 추출
                            cve_list = vuln.get('cve-id', []) or vuln.get('cve', []) or vuln.get('CVE-ID', [])
                        
                        # ✅ CVE 정규화 적용
                        cve_list = self._normalize_cve_list(cve_list)
                        
                        # CWE 추출 및 정규화
                        raw_cwe_list = []
                        if isinstance(info, dict):
                            raw_cwe_list = info.get('classification', {}).get('cwe-id', [])
                        else:
                            raw_cwe_list = vuln.get('cwe', [])
                        
                        # ✅ CWE 정규화 적용
                        cwe_list = self._normalize_cwe_list(raw_cwe_list)
                        
                        # severity 추출 (견고한 로직: info 등급도 포함, 기본값 'info' 사용)
                        severity = None
                        if isinstance(info, dict):
                            severity = info.get('severity', '')
                        if not severity:
                            severity = vuln.get('severity', '')
                        
                        # severity 정규화 (소문자 변환 및 매핑)
                        if severity:
                            severity = str(severity).lower()
                            # Nuclei severity 매핑 (info, low, medium, high, critical)
                            severity_map = {
                                'info': 'info',
                                'informational': 'info',
                                'low': 'low',
                                'medium': 'medium',
                                'high': 'high',
                                'critical': 'critical'
                            }
                            severity = severity_map.get(severity, severity)  # 매핑되지 않으면 원본 유지
                        else:
                            # severity가 없으면 기본값 'info' 사용 (원본 정보 손실 방지)
                            logger.debug(f"Nuclei 취약점 severity 없음, 기본값 'info' 사용: {vuln.get('template-id', 'unknown')}")
                            severity = 'info'
                        
                        # Confidence 추출 (Nuclei)
                        confidence = None
                        if isinstance(info, dict):
                            # Nuclei의 classification.confidence 또는 metadata.confidence 확인
                            classification = info.get('classification', {})
                            if isinstance(classification, dict):
                                confidence = classification.get('confidence', '') or classification.get('confidence-ratio', '')
                            # metadata에서도 확인
                            if not confidence:
                                metadata = info.get('metadata', {})
                                if isinstance(metadata, dict):
                                    confidence = metadata.get('confidence', '')
                        # 기본값 처리
                        if not confidence:
                            confidence = None
                        
                        # CWE 추출 및 정규화
                        raw_cwe_list = info.get('classification', {}).get('cwe-id', []) if isinstance(info, dict) else vuln.get('cwe', [])
                        cwe_list_normalized = self._normalize_cwe_list(raw_cwe_list)
                        
                        vulnerability = {
                            'name': info.get('name', '') if isinstance(info, dict) else vuln.get('name', ''),
                            'id': vuln.get('template-id', '') or vuln.get('id', ''),
                            'severity': severity,  # 정규화된 severity 사용
                            'url': vuln.get('matched-at', '') or vuln.get('url', ''),
                            'description': info.get('description', '') if isinstance(info, dict) else vuln.get('description', ''),
                            'source': 'nuclei',
                            'cve': cve_list,  # ✅ 정규화된 CVE ID
                            'cwe': cwe_list_normalized,  # ✅ 정규화된 CWE ID
                            'tags': info.get('tags', []) if isinstance(info, dict) else vuln.get('tags', []),
                            'confidence': confidence,  # Confidence 필드 추가
                            # AI 검증 결과 필드 (초기값 None)
                            'ai_analysis': None,
                            'poc_code': None,
                            'execution_result': None
                        }
                        integrated_report['vulnerabilities'].append(vulnerability)
                
                integrated_report['summary']['sources']['nuclei'] = True
                logger.info(f"Nuclei 파싱 완료: {len(nuclei_vulns)}개 취약점")
                
            except Exception as e:
                logger.error(f"Nuclei 결과 파싱 실패: {e}", exc_info=True)
        
        # 3. ZAP 결과 파싱 (Vulnerabilities)
        if zap_file and Path(zap_file).exists():
            try:
                logger.info(f"ZAP 결과 파싱 중: {zap_file}")
                with open(zap_file, 'r', encoding='utf-8') as f:
                    zap_data = json.load(f)
                
                # ZAP JSON 구조 파싱
                alerts = []
                if isinstance(zap_data, dict):
                    # 표준 ZAP JSON 형식
                    site_list = zap_data.get('site', [])
                    if site_list and isinstance(site_list, list) and len(site_list) > 0:
                        alerts = site_list[0].get('alerts', [])
                    elif 'alerts' in zap_data:
                        alerts = zap_data.get('alerts', [])
                elif isinstance(zap_data, list):
                    alerts = zap_data
                
                for alert in alerts:
                    if not isinstance(alert, dict):
                        continue
                    
                    # Confidence 추출 (ZAP)
                    # ZAP의 경우 confidence 또는 reliability 필드 사용
                    confidence = alert.get('confidence', '') or alert.get('reliability', '')
                    # ZAP confidence는 보통 숫자(0-4) 또는 문자열(False Positive, Low, Medium, High, Confirmed)
                    if confidence:
                        # 숫자로 변환 가능하면 변환
                        try:
                            conf_num = int(confidence)
                            # ZAP confidence 매핑: 0=False Positive, 1=Low, 2=Medium, 3=High, 4=Confirmed
                            conf_map = {0: 'False Positive', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Confirmed'}
                            confidence = conf_map.get(conf_num, str(confidence))
                        except (ValueError, TypeError):
                            # 이미 문자열이면 그대로 사용
                            pass
                    else:
                        confidence = None
                    
                    # CVE 추출 및 정규화
                    raw_cve_list = self._extract_cve_from_zap_alert(alert)
                    cve_list_normalized = self._normalize_cve_list(raw_cve_list)
                    
                    # CWE 추출 및 정규화
                    raw_cwe = alert.get('cweid', '') or alert.get('cwe', '')
                    cwe_list_normalized = self._normalize_cwe_list(raw_cwe)
                    
                    vulnerability = {
                        'name': alert.get('alert', '') or alert.get('name', ''),
                        'id': alert.get('pluginid', '') or alert.get('id', ''),
                        'url': alert.get('uri', '') or alert.get('url', ''),
                        'description': alert.get('desc', '') or alert.get('description', ''),
                        'solution': alert.get('solution', ''),
                        'source': 'zap',
                        'cwe': cwe_list_normalized,  # ✅ 정규화된 CWE ID
                        'wascid': alert.get('wascid', ''),
                        'cve': cve_list_normalized,  # ✅ 정규화된 CVE ID
                        # 🆕 evidence 필드 개선: instancerefs에서 추출
                        'evidence': self._extract_zap_evidence(alert),  # 개선된 evidence 추출
                        'confidence': confidence,  # Confidence 필드 추가
                        # 🆕 추가 필드들
                        'instancerefs': alert.get('instancerefs', []),
                        'instances': alert.get('instances', []),  # _get_alerts에서 처리된 instances
                        'extracted-results': self._extract_zap_extracted_results(alert),  # 🆕 중요!
                        'request': self._extract_zap_request(alert),  # 🆕 요청 정보
                        'response': self._extract_zap_response(alert),  # 🆕 응답 정보
                        'other': alert.get('other', ''),
                        'param': alert.get('param', ''),
                        'attack': alert.get('attack', ''),
                        # AI 검증 결과 필드 (초기값 None)
                        'ai_analysis': None,
                        'poc_code': None,
                        'execution_result': None
                    }
                    
                    # severity 코드 변환 (견고한 폴백 로직 개선)
                    # 1단계: 원본 risk 필드를 우선 확인 (ZAP는 risk 필드를 주로 사용)
                    severity = None
                    original_risk = alert.get('risk', '') or alert.get('riskdesc', '')
                    
                    if original_risk:
                        # 원본 risk 문자열을 소문자로 변환하여 매핑
                        risk_lower = str(original_risk).strip().lower()
                        # ZAP의 risk 문자열 매핑 (High, Medium, Low, Informational)
                        risk_string_map = {
                            'informational': 'info',
                            'information': 'info',
                            'info': 'info',
                            'low': 'low',
                            'medium': 'medium',
                            'high': 'high',
                            'critical': 'critical'
                        }
                        severity = risk_string_map.get(risk_lower)
                        
                        # 디버깅 로그
                        if severity:
                            logger.debug(f"✅ [ZAP] risk 매핑 성공: '{original_risk}' -> '{severity}'")
                        else:
                            logger.warning(f"⚠️ [ZAP] risk 문자열 매핑 실패: 원본='{original_risk}', 소문자='{risk_lower}'")
                    
                    # 2단계: riskcode 숫자 매핑 시도 (risk 필드가 없을 때만)
                    if not severity:
                        risk_map = {'0': 'info', '1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}
                        if isinstance(alert.get('riskcode'), (str, int)):
                            risk_code = str(alert.get('riskcode'))
                            severity = risk_map.get(risk_code)
                            if severity:
                                logger.debug(f"✅ [ZAP] riskcode로 매핑 성공: {risk_code} -> {severity}")
                    
                    # 3단계: 모든 매핑 실패 시 기본값 (원본 정보 보존을 위해 'info' 사용)
                    if not severity:
                        logger.warning(f"⚠️ [ZAP] severity 매핑 실패: riskcode={alert.get('riskcode')}, risk={alert.get('risk')}, 기본값 'info' 사용")
                        severity = 'info'
                    
                    # 디버깅: High/Critical severity 확인
                    if severity in ['high', 'critical']:
                        logger.info(f"🔴 [ZAP] High/Critical 발견: {alert.get('name', 'unknown')} -> severity={severity}")
                    
                    vulnerability['severity'] = severity
                    integrated_report['vulnerabilities'].append(vulnerability)
                
                integrated_report['summary']['sources']['zap'] = True
                logger.info(f"ZAP 파싱 완료: {len(alerts)}개 경고")
                
            except Exception as e:
                logger.error(f"ZAP 결과 파싱 실패: {e}", exc_info=True)
        
        # 4. 중복 제거 (CVE ID 또는 취약점 이름 기준)
        logger.info("중복 제거 중...")
        seen_vulns = {}
        deduplicated_vulns = []
        
        for vuln in integrated_report['vulnerabilities']:
            # ✅ 개선된 중복 제거 로직
            cve_list = vuln.get('cve', [])
            name = vuln.get('name', '').lower()
            url = vuln.get('url', '')
            
            # 1. CVE ID 기반 (우선순위 높음)
            if cve_list and len(cve_list) > 0:
                cve_id = cve_list[0] if isinstance(cve_list, list) else cve_list
                key = f"cve:{cve_id}"
            # 2. 이름 + URL 기반
            else:
                key = f"name_url:{name}:{url}"
            
            # ✅ 추가: 같은 이름+URL이면 CVE 통합
            if key not in seen_vulns:
                # sources 리스트로 변환
                if 'source' in vuln:
                    vuln['sources'] = [vuln['source']]
                seen_vulns[key] = vuln
                deduplicated_vulns.append(vuln)
            else:
                # 기존 취약점에 source 및 CVE 병합
                existing = seen_vulns[key]
                source = vuln.get('source', '')
                if source and source not in existing.get('sources', []):
                    if 'sources' not in existing:
                        existing['sources'] = [existing.get('source', '')]
                    existing['sources'].append(source)
                
                # ✅ CVE 병합 로직 (이름+URL 기반 매칭 시에도 CVE 통합)
                existing_cves = set(existing.get('cve', []))
                new_cves = set(vuln.get('cve', []))
                merged_cves = list(existing_cves | new_cves)
                
                if merged_cves:
                    existing['cve'] = sorted(merged_cves)  # 정렬하여 저장
                    logger.debug(f"CVE 병합: {existing.get('name')} - {merged_cves}")
        
        integrated_report['vulnerabilities'] = deduplicated_vulns
        integrated_report['summary']['total_vulnerabilities'] = len(deduplicated_vulns)
        
        logger.info(f"중복 제거 완료: {len(deduplicated_vulns)}개 고유 취약점")
        logger.info(f"스캔 결과 통합 완료: {integrated_report['summary']}")
        
        return integrated_report
    
    def refine_for_ai(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI 분석을 위해 데이터 정제 (새로운 Unified Schema 지원)
        
        Args:
            aggregated_data: 통합된 스캔 결과 (새로운 구조 또는 기존 구조 모두 지원)
        
        Returns:
            정제된 데이터 (AI 프롬프트에 적합한 형식)
            {
                'target_url': '...',
                'vulnerabilities': [
                    {
                        'name': '취약점 이름',
                        'url': '발견된 URL',
                        'severity': '위험도',
                        'evidence': '증거',
                        'sources': ['nuclei', 'zap']  # 여러 도구에서 발견된 경우
                    },
                    ...
                ],
                'technologies': [...],
                'ports': [...]
            }
        """
        # 새로운 Unified Schema인지 확인
        is_unified_schema = 'infrastructure' in aggregated_data and 'vulnerabilities' in aggregated_data
        
        if is_unified_schema:
            # 새로운 Unified Schema 사용
            refined = {
                'target_url': aggregated_data.get('metadata', {}).get('target_url', ''),
                'vulnerabilities': [],
                'technologies': [],
                'ports': []
            }
            
            # 취약점 정제 (이미 중복 제거되고 sources가 포함됨)
            for vuln in aggregated_data.get('vulnerabilities', []):
                # severity 추출 (기본값 제거 - 원본 데이터를 신뢰)
                severity = vuln.get('severity')
                
                # severity가 없거나 빈 값이면 경고 로그
                if not severity or (isinstance(severity, str) and severity.strip() == ''):
                    logger.warning(f"⚠️ [refine_for_ai] severity 없음: 취약점={vuln.get('name', 'unknown')}, URL={vuln.get('url', 'unknown')}")
                    # 기본값 사용하지 않고 None으로 설정
                    severity = None
                
                refined['vulnerabilities'].append({
                    'name': vuln.get('name', ''),
                    'url': vuln.get('url', ''),
                    'severity': severity,  # 기본값 'medium' 제거
                    'description': vuln.get('description', ''),
                    'sources': vuln.get('sources', [vuln.get('source', '')]),
                    'cve': vuln.get('cve', []),
                    'cwe': vuln.get('cwe', []),
                    'evidence': vuln.get('evidence', ''),
                    'solution': vuln.get('solution', ''),
                    'confidence': vuln.get('confidence')  # Confidence 필드 추가
                })
            
            # 포트 정보 정제
            for port in aggregated_data.get('infrastructure', {}).get('open_ports', []):
                refined['ports'].append({
                    'port': port.get('port', ''),
                    'service': port.get('service', ''),
                    'product': port.get('product', ''),
                    'version': port.get('version', '')
                })
        else:
            # 기존 구조 (하위 호환성)
            refined = {
                'target_url': aggregated_data.get('target_url', ''),
                'vulnerabilities': [],
                'technologies': [],
                'ports': []
            }
            
            # 취약점 정제 (Nuclei + ZAP)
            # Nuclei 취약점
            for vuln in aggregated_data.get('nuclei', {}).get('vulnerabilities', []):
                severity = vuln.get('severity')
                if not severity or (isinstance(severity, str) and severity.strip() == ''):
                    logger.warning(f"⚠️ [refine_for_ai] Nuclei severity 없음: {vuln.get('name', 'unknown')}")
                    severity = None
                
                refined['vulnerabilities'].append({
                    'name': vuln.get('name', ''),
                    'url': vuln.get('url', ''),
                    'severity': severity,  # 기본값 'medium' 제거
                    'evidence': vuln.get('matcher_name', ''),
                    'source': 'nuclei',
                    'cve': vuln.get('cve', []),
                    'cwe': vuln.get('cwe', [])
                })
            
            # ZAP 경고
            for alert in aggregated_data.get('zap', {}).get('alerts', []):
                # ZAP의 경우 risk 필드에서 직접 추출
                risk = alert.get('risk', '')
                if risk:
                    risk_lower = str(risk).strip().lower()
                    risk_string_map = {
                        'informational': 'info',
                        'information': 'info',
                        'info': 'info',
                        'low': 'low',
                        'medium': 'medium',
                        'high': 'high',
                        'critical': 'critical'
                    }
                    severity = risk_string_map.get(risk_lower)
                    if not severity:
                        logger.warning(f"⚠️ [refine_for_ai] ZAP risk 매핑 실패: {risk}")
                        severity = None
                else:
                    logger.warning(f"⚠️ [refine_for_ai] ZAP risk 없음: {alert.get('name', 'unknown')}")
                    severity = None
                
                refined['vulnerabilities'].append({
                    'name': alert.get('name', ''),
                    'url': alert.get('url', ''),
                    'severity': severity,  # 기본값 'medium' 제거
                    'evidence': alert.get('evidence', ''),
                    'source': 'zap',
                    'description': alert.get('description', ''),
                    'solution': alert.get('solution', '')
                })
            
            # 기술 스택 정제
            for tech in aggregated_data.get('nuclei', {}).get('technologies', []):
                refined['technologies'].append({
                    'name': tech.get('name', ''),
                    'matched_at': tech.get('matched_at', '')
                })
            
            # 포트 정보 정제
            for port in aggregated_data.get('nmap', {}).get('ports', []):
                refined['ports'].append({
                    'port': port.get('port', ''),
                    'service': port.get('service', ''),
                    'product': port.get('product', ''),
                    'version': port.get('version', '')
                })
        
        logger.info(f"데이터 정제 완료: {len(refined['vulnerabilities'])}개 취약점")
        
        return refined
    
    def _normalize_cve_list(self, cve_list: Any) -> List[str]:
        """
        CVE 리스트 정규화
        
        Args:
            cve_list: CVE 리스트 (문자열, 리스트, 또는 None)
        
        Returns:
            정규화된 CVE 리스트 (중복 제거, 대문자, 형식 검증)
        """
        import re
        
        # 1. 문자열 → 리스트 변환
        if isinstance(cve_list, str):
            cve_list = [cve_list] if cve_list else []
        elif not isinstance(cve_list, list):
            cve_list = []
        
        # 2. 정규화 및 검증
        normalized = []
        cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)
        
        for cve in cve_list:
            if cve and isinstance(cve, str):
                # 공백 제거 + 대문자 변환
                cve_upper = cve.strip().upper()
                
                # CVE- 형식 검증
                if cve_pattern.match(cve_upper):
                    normalized.append(cve_upper)
                else:
                    logger.warning(f"⚠️ 잘못된 CVE 형식: {cve} (무시됨)")
        
        # 3. 중복 제거 (순서 유지)
        seen = set()
        unique = []
        for cve in normalized:
            if cve not in seen:
                seen.add(cve)
                unique.append(cve)
        
        return unique
    
    def _normalize_cwe_list(self, cwe_list: Any) -> List[str]:
        """
        CWE 리스트 정규화
        
        Args:
            cwe_list: CWE 리스트 (문자열, 숫자, 리스트, 또는 None)
        
        Returns:
            정규화된 CWE 리스트 (중복 제거, 대문자, CWE- 접두사)
        """
        # 1. 다양한 타입 처리
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list] if cwe_list else []
        elif isinstance(cwe_list, (int, float)):
            cwe_list = [str(int(cwe_list))]
        elif not isinstance(cwe_list, list):
            cwe_list = []
        
        # 2. 정규화
        normalized = []
        for cwe in cwe_list:
            if cwe:
                cwe_str = str(cwe).strip().upper()
                
                # CWE- 접두사 추가 (없으면)
                if cwe_str.isdigit():
                    cwe_str = f"CWE-{cwe_str}"
                elif not cwe_str.startswith('CWE-'):
                    # "CWE79" → "CWE-79"
                    if cwe_str.startswith('CWE') and len(cwe_str) > 3 and cwe_str[3:].isdigit():
                        cwe_str = f"CWE-{cwe_str[3:]}"
                
                if cwe_str.startswith('CWE-'):
                    normalized.append(cwe_str)
        
        # 3. 중복 제거 (순서 유지)
        return list(dict.fromkeys(normalized))
    
    def _extract_cve_from_zap_alert(self, alert: Dict[str, Any]) -> List[str]:
        """
        ZAP alert에서 CVE ID를 추출 (정규화 전)
        
        Args:
            alert: ZAP alert 데이터
            
        Returns:
            CVE ID 리스트 (정규화 전, _normalize_cve_list에서 정규화됨)
        """
        import re
        
        cve_list = []
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # 1. reference 필드에서 CVE 추출
        reference = alert.get('reference', '')
        if reference:
            matches = re.findall(cve_pattern, reference, re.IGNORECASE)
            cve_list.extend(matches)
        
        # 2. other 필드에서도 CVE 추출 시도
        other_field = alert.get('other', '')
        if other_field:
            matches = re.findall(cve_pattern, other_field, re.IGNORECASE)
            cve_list.extend(matches)
        
        # 3. description 필드에서도 CVE 추출 시도
        description = alert.get('desc', '') or alert.get('description', '')
        if description:
            matches = re.findall(cve_pattern, description, re.IGNORECASE)
            cve_list.extend(matches)
        
        # 4. solution 필드에서도 CVE 추출 시도
        solution = alert.get('solution', '')
        if solution:
            matches = re.findall(cve_pattern, solution, re.IGNORECASE)
            cve_list.extend(matches)
        
        # 중복 제거 (정규화는 _normalize_cve_list에서)
        return list(set(cve_list))
    
    def _extract_zap_evidence(self, alert: Dict[str, Any]) -> str:
        """
        ZAP alert에서 evidence 추출 (instancerefs 포함)
        
        Args:
            alert: ZAP alert 딕셔너리
            
        Returns:
            추출된 evidence 문자열
        """
        # 기본 evidence
        evidence = alert.get('evidence', '')
        
        # instancerefs에서 evidence 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list):
            evidence_list = []
            for instance in instancerefs:
                if isinstance(instance, dict):
                    instance_evidence = instance.get('evidence', '')
                    if instance_evidence:
                        evidence_list.append(instance_evidence)
            if evidence_list:
                if evidence:
                    evidence = f"{evidence} | {' | '.join(evidence_list)}"
                else:
                    evidence = ' | '.join(evidence_list)
        
        # instances에서도 evidence 추출 (이미 처리된 경우)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list):
            evidence_list = []
            for instance in instances:
                if isinstance(instance, dict):
                    instance_evidence = instance.get('evidence', '')
                    if instance_evidence:
                        evidence_list.append(instance_evidence)
            if evidence_list:
                if evidence:
                    evidence = f"{evidence} | {' | '.join(evidence_list)}"
                else:
                    evidence = ' | '.join(evidence_list)
        
        return evidence
    
    def _extract_zap_extracted_results(self, alert: Dict[str, Any]) -> List[str]:
        """
        ZAP alert에서 extracted-results 추출
        
        Args:
            alert: ZAP alert 딕셔너리
            
        Returns:
            extracted-results 리스트
        """
        extracted_results = []
        
        # instancerefs에서 extracted-results 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list):
            for instance in instancerefs:
                if isinstance(instance, dict):
                    extracted = instance.get('extracted-results', '')
                    if extracted:
                        if isinstance(extracted, list):
                            extracted_results.extend(extracted)
                        else:
                            extracted_results.append(str(extracted))
        
        # instances에서도 extracted-results 추출 (이미 처리된 경우)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list):
            for instance in instances:
                if isinstance(instance, dict):
                    extracted = instance.get('extracted-results', '')
                    if extracted:
                        if isinstance(extracted, list):
                            extracted_results.extend(extracted)
                        else:
                            extracted_results.append(str(extracted))
        
        return extracted_results
    
    def _extract_zap_request(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        ZAP alert에서 request 정보 추출
        
        Args:
            alert: ZAP alert 딕셔너리
            
        Returns:
            request 정보 딕셔너리
        """
        # instancerefs에서 첫 번째 인스턴스의 request 정보 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list) and len(instancerefs) > 0:
            first_instance = instancerefs[0]
            if isinstance(first_instance, dict):
                return {
                    'method': first_instance.get('method', ''),
                    'uri': first_instance.get('uri', ''),
                    'parameter': first_instance.get('parameter', ''),
                    'attack': first_instance.get('attack', ''),
                    'header': first_instance.get('requestHeader', ''),
                    'body': first_instance.get('requestBody', '')
                }
        
        # instances에서도 추출 시도 (이미 처리된 경우)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list) and len(instances) > 0:
            first_instance = instances[0]
            if isinstance(first_instance, dict):
                return {
                    'method': first_instance.get('method', ''),
                    'uri': first_instance.get('uri', ''),
                    'parameter': first_instance.get('parameter', ''),
                    'attack': first_instance.get('attack', ''),
                    'header': first_instance.get('requestHeader', ''),
                    'body': first_instance.get('requestBody', '')
                }
        
        return {}
    
    def _extract_zap_response(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        ZAP alert에서 response 정보 추출
        
        Args:
            alert: ZAP alert 딕셔너리
            
        Returns:
            response 정보 딕셔너리
        """
        # instancerefs에서 첫 번째 인스턴스의 response 정보 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list) and len(instancerefs) > 0:
            first_instance = instancerefs[0]
            if isinstance(first_instance, dict):
                return {
                    'header': first_instance.get('responseHeader', ''),
                    'body': first_instance.get('responseBody', ''),
                    'evidence': first_instance.get('evidence', '')
                }
        
        # instances에서도 추출 시도 (이미 처리된 경우)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list) and len(instances) > 0:
            first_instance = instances[0]
            if isinstance(first_instance, dict):
                return {
                    'header': first_instance.get('responseHeader', ''),
                    'body': first_instance.get('responseBody', ''),
                    'evidence': first_instance.get('evidence', '')
                }
        
        return {}
    
    def _extract_zap_evidence(self, alert: Dict[str, Any]) -> str:
        """
        ZAP alert에서 evidence 추출 (instancerefs 포함)
        
        Args:
            alert: ZAP alert 딕셔너리
        
        Returns:
            추출된 evidence 문자열
        """
        # 기본 evidence
        evidence = alert.get('evidence', '')
        
        # instancerefs에서 evidence 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list):
            evidence_list = []
            for instance in instancerefs:
                instance_evidence = instance.get('evidence', '')
                if instance_evidence:
                    evidence_list.append(instance_evidence)
            if evidence_list:
                if evidence:
                    evidence = f"{evidence} | {' | '.join(evidence_list)}"
                else:
                    evidence = ' | '.join(evidence_list)
        
        # instances 필드에서도 추출 (zap_scanner에서 처리된 경우)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list):
            evidence_list = []
            for instance in instances:
                instance_evidence = instance.get('evidence', '')
                if instance_evidence:
                    evidence_list.append(instance_evidence)
            if evidence_list:
                if evidence:
                    evidence = f"{evidence} | {' | '.join(evidence_list)}"
                else:
                    evidence = ' | '.join(evidence_list)
        
        return evidence
    
    def _extract_zap_extracted_results(self, alert: Dict[str, Any]) -> List[str]:
        """
        ZAP alert에서 extracted-results 추출
        
        Args:
            alert: ZAP alert 딕셔너리
        
        Returns:
            extracted-results 리스트
        """
        extracted_results = []
        
        # instancerefs에서 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list):
            for instance in instancerefs:
                extracted = instance.get('extracted-results', '')
                if extracted:
                    if isinstance(extracted, list):
                        extracted_results.extend(extracted)
                    else:
                        extracted_results.append(str(extracted))
        
        # instances 필드에서도 추출 (zap_scanner에서 처리된 경우)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list):
            for instance in instances:
                extracted = instance.get('extracted-results', '')
                if extracted:
                    if isinstance(extracted, list):
                        extracted_results.extend(extracted)
                    else:
                        extracted_results.append(str(extracted))
        
        return extracted_results
    
    def _extract_zap_request(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        ZAP alert에서 request 정보 추출
        
        Args:
            alert: ZAP alert 딕셔너리
        
        Returns:
            request 정보 딕셔너리
        """
        # instances 필드에서 추출 (zap_scanner에서 처리된 경우, 우선)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list) and len(instances) > 0:
            first_instance = instances[0]
            return {
                'method': first_instance.get('method', ''),
                'uri': first_instance.get('uri', ''),
                'parameter': first_instance.get('parameter', ''),
                'attack': first_instance.get('attack', ''),
                'header': first_instance.get('requestHeader', ''),
                'body': first_instance.get('requestBody', '')
            }
        
        # instancerefs에서 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list) and len(instancerefs) > 0:
            first_instance = instancerefs[0]
            return {
                'method': first_instance.get('method', ''),
                'uri': first_instance.get('uri', ''),
                'parameter': first_instance.get('parameter', ''),
                'attack': first_instance.get('attack', ''),
                'header': first_instance.get('requestHeader', ''),
                'body': first_instance.get('requestBody', '')
            }
        
        return {}
    
    def _extract_zap_response(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        ZAP alert에서 response 정보 추출
        
        Args:
            alert: ZAP alert 딕셔너리
        
        Returns:
            response 정보 딕셔너리
        """
        # instances 필드에서 추출 (zap_scanner에서 처리된 경우, 우선)
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list) and len(instances) > 0:
            first_instance = instances[0]
            return {
                'header': first_instance.get('responseHeader', ''),
                'body': first_instance.get('responseBody', ''),
                'evidence': first_instance.get('evidence', '')
            }
        
        # instancerefs에서 추출
        instancerefs = alert.get('instancerefs', [])
        if instancerefs and isinstance(instancerefs, list) and len(instancerefs) > 0:
            first_instance = instancerefs[0]
            return {
                'header': first_instance.get('responseHeader', ''),
                'body': first_instance.get('responseBody', ''),
                'evidence': first_instance.get('evidence', '')
            }
        
        return {}

