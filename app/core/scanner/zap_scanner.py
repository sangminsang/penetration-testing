"""
OWASP ZAP 자동 스캔 모듈
app/core/scanner/zap_scanner.py
"""

import time
import logging
from typing import Dict, List, Any, Optional
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)

class ZapScanner:
    """
    OWASP ZAP API를 사용한 자동 보안 스캔 클래스
    Spider(크롤링) → Active Scan(공격 스캔) → Alert 수집
    """
    
    def __init__(
        self,
        api_key: str = 'change-me-9203935709',
        proxy_host: str = '127.0.0.1',
        proxy_port: int = 8080,
        timeout: int = 300
    ):
        """
        ZAP 클라이언트 초기화
        
        Args:
            api_key: ZAP API Key (Tools > Options > API에서 생성)
            proxy_host: ZAP 프록시 호스트
            proxy_port: ZAP 프록시 포트
            timeout: 스캔 타임아웃 (초)
        """
        self.api_key = api_key
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout
        
        proxies = {
            'http': f'http://{proxy_host}:{proxy_port}',
            'https': f'http://{proxy_host}:{proxy_port}'
        }
        
        try:
            self.zap = ZAPv2(apikey=api_key, proxies=proxies)
            logger.info(f"ZAP Client initialized: {proxy_host}:{proxy_port}")
        except Exception as e:
            logger.error(f"Failed to initialize ZAP client: {e}")
            raise
    
    def access_target(self, target_url: str) -> bool:
        """
        타겟 URL에 접근하여 ZAP 사이트 트리에 등록
        
        Args:
            target_url: 스캔할 타겟 URL
            
        Returns:
            성공 여부
        """
        try:
            logger.info(f"Accessing target URL: {target_url}")
            self.zap.core.access_url(url=target_url, followredirects=True)
            time.sleep(2)  # 사이트 트리 업데이트 대기
            return True
        except Exception as e:
            logger.error(f"Failed to access target: {e}")
            return False
    
    def run_spider(self, target_url: str, max_children: Optional[int] = None) -> Dict[str, Any]:
        """
        Spider(크롤링) 실행
        
        Args:
            target_url: 크롤링할 URL
            max_children: 최대 크롤링 자식 노드 수 (None=무제한)
            
        Returns:
            {
                'scan_id': str,
                'status': 'completed' | 'failed',
                'urls_found': List[str],
                'progress': int
            }
        """
        try:
            logger.info(f"Starting Spider scan on: {target_url}")
            
            # Spider 스캔 시작
            scan_id = self.zap.spider.scan(
                url=target_url,
                maxchildren=max_children,
                recurse=True,
                contextname=None,
                subtreeonly=None
            )
            
            logger.info(f"Spider scan started. Scan ID: {scan_id}")
            
            # Spider 진행률 모니터링
            start_time = time.time()
            while True:
                try:
                    status = self.zap.spider.status(scan_id)
                    progress = int(status)
                    
                    if progress >= 100:
                        break
                    
                    if time.time() - start_time > self.timeout:
                        logger.warning(f"Spider scan timeout after {self.timeout}s")
                        self.zap.spider.stop(scan_id)
                        break
                    
                    logger.info(f"Spider progress: {progress}%")
                    time.sleep(2)
                    
                except (ValueError, TypeError) as e:
                    logger.error(f"Error reading spider status: {e}")
                    break
            
            # 크롤링된 URL 수집
            urls_found = self.zap.spider.results(scan_id)
            logger.info(f"Spider completed. URLs found: {len(urls_found)}")
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'urls_found': urls_found,
                'progress': 100
            }
            
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            return {
                'scan_id': None,
                'status': 'failed',
                'urls_found': [],
                'progress': 0,
                'error': str(e)
            }
    
    def run_active_scan(
        self,
        target_url: str,
        recurse: bool = True,
        scan_policy_name: Optional[str] = None,
        context_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Active Scan(공격 스캔) 실행
        
        Args:
            target_url: 스캔할 URL
            recurse: 재귀적으로 하위 노드 스캔 여부
            scan_policy_name: 스캔 정책 이름 (None=기본 정책)
            context_id: 컨텍스트 ID (인증 스캔 시 사용)
            
        Returns:
            {
                'scan_id': str,
                'status': 'completed' | 'failed',
                'progress': int
            }
        """
        try:
            logger.info(f"Starting Active Scan on: {target_url}")
            
            # Active Scan 시작
            scan_id = self.zap.ascan.scan(
                url=target_url,
                recurse=recurse,
                inscopeonly=None,
                scanpolicyname=scan_policy_name,
                method=None,
                postdata=True,
                contextid=context_id
            )
            
            logger.info(f"Active scan API returned scan_id: {scan_id}")
            
            # scan_id 유효성 검사 (즉시 체크)
            if not scan_id or scan_id == 'does_not_exist' or not str(scan_id).isdigit():
                error_msg = f"Invalid scan ID: {scan_id}. Target URL may not be in ZAP's site tree."
                logger.error(error_msg)
                return {
                    'scan_id': None,
                    'status': 'failed',
                    'progress': 0,
                    'error': error_msg
                }
            
            logger.info(f"Active scan started successfully. Scan ID: {scan_id}")
            
            # Active Scan 진행률 모니터링
            start_time = time.time()
            while True:
                try:
                    status = self.zap.ascan.status(scan_id)
                    progress = int(status)
                    
                    if progress >= 100:
                        break
                    
                    if time.time() - start_time > self.timeout:
                        logger.warning(f"Active scan timeout after {self.timeout}s")
                        self.zap.ascan.stop(scan_id)
                        break
                    
                    logger.info(f"Active Scan progress: {progress}%")
                    time.sleep(5)
                    
                except (ValueError, TypeError) as e:
                    logger.error(f"Error reading active scan status: {e}")
                    break
            
            logger.info("Active Scan completed")
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'progress': 100
            }
            
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            return {
                'scan_id': None,
                'status': 'failed',
                'progress': 0,
                'error': str(e)
            }


    def get_alerts(
        self,
        base_url: Optional[str] = None,
        risk_levels: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        스캔 결과 Alert(취약점) 수집
        
        Args:
            base_url: 필터링할 베이스 URL (None=전체)
            risk_levels: 필터링할 위험도 리스트
                        ['High', 'Medium', 'Low', 'Informational']
        
        Returns:
            [
                {
                    'alert': str,
                    'risk': str,
                    'url': str,
                    'evidence': str,
                    'description': str,
                    'solution': str,
                    'cwe_id': str,
                    'wasc_id': str,
                    'confidence': str
                },
                ...
            ]
        """
        try:
            # 기본 위험도: Medium 이상
            if risk_levels is None:
                risk_levels = ['High', 'Medium']
            
            logger.info(f"Fetching alerts for base_url={base_url}, risk_levels={risk_levels}")
            
            # 모든 Alert 가져오기
            all_alerts = self.zap.core.alerts(baseurl=base_url)
            
            # 위험도 필터링
            filtered_alerts = []
            for alert in all_alerts:
                if alert.get('risk') in risk_levels:
                    filtered_alerts.append({
                        'alert': alert.get('alert', ''),
                        'risk': alert.get('risk', ''),
                        'url': alert.get('url', ''),
                        'evidence': alert.get('evidence', ''),
                        'description': alert.get('description', ''),
                        'solution': alert.get('solution', ''),
                        'cwe_id': alert.get('cweid', ''),
                        'wasc_id': alert.get('wascid', ''),
                        'confidence': alert.get('confidence', ''),
                        'param': alert.get('param', ''),
                        'attack': alert.get('attack', ''),
                        'other_info': alert.get('other', '')
                    })
            
            logger.info(f"Total alerts: {len(all_alerts)}, Filtered (>=Medium): {len(filtered_alerts)}")
            return filtered_alerts
            
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []
    
    def full_scan(
        self,
        target_url: str,
        run_spider: bool = True,
        run_active: bool = True,
        risk_levels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        전체 스캔 워크플로우 실행 (Spider → Active Scan → Alert 수집)
        
        Args:
            target_url: 스캔할 타겟 URL
            run_spider: Spider 실행 여부
            run_active: Active Scan 실행 여부
            risk_levels: 필터링할 위험도 리스트
            
        Returns:
            {
                'target': str,
                'spider_result': Dict,
                'active_scan_result': Dict,
                'alerts': List[Dict],
                'summary': {
                    'total_alerts': int,
                    'high': int,
                    'medium': int,
                    'low': int
                }
            }
        """
        result = {
            'target': target_url,
            'spider_result': {},
            'active_scan_result': {},
            'alerts': [],
            'summary': {}
        }
        
        try:
            # Step 1: 타겟 접근
            if not self.access_target(target_url):
                raise Exception("Failed to access target URL")
            
            # Step 2: Spider 실행
            if run_spider:
                spider_result = self.run_spider(target_url)
                result['spider_result'] = spider_result
                
                if spider_result['status'] == 'failed':
                    logger.warning("Spider failed, continuing with Active Scan")
            
            # Step 3: Active Scan 실행
            if run_active:
                active_scan_result = self.run_active_scan(target_url)
                result['active_scan_result'] = active_scan_result
                
                if active_scan_result['status'] == 'failed':
                    logger.error("Active Scan failed")
                    # Active Scan 실패해도 계속 진행 (Passive Scan 결과라도 수집)
            
            # Step 4: Passive Scan 완료 대기
            logger.info("Waiting for Passive Scan to complete...")
            time.sleep(5)
            
            try:
                while int(self.zap.pscan.records_to_scan) > 0:
                    records_left = int(self.zap.pscan.records_to_scan)
                    logger.info(f"Passive scan records remaining: {records_left}")
                    time.sleep(2)
            except Exception as e:
                logger.warning(f"Error checking passive scan: {e}")
            
            logger.info("Passive Scan completed")
            
            # Step 5: Alert 수집
            alerts = self.get_alerts(base_url=target_url, risk_levels=risk_levels)
            result['alerts'] = alerts
            
            # Step 6: 요약 생성
            summary = {
                'total_alerts': len(alerts),
                'high': len([a for a in alerts if a['risk'] == 'High']),
                'medium': len([a for a in alerts if a['risk'] == 'Medium']),
                'low': len([a for a in alerts if a['risk'] == 'Low']),
                'informational': len([a for a in alerts if a['risk'] == 'Informational'])
            }
            
            result['summary'] = summary
            logger.info(f"Full scan completed. Summary: {summary}")
            return result
            
        except Exception as e:
            logger.error(f"Full scan failed: {e}")
            result['error'] = str(e)
            return result
    
    def shutdown_zap(self):
        """ZAP 프로세스 종료"""
        try:
            logger.info("Shutting down ZAP...")
            self.zap.core.shutdown()
        except Exception as e:
            logger.error(f"Failed to shutdown ZAP: {e}")


def format_alerts_for_dashboard(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    대시보드 표시용 Alert 데이터 포맷팅
    
    Args:
        alerts: ZapScanner.get_alerts() 반환값
        
    Returns:
        대시보드용 JSON 구조
    """
    return {
        'total': len(alerts),
        'by_risk': {
            'High': [a for a in alerts if a['risk'] == 'High'],
            'Medium': [a for a in alerts if a['risk'] == 'Medium'],
            'Low': [a for a in alerts if a['risk'] == 'Low']
        },
        'by_alert_type': {}  # 추가 분류 가능
    }
