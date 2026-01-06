# app/core/scanner/zap_scanner.py

import time
import logging
from typing import Dict, List, Any, Optional
from zapv2 import ZAPv2
from app.config import Config

logger = logging.getLogger(__name__)

class ZapScanner:
    """
    OWASP ZAP API를 사용한 자동 보안 스캔 클래스
    Spider(크롤링) -> Active Scan(공격 스캔) -> Alert 수집
    
    [개선 사항] 2026-01-06
    - Katana/Nuclei 등 외부 도구에서 수집한 URL을 받아
      중복 크롤링 없이 즉시 Active Scan을 수행하는 최적화 모드 추가
    """
    
    def __init__(
        self,
        api_key: str = None,
        proxy_host: str = None,
        proxy_port: int = None,
        timeout: int = None
    ):
        """ZAP 클라이언트 초기화"""
        self.api_key = api_key or Config.ZAP_API_KEY
        self.proxy_host = proxy_host or Config.ZAP_PROXY_HOST
        self.proxy_port = proxy_port or Config.ZAP_PROXY_PORT
        self.timeout = timeout or Config.ZAP_TIMEOUT
        
        proxies = {
            'http': f'http://{self.proxy_host}:{self.proxy_port}',
            'https': f'http://{self.proxy_host}:{self.proxy_port}'
        }
        
        try:
            self.zap = ZAPv2(apikey=self.api_key, proxies=proxies)
            logger.info(f"ZAP Client initialized: {self.proxy_host}:{self.proxy_port}")
        except Exception as e:
            logger.error(f"Failed to initialize ZAP client: {e}")
            raise

    def access_target(self, target_url: str) -> bool:
        """
        ZAP이 해당 URL을 인지하도록 단순 접속 (ZAP Tree 등록용)
        """
        try:
            # logger.info(f"Accessing target URL: {target_url}")
            # followredirects=True로 설정하여 최종 목적지까지 도달하게 함
            self.zap.core.access_url(url=target_url, followredirects=True)
            # time.sleep(1) # 너무 빠른 요청 방지
            return True
        except Exception as e:
            logger.error(f"Failed to access target: {e}")
            return False

    def run_spider(self, target_url: str, max_children: Optional[int] = None) -> Dict[str, Any]:
        """
        [Legacy] ZAP 자체 스파이더 실행 (느릴 수 있음)
        """
        try:
            logger.info(f"Starting Spider scan on: {target_url}")
            if max_children is None:
                max_children = 100
            
            scan_id = self.zap.spider.scan(
                url=target_url,
                maxchildren=max_children,
                recurse=True
            )
            
            logger.info(f"Spider scan started. Scan ID: {scan_id}")
            
            start_time = time.time()
            timeout = 300  # 5분 제한
            
            while True:
                try:
                    status = self.zap.spider.status(scan_id)
                    progress = int(status)
                    if progress >= 100:
                        break
                    if time.time() - start_time > timeout:
                        self.zap.spider.stop(scan_id)
                        break
                    time.sleep(2)
                except (ValueError, TypeError):
                    break
            
            urls_found = self.zap.spider.results(scan_id)
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'urls_found': urls_found,
                'progress': 100
            }
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def run_active_scan(self, target_url: str, recurse: bool = True, scan_policy_name: str = None, context_id: str = None) -> Dict[str, Any]:
        """
        단일 URL에 대한 Active Scan 실행
        """
        try:
            logger.info(f"Starting Active Scan on: {target_url} (Recurse: {recurse})")
            scan_id = self.zap.ascan.scan(
                url=target_url,
                recurse=recurse,
                scanpolicyname=scan_policy_name,
                postdata=True,
                contextid=context_id
            )
            
            if not scan_id or scan_id == 'does_not_exist' or not str(scan_id).isdigit():
                return {'status': 'failed', 'error': f"Invalid scan ID: {scan_id}"}
            
            # 비동기 처리를 위해 대기하지 않고 ID만 리턴하는 것이 좋을 수 있으나,
            # 현재 구조상 대기 로직 유지 (타임아웃 적용)
            start_time = time.time()
            while True:
                try:
                    status = self.zap.ascan.status(scan_id)
                    progress = int(status)
                    if progress >= 100:
                        break
                    if time.time() - start_time > self.timeout:
                        self.zap.ascan.stop(scan_id)
                        break
                    time.sleep(5)
                except (ValueError, TypeError):
                    break
            
            return {'scan_id': scan_id, 'status': 'completed', 'progress': 100}
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def run_active_scan_on_list(self, target_urls: List[str]) -> Dict[str, Any]:
        """
        [최적화됨] URL 리스트를 받아 '크롤링 없이' 즉시 공격 수행
        Katana 등으로 찾은 URL들을 한꺼번에 ZAP에 던져서 병렬 스캔 효과를 냄
        """
        logger.info(f"Starting Optimized ZAP Scan on {len(target_urls)} URLs (No Spidering)")
        
        scanned_count = 0
        failed_count = 0
        
        # 1. Seeding: ZAP이 URL들을 인식하도록 한 번씩 찔러줌
        for url in target_urls:
            self.access_target(url)
            
        # 2. Active Scan: 리스트에 있는 URL들만 타격 (recurse=False)
        for url in target_urls:
            try:
                # recurse=False: 하위 경로 탐색 금지 (이미 Katana가 다 찾음)
                # inscopeonly=False: 스코프 무관하게 강제 스캔
                scan_id = self.zap.ascan.scan(
                    url=url, 
                    recurse=False, 
                    inscopeonly=False
                )
                logger.debug(f"Launched Active Scan for: {url} (ID: {scan_id})")
                scanned_count += 1
            except Exception as e:
                logger.error(f"Failed to launch scan for {url}: {e}")
                failed_count += 1

        # 3. 모든 스캔이 끝날 때까지 대기
        self.wait_for_scans_to_finish()
        
        return {
            "status": "completed",
            "scanned_count": scanned_count,
            "failed_count": failed_count
        }

    def wait_for_scans_to_finish(self):
        """현재 실행 중인 모든 Active Scan이 완료될 때까지 대기"""
        logger.info("Waiting for all ZAP active scans to complete...")
        while True:
            try:
                scans = self.zap.ascan.scans
                if not scans:
                    break
                
                running_scans = [s for s in scans if s.get('state') != 'FINISHED']
                if not running_scans:
                    break
                    
                # 진행 상황 로깅 (선택 사항)
                # logger.debug(f"Remaining scans: {len(running_scans)}")
                time.sleep(5)
            except Exception:
                break
        logger.info("All ZAP active scans completed.")

    def get_alerts(self, base_url: Optional[str] = None, risk_levels: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        try:
            if risk_levels is None:
                risk_levels = ['High', 'Medium']
            
            # baseurl이 있으면 해당 사이트만, 없으면 전체 알림 가져오기
            all_alerts = self.zap.core.alerts(baseurl=base_url)
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
                        'confidence': alert.get('confidence', '')
                    })
            return filtered_alerts
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []

    def targeted_scan(self, target_urls: List[str]) -> Dict[str, Any]:
        """
        Nuclei 등에서 발견된 특정 URL만 정밀 타격 (Funnel 전략)
        Legacy 호환성을 위해 유지하되, 내부적으로는 최적화 로직 사용 가능
        """
        return self.fast_scan_with_external_urls(target_urls)

    def full_scan(self, target_url: str, run_spider: bool = True, run_active: bool = True, risk_levels: List[str] = None) -> Dict[str, Any]:
        """
        [Legacy] 전체 스캔 워크플로우 (하위 호환성 유지)
        """
        try:
            if not self.access_target(target_url):
                raise Exception("Failed to access target URL")
                
            spider_res = {}
            if run_spider:
                spider_res = self.run_spider(target_url)
                
            active_res = {}
            if run_active:
                active_res = self.run_active_scan(target_url)
                
            alerts = self.get_alerts(base_url=target_url, risk_levels=risk_levels)
            
            return {
                'target': target_url,
                'spider_result': spider_res,
                'active_scan_result': active_res,
                'alerts': alerts
            }
        except Exception as e:
            return {'error': str(e)}
            
    def fast_scan_with_external_urls(self, url_list: List[str]) -> Dict[str, Any]:
        """
        [NEW] Katana/Crawler 결과 리스트를 받아 고속 스캔 수행
        """
        try:
            if not url_list:
                return {'error': 'No URLs provided'}

            # 1. 스파이더 생략하고 바로 Active Scan 리스트 처리
            scan_result = self.run_active_scan_on_list(url_list)
            
            # 2. 결과(Alerts) 수집
            # 주의: base_url을 지정하지 않으면 ZAP에 쌓인 모든 알림을 가져옴
            # 필요하다면 url_list[0]의 도메인을 base_url로 추출해서 필터링 가능
            alerts = self.get_alerts(risk_levels=['High', 'Medium', 'Low'])
            
            return {
                'scan_summary': scan_result,
                'alerts': alerts
            }
        except Exception as e:
            logger.error(f"Fast scan failed: {e}")
            return {'error': str(e)}

def format_alerts_for_dashboard(alerts):
    """ZAP 경고 데이터를 대시보드 표시 형식으로 변환"""
    formatted = []
    for alert in alerts:
        formatted.append({
            'name': alert.get('alert', 'Unknown'),
            'risk': alert.get('risk', 'Informational'),
            'url': alert.get('url', ''),
            'description': alert.get('description', ''),
            'solution': alert.get('solution', ''),
            'evidence': alert.get('evidence', '')
        })
    return formatted
