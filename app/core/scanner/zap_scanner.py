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
        try:
            logger.info(f"Accessing target URL: {target_url}")
            self.zap.core.access_url(url=target_url, followredirects=True)
            time.sleep(2)
            return True
        except Exception as e:
            logger.error(f"Failed to access target: {e}")
            return False

    def run_spider(self, target_url: str, max_children: Optional[int] = None) -> Dict[str, Any]:
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
            timeout = 60
            
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

    def get_alerts(self, base_url: Optional[str] = None, risk_levels: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        try:
            if risk_levels is None:
                risk_levels = ['High', 'Medium']
            
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
        """
        results = {'scanned_urls': [], 'alerts': []}
        logger.info(f"Starting TARGETED ZAP SCAN on {len(target_urls)} URLs")
        
        for url in target_urls:
            try:
                self.access_target(url)
                scan_result = self.run_active_scan(url, recurse=False)
                results['scanned_urls'].append({'url': url, 'status': scan_result.get('status')})
            except Exception as e:
                logger.error(f"Failed targeted scan for {url}: {e}")
        
        results['alerts'] = self.get_alerts(risk_levels=['High', 'Medium', 'Low'])
        return results

    def full_scan(self, target_url: str, run_spider: bool = True, run_active: bool = True, risk_levels: List[str] = None) -> Dict[str, Any]:
        """전체 스캔 워크플로우"""
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
