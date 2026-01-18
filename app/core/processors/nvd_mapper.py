"""
NVD 매퍼 모듈

CPE를 기반으로 NVD(National Vulnerability Database)에서 CVE를 검색하고 매핑합니다.
"""

import logging
import requests
import time
from typing import Dict, List, Any, Optional
from pymongo import MongoClient
from app.config import Config

logger = logging.getLogger(__name__)


class NVDMapper:
    """
    NVD 매퍼 클래스
    
    CPE를 기반으로 NVD 데이터베이스에서 CVE를 검색합니다.
    MongoDB 또는 NVD API를 사용합니다.
    """
    
    def __init__(self):
        """NVD 매퍼 초기화"""
        # MongoDB 클라이언트 (NVD 데이터베이스)
        self.mongo_client = None
        self.mongo_db = None
        
        try:
            self.mongo_client = MongoClient(
                host=Config.MONGO_HOST,
                port=Config.MONGO_PORT,
                serverSelectionTimeoutMS=5000
            )
            self.mongo_db = self.mongo_client[Config.MONGO_DB_NAME]
            logger.info("MongoDB 연결 성공")
        except Exception as e:
            logger.warning(f"MongoDB 연결 실패: {e}. NVD API를 사용합니다.")
            self.mongo_client = None
    
    def map_cpes_to_cves(self, cpes: List[str], max_cpes: int = 50, timeout_per_cpe: int = 30) -> Dict[str, List[Dict[str, Any]]]:
        """
        CPE 목록을 CVE로 매핑 (무한루프 방지)
        
        Args:
            cpes: CPE 문자열 목록
            max_cpes: 최대 처리할 CPE 개수 (기본값: 50)
            timeout_per_cpe: CPE당 최대 처리 시간 (초, 기본값: 30초)
        
        Returns:
            CPE별 CVE 목록 딕셔너리
            {
                'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*': [
                    {
                        'cve_id': 'CVE-2021-41773',
                        'description': '...',
                        'cvss_score': 7.5,
                        ...
                    },
                    ...
                ],
                ...
            }
        """
        cpe_to_cves = {}
        start_time = time.time()
        
        # 최대 CPE 개수 제한
        cpes_to_process = cpes[:max_cpes]
        if len(cpes) > max_cpes:
            logger.warning(f"CPE 개수가 너무 많습니다 ({len(cpes)}개). 최대 {max_cpes}개만 처리합니다.")
        
        for idx, cpe in enumerate(cpes_to_process, 1):
            # 전체 타임아웃 체크
            elapsed = time.time() - start_time
            if elapsed > (timeout_per_cpe * max_cpes):
                logger.warning(f"CPE 매핑 전체 타임아웃 ({elapsed:.1f}초 초과). {idx-1}/{len(cpes_to_process)}개 처리 완료")
                break
            
            # 개별 CPE 타임아웃
            cpe_start_time = time.time()
            try:
                cves = self._search_cves_by_cpe(cpe)
                if cves:
                    cpe_to_cves[cpe] = cves
                    logger.info(f"CPE {idx}/{len(cpes_to_process)} {cpe}: {len(cves)}개 CVE 발견")
            except Exception as e:
                logger.error(f"CPE {cpe} 처리 실패: {e}")
                continue
            
            # 개별 CPE 처리 시간 체크
            cpe_elapsed = time.time() - cpe_start_time
            if cpe_elapsed > timeout_per_cpe:
                logger.warning(f"CPE {cpe} 처리 시간 초과 ({cpe_elapsed:.1f}초)")
        
        logger.info(f"CPE 매핑 완료: {len(cpe_to_cves)}/{len(cpes_to_process)}개 CPE 처리")
        return cpe_to_cves
    
    def _search_cves_by_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """
        CPE로 CVE 검색
        
        Args:
            cpe: CPE 문자열
        
        Returns:
            CVE 목록
        """
        # MongoDB 우선 사용
        if self.mongo_db:
            cves = self._search_mongodb(cpe)
            if cves:
                return cves
        
        # MongoDB 실패 시 NVD API 사용
        return self._search_nvd_api(cpe)
    
    def _search_mongodb(self, cpe: str) -> List[Dict[str, Any]]:
        """
        MongoDB에서 CVE 검색
        
        Args:
            cpe: CPE 문자열
        
        Returns:
            CVE 목록
        """
        try:
            # CPE를 정규화 (와일드카드 처리)
            # cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*
            # -> cpe:2.3:a:apache:http_server:*
            cpe_parts = cpe.split(':')
            if len(cpe_parts) >= 5:
                # vendor:product까지만 사용
                base_cpe = ':'.join(cpe_parts[:5]) + ':*'
            else:
                base_cpe = cpe
            
            # MongoDB 쿼리
            # cve-search 데이터베이스 구조에 맞게 조정 필요
            collection = self.mongo_db.get_collection('cves')
            
            # CPE가 포함된 CVE 검색
            query = {
                'vulnerable_configuration': {'$regex': base_cpe, '$options': 'i'}
            }
            
            results = collection.find(query).limit(100)  # 최대 100개
            
            cves = []
            for doc in results:
                cve = {
                    'cve_id': doc.get('id', ''),
                    'description': doc.get('summary', ''),
                    'cvss_score': doc.get('cvss', 0.0),
                    'published_date': doc.get('Published', ''),
                    'modified_date': doc.get('Modified', ''),
                    'references': doc.get('references', [])
                }
                cves.append(cve)
            
            return cves
        
        except Exception as e:
            logger.error(f"MongoDB 검색 실패: {e}")
            return []
    
    def _search_nvd_api(self, cpe: str) -> List[Dict[str, Any]]:
        """
        NVD API에서 CVE 검색
        
        Args:
            cpe: CPE 문자열
        
        Returns:
            CVE 목록
        """
        try:
            # NVD API v2.0 사용
            url = f"{Config.NVD_BASE_URL}?cpeName={cpe}"
            
            headers = {}
            if Config.NVD_API_KEY:
                headers['apiKey'] = Config.NVD_API_KEY
            
            response = requests.get(
                url,
                headers=headers,
                timeout=Config.NVD_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json()
            
            cves = []
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                
                # CVSS 점수 추출
                cvss_score = 0.0
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0.0)
                elif 'cvssMetricV2' in metrics:
                    cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0.0)
                
                cve = {
                    'cve_id': cve_data.get('id', ''),
                    'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                    'cvss_score': cvss_score,
                    'published_date': cve_data.get('published', ''),
                    'modified_date': cve_data.get('lastModified', ''),
                    'references': [ref.get('url', '') for ref in cve_data.get('references', [])]
                }
                cves.append(cve)
            
            # API 제한 고려 (초당 5개 요청)
            time.sleep(0.2)
            
            # 결과 개수 제한 (무한루프 방지)
            max_cves = 100
            if len(cves) > max_cves:
                logger.warning(f"CPE {cpe}에 대한 CVE가 너무 많습니다 ({len(cves)}개). 최대 {max_cves}개만 반환합니다.")
                cves = cves[:max_cves]
            
            return cves
        
        except Exception as e:
            logger.error(f"NVD API 검색 실패: {e}")
            return []
    
    def map_scan_results_to_cves(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        스캔 결과를 CVE로 매핑
        
        Args:
            scan_results: 통합된 스캔 결과
        
        Returns:
            CVE 매핑 결과가 추가된 스캔 결과
        """
        from app.core.processors.cpe_parser import CPEParser
        
        # CPE 추출
        cpes = CPEParser.extract_cpes_from_scan_results(scan_results)
        
        # CVE 매핑
        cpe_to_cves = self.map_cpes_to_cves(cpes)
        
        # 결과에 추가
        scan_results['cpe_mapping'] = {
            'cpes': cpes,
            'cpe_to_cves': cpe_to_cves,
            'total_cves': sum(len(cves) for cves in cpe_to_cves.values())
        }
        
        logger.info(f"CVE 매핑 완료: {len(cpes)}개 CPE, {scan_results['cpe_mapping']['total_cves']}개 CVE")
        
        return scan_results

