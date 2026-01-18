"""
애플리케이션 설정 모듈

모든 설정값을 중앙에서 관리합니다.
환경 변수를 통해 설정을 오버라이드할 수 있습니다.
"""

import os


class Config:
    """애플리케이션 기본 설정"""
    
    # === MongoDB 설정 (NVD 데이터베이스용) ===
    MONGO_HOST = os.environ.get('MONGO_HOST', '127.0.0.1')
    MONGO_PORT = int(os.environ.get('MONGO_PORT', 27017))
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'cvedb')
    
    # === Ollama (Llama AI) 설정 ===
    # Docker 컨테이너 내부에서 호스트의 Ollama에 접근하기 위해 host.docker.internal 사용
    OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://host.docker.internal:11434')
    OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.1:8b')  # 가장 안정적인 8B 모델 (팩트 기반 리포트)
    
    # === Nmap 설정 ===
    NMAP_ARGS = os.environ.get('NMAP_ARGS', '-sV -sT -Pn --script=http-headers,http-server-header')
    NMAP_TIMEOUT = int(os.environ.get('NMAP_TIMEOUT', 1800))  # 30분 (타임아웃 증가)
    
    # === ZAP 설정 ===
    ZAP_API_KEY = os.environ.get('ZAP_API_KEY', '12345')
    ZAP_PROXY_HOST = os.environ.get('ZAP_PROXY_HOST', '127.0.0.1')
    ZAP_PROXY_PORT = int(os.environ.get('ZAP_PROXY_PORT', 8080))
    ZAP_TIMEOUT = int(os.environ.get('ZAP_TIMEOUT', 1800))  # 30분 (타임아웃 증가)
    ZAP_DEFAULT_RISK_LEVELS = ['High', 'Medium', 'Low']
    
    # === Nuclei 설정 ===
    NUCLEI_TIMEOUT = int(os.environ.get('NUCLEI_TIMEOUT', 1800))  # 30분 (타임아웃 증가)
    NUCLEI_TEMPLATE_PATH = os.environ.get('NUCLEI_TEMPLATE_PATH', '/root/.config/nuclei/templates')
    
    # === Katana 설정 ===
    KATANA_TIMEOUT = int(os.environ.get('KATANA_TIMEOUT', 600))  # 10분 (타임아웃 증가)
    KATANA_MAX_DEPTH = int(os.environ.get('KATANA_MAX_DEPTH', 3))
    
    # === NVD API 설정 ===
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
    NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    NVD_RESULTS_PER_PAGE = 50
    NVD_REQUEST_TIMEOUT = 15
    
    # === CVE-Search 설정 (로컬 NVD 데이터베이스) ===
    CVE_SEARCH_HOST = os.environ.get('CVE_SEARCH_HOST', 'security-scanner-cve-search')
    CVE_SEARCH_PORT = int(os.environ.get('CVE_SEARCH_PORT', 5000))
    # CVE_SEARCH_URL은 환경 변수에서 직접 가져오거나, 호스트와 포트로 구성
    _cve_search_host = os.environ.get('CVE_SEARCH_HOST', 'security-scanner-cve-search')
    _cve_search_port = int(os.environ.get('CVE_SEARCH_PORT', 5000))
    CVE_SEARCH_URL = os.environ.get('CVE_SEARCH_URL', f'http://{_cve_search_host}:{_cve_search_port}')
    
    # === 스캔 결과 저장 경로 ===
    SCAN_RESULTS_DIR = os.environ.get('SCAN_RESULTS_DIR', os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'scan_results'
    ))
    
    # === Redis 설정 (실시간 업데이트용) ===
    REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_DB = int(os.environ.get('REDIS_DB', 0))
    
    # === 도커 설정 ===
    DOCKER_NETWORK = os.environ.get('DOCKER_NETWORK', 'security-scanner-net')
    
    # === CWE 메타데이터 설정 ===
    CWE_METADATA_PATH = os.environ.get('CWE_METADATA_PATH', os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'data', 'cwe_metadata.json'
    ))
    
    # === 기타 설정 ===
    MASK_REAL_IP = os.environ.get('MASK_REAL_IP', 'True').lower() == 'true'  # 데모용 IP 마스킹
    
    # === PoC 검증 설정 ===
    POC_VERIFICATION_ENABLED = os.environ.get('POC_VERIFICATION_ENABLED', 'false').lower() == 'true'  # 기본값: false
    POC_VERIFICATION_MIN_CONFIDENCE = os.environ.get('POC_VERIFICATION_MIN_CONFIDENCE', 'Medium')  # Low, Medium, High, Confirmed

