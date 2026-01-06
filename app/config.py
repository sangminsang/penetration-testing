# app/config.py

class Config:
    # cve-search api
    CVE_SEARCH_BASE_URL = "https://localhost"

    # ollama
    OLLAMA_BASE_URL = "http://localhost:11434"
    OLLAMA_MODEL = "gemma3:4b"

    # nmap 등 옵션
    # 🆕 HTTP 헤더 감지 추가
    NMAP_ARGS = "-sV -sT -Pn --script=http-headers,http-server-header"

    # 데모 시 보안 관련 옵션(예: 실제 IP 마스킹)
    MASK_REAL_IP = True

    # NVD 관련 설정
    NVD_API_KEY = "fe4669a1-c66f-4058-bc9e-5440b5919e2f"
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RESULTS_PER_PAGE = 50
    REQUEST_TIMEOUT = 15

    # ZAP Docker 설정
    ZAP_API_KEY = '12345'
    ZAP_PROXY_HOST = '127.0.0.1'
    ZAP_PROXY_PORT = 8080
    ZAP_TIMEOUT = 600  # 10분
    ZAP_DEFAULT_RISK_LEVELS = ['High', 'Medium']
