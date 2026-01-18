import requests
import json
import time

# 우리가 설정한 고정 IP
CVE_SEARCH_URL = "http://172.18.0.6:5000"
TEST_CVE_ID = "CVE-2021-44228"  # Log4Shell (유명해서 데이터 무조건 있음)

def test_connection():
    print(f"📡 [TEST] Connecting to {CVE_SEARCH_URL} for {TEST_CVE_ID}...")
    
    try:
        # scan_orchestrator.py와 똑같은 방식으로 요청 (Proxies=None 중요!)
        url = f"{CVE_SEARCH_URL}/api/cve/{TEST_CVE_ID}"
        response = requests.get(
            url, 
            timeout=10, 
            proxies={"http": None, "https": None} # 우리가 적용한 핵심 설정
        )
        
        if response.status_code == 200:
            data = response.json()
            print("\n✅ [SUCCESS] 연결 성공! NVD 데이터 수신 완료:")
            print(f"   - CVE ID: {data.get('id')}")
            print(f"   - CVSS Score: {data.get('cvss')}")
            print(f"   - Summary: {data.get('summary')[:100]}...") # 내용 길어서 100자만
            return True
        else:
            print(f"\n❌ [FAIL] 서버 응답 오류 (Status: {response.status_code})")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"\n❌ [ERROR] 연결 실패: {str(e)}")
        return False

if __name__ == "__main__":
    test_connection()
