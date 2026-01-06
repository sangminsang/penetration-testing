# test_scanner.py (최종 수정본)
import sys
import os
import json
import logging

# 현재 작업 디렉토리 추가
current_dir = os.getcwd()
sys.path.insert(0, current_dir)

logging.basicConfig(level=logging.INFO, format='%(message)s') # 로그 포맷 간소화

print(f"[*] Current Directory: {current_dir}")

# 모듈 Import 시도 (가능한 모든 경로 순회)
module_imported = False
try:
    # Case 1: app/core/recon/web.py (가장 유력)
    from app.core.recon.web import detect_with_http_headers, detect_javascript_libraries
    print("[*] Successfully imported from: app.core.recon.web")
    module_imported = True
except ImportError:
    try:
        # Case 2: app/core/scanner/web.py
        from app.core.scanner.web import detect_with_http_headers, detect_javascript_libraries
        print("[*] Successfully imported from: app.core.scanner.web")
        module_imported = True
    except ImportError:
        try:
            # Case 3: core/recon/web.py (app 패키지 내부에서 실행 시)
            from core.recon.web import detect_with_http_headers, detect_javascript_libraries
            print("[*] Successfully imported from: core.recon.web")
            module_imported = True
        except ImportError:
             pass

if not module_imported:
    print("\n[!] Import Error: Could not find 'web.py' module.")
    print("Please verify the file exists at one of these locations:")
    print(f" - {os.path.join(current_dir, 'app/core/recon/web.py')}")
    print(f" - {os.path.join(current_dir, 'app/core/scanner/web.py')}")
    sys.exit(1)

# 테스트 실행 함수
def test_target(url):
    print(f"\n{'='*50}")
    print(f" TARGET: {url}")
    print(f"{'='*50}\n")

    print("[1] JS Library Analysis (BeautifulSoup)...")
    try:
        js_libs = detect_javascript_libraries(url)
        print(json.dumps(js_libs, indent=2))
    except Exception as e:
        print(f"Error: {e}")

    print("\n[2] HTTP & Behavioral Analysis (MMH3/Error Pages)...")
    try:
        headers_tech = detect_with_http_headers(url)
        print(json.dumps(headers_tech, indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("\nEnter Target URL (default: http://testphp.vulnweb.com): ").strip()
    if not target:
        target = "http://testphp.vulnweb.com"
    
    if not target.startswith("http"):
        target = "http://" + target
        
    test_target(target)
