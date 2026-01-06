# test_scanner_unified.py 수정본

import sys
import os
import json
import logging

# 1. 경로 설정 (현재 폴더 및 상위 폴더 추가)
current_dir = os.getcwd()
sys.path.insert(0, current_dir)

logging.basicConfig(level=logging.INFO, format='%(message)s')

# 2. TechUnifier Import 시도
try:
    # unifier.py가 app/core/recon/unifier.py에 있다고 가정
    try:
        from app.core.recon.unifier import TechUnifier
    except ImportError:
        # 경로가 안 맞으면 상대 경로 시도
        from core.recon.unifier import TechUnifier
        
    print("[*] Successfully imported TechUnifier")
except ImportError as e:
    print(f"[!] TechUnifier Import Error: {e}")
    sys.exit(1)

# 3. Web Scanner Import 시도 (아까 성공했던 경로 우선)
web_module = None
try:
    # Case 1: app.core.recon.web (아까 성공한 경로!)
    import app.core.recon.web as web_module
    print("[*] Successfully imported web module from app.core.recon.web")
except ImportError:
    try:
        # Case 2: app.core.recon.scanner.web
        import app.core.recon.scanner.web as web_module
        print("[*] Successfully imported web module from app.core.recon.scanner.web")
    except ImportError as e:
        print(f"[!] Web Module Import Error: {e}")
        sys.exit(1)

# 4. 함수 별칭 지정
# web.py에 scan_target_unified 함수를 추가했는지 여부에 따라 처리
if hasattr(web_module, 'scan_target_unified'):
    scan_target_unified = web_module.scan_target_unified
    USE_INTERNAL_UNIFIER = True
else:
    # 함수를 아직 추가 안 했으면 여기서 직접 Unifier를 쓰도록 설정
    detect_with_http_headers = web_module.detect_with_http_headers
    detect_javascript_libraries = web_module.detect_javascript_libraries
    USE_INTERNAL_UNIFIER = False
    print("[!] scan_target_unified function not found in web.py. Using manual integration.")


def test_unified_scan(url):
    print(f"\n{'='*60}")
    print(f" UNIFIED SCAN TARGET: {url}")
    print(f"{'='*60}\n")
    
    if USE_INTERNAL_UNIFIER:
        # web.py 안에 있는 통합 함수 사용
        results = scan_target_unified(url)
    else:
        # 여기서 직접 통합 로직 실행
        unifier = TechUnifier()
        
        print("[*] Running Header/Behavioral Analysis...")
        # detect_with_http_headers 실행
        h_techs = detect_with_http_headers(url)
        unifier.merge_list(h_techs)
        
        print("[*] Running JS Analysis...")
        # detect_javascript_libraries 실행
        js_techs = detect_javascript_libraries(url)
        # JS 결과 포맷 변환
        for lib in js_techs:
            unifier.add_tech(
                name=lib.get('library'),
                version=lib.get('version'),
                category='javascript_library',
                source=lib.get('source', 'script'),
                confidence=80
            )
            
        results = unifier.get_results(min_confidence=30)
    
    print(f"\n[+] Final Unified Results ({len(results)} found):")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    target = input("Enter Target URL (default: http://testphp.vulnweb.com): ").strip()
    if not target: target = "http://testphp.vulnweb.com"
    if not target.startswith("http"): target = "http://" + target
    test_unified_scan(target)
