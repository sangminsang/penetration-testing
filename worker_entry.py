import os
import sys
import json

# 현재 파일이 있는 디렉토리를 파이썬 경로에 추가 (ModuleNotFoundError 방지)
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from app.core.recon.web import collect_web_info
except ImportError as e:
    print(f"[WORKER] ❌ 임포트 에러 발생: {e}")
    print(f"[WORKER] 📂 현재 작업 디렉토리: {os.getcwd()}")
    print(f"[WORKER] 📂 파이썬 경로: {sys.path}")
    sys.exit(1)

def main():
    target_urls_str = os.getenv("TARGET_URLS", "")
    if not target_urls_str:
        print("[WORKER] ❌ 할당된 타겟이 없습니다. 종료합니다.")
        return

    targets = target_urls_str.split(",")
    print(f"[WORKER] 🚀 스캔 시작: {len(targets)}개의 타겟 할당됨")

    for url in targets:
        try:
            print(f"[WORKER] 🔍 현재 스캔 중: {url}")
            result = collect_web_info(url)
            
            output_path = f"/app/results/scan_{url.replace('://', '_').replace('/', '_')}.json"
            os.makedirs("/app/results", exist_ok=True)
            with open(output_path, "w", encoding='utf-8') as f:
                json.dump(result, f, indent=4, ensure_ascii=False)
                
        except Exception as e:
            print(f"[WORKER] ❌ {url} 스캔 중 오류 발생: {e}")

    print("[WORKER] ✅ 모든 할당된 작업을 마쳤습니다.")

if __name__ == "__main__":
    main()
