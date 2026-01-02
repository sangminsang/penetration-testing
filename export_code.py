import os

# 1. 딱 이 4가지 확장자만 가져오도록 설정
TARGET_EXTENSIONS = {'.py', '.js', '.html', '.css'}

# 2. 탐색조차 하지 않을 폴더들 (백업 폴더, 데이터 폴더 등 제외)
IGNORE_DIRS = {
    'code_collection', 'data',          # 용량 큰 폴더 제외
    '__pycache__', '.git', '.idea',     # 시스템/IDE 폴더 제외
    'venv', 'env', 'node_modules',      # 라이브러리 폴더 제외
    'build', 'dist'
}

def collect_code():
    # 현재 스크립트가 있는 위치(12.26 app)를 기준으로 잡음
    root_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(root_dir, 'clean_project_code.txt')
    
    print(f"탐색 시작: {root_dir}")
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write(f"# Project Code Extract\n")
        outfile.write(f"# Root: {root_dir}\n\n")
        
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # 제외할 폴더는 탐색 목록에서 즉시 삭제 (하위로 들어가지 않음)
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                
                # 1) 원하는 확장자이고, 2) 이 스크립트 파일 자신이 아니면 저장
                if ext in TARGET_EXTENSIONS and filename != os.path.basename(__file__):
                    full_path = os.path.join(dirpath, filename)
                    rel_path = os.path.relpath(full_path, root_dir) # 상대 경로로 표시
                    
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # 파일 구분 헤더 작성
                        outfile.write(f"\n{'='*50}\n")
                        outfile.write(f"File: {rel_path}\n")
                        outfile.write(f"{'='*50}\n")
                        outfile.write(content + "\n")
                        
                        print(f"[추가] {rel_path}")
                        
                    except Exception as e:
                        print(f"[에러] {filename} 읽기 실패: {e}")

    print(f"\n✅ 완료! '{output_file}' 파일에 모든 코드가 모였습니다.")

if __name__ == "__main__":
    collect_code()
