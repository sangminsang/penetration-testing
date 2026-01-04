import os
import math

# 1. 딱 이 4가지 확장자만 가져오도록 설정
TARGET_EXTENSIONS = {'.py', '.js', '.html', '.css'}

# 마크다운 코드 블록용 언어 태그 매핑
EXT_TO_LANG = {
    '.py': 'python',
    '.js': 'javascript',
    '.html': 'html',
    '.css': 'css'
}

# 2. 탐색조차 하지 않을 폴더들 (백업 폴더, 데이터 폴더 등 제외)
IGNORE_DIRS = {
    'code_collection', 'data',          # 용량 큰 폴더 제외
    '__pycache__', '.git', '.idea',     # 시스템/IDE 폴더 제외
    'venv', 'env', 'node_modules',      # 라이브러리 폴더 제외
    'build', 'dist'
}

def collect_code():
    # 현재 스크립트가 있는 위치를 기준으로 잡음
    root_dir = os.path.dirname(os.path.abspath(__file__))
    output_base_name = 'clean_project_code'
    
    print(f"탐색 시작: {root_dir}")
    
    # 전체 파일 목록을 먼저 수집 (분할 저장을 위해)
    all_valid_files = []
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 제외할 폴더는 탐색 목록에서 즉시 삭제
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            
            # 1) 원하는 확장자이고, 2) 이 스크립트 파일 자신이 아니면 리스트에 추가
            if ext in TARGET_EXTENSIONS and filename != os.path.basename(__file__):
                full_path = os.path.join(dirpath, filename)
                all_valid_files.append(full_path)
    
    total_files = len(all_valid_files)
    if total_files == 0:
        print("추출할 파일이 없습니다.")
        return

    # 파일 목록 정렬 (순서 보장)
    all_valid_files.sort()

    # 5개의 파일로 나누기 위한 계산
    num_parts = 5
    chunk_size = math.ceil(total_files / num_parts)
    
    global_file_counter = 1  # 파일 번호 전역 카운터
    
    for i in range(num_parts):
        # 현재 파트(part)에 해당하는 파일 목록 슬라이싱
        start_idx = i * chunk_size
        end_idx = start_idx + chunk_size
        current_chunk = all_valid_files[start_idx:end_idx]
        
        # 만약 남은 파일이 없으면 중단
        if not current_chunk:
            break
            
        part_num = i + 1
        # 확장자를 .txt -> .md로 변경
        output_file = os.path.join(root_dir, f'{output_base_name}_{part_num}.md')
        
        with open(output_file, 'w', encoding='utf-8') as outfile:
            # 마크다운 헤더 작성
            outfile.write(f"# Project Code Extract (Part {part_num}/{num_parts})\n")
            outfile.write(f"- **Root:** `{root_dir}`\n")
            outfile.write(f"- **Files included:** {len(current_chunk)} (Total: {total_files})\n\n")
            outfile.write("---\n") # 구분선
            
            for full_path in current_chunk:
                filename = os.path.basename(full_path)
                ext = os.path.splitext(filename)[1].lower()
                lang_tag = EXT_TO_LANG.get(ext, '') # 확장자에 맞는 언어 태그 가져오기
                
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # 파일 구분 헤더 (마크다운 형식 적용)
                    outfile.write(f"\n## File {global_file_counter}: {filename}\n")
                    outfile.write(f"**Absolute Path:** `{full_path}`\n\n")
                    
                    # 코드 블록 시작 (```python 등)
                    outfile.write(f"```{lang_tag}\n")
                    outfile.write(content)
                    # 코드 내용이 줄바꿈 없이 끝나는 경우를 대비해 개행 추가
                    if not content.endswith('\n'):
                        outfile.write('\n')
                    outfile.write("```\n") # 코드 블록 종료
                    outfile.write("---\n") # 파일 간 구분선
                    
                    print(f"[{part_num}번 md 생성 중] File {global_file_counter}: {filename}")
                    global_file_counter += 1
                    
                except Exception as e:
                    print(f"[에러] {filename} 읽기 실패: {e}")

    print(f"\n✅ 완료! 총 {num_parts}개의 마크다운(.md) 파일에 코드가 분할 저장되었습니다.")

if __name__ == "__main__":
    collect_code()