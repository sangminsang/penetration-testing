import os
import json
import logging
from app import create_app, db
from app.models import Project, ScanResult
from datetime import datetime

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def manual_import_results(project_id=None):
    """
    scan_results 폴더의 JSON 파일들을 읽어 DB에 저장합니다.
    project_id가 없으면 가장 최근 프로젝트를 자동으로 찾습니다.
    """
    app, _ = create_app()
    
    with app.app_context():
        # 1. 대상 프로젝트 찾기
        if project_id:
            project = Project.query.get(project_id)
        else:
            # 가장 최근에 생성된 프로젝트 사용 (테스트용)
            project = Project.query.order_by(Project.id.desc()).first()
            
        if not project:
            logger.error("❌ 프로젝트를 찾을 수 없습니다. 먼저 프로젝트를 생성해주세요.")
            return

        logger.info(f"[*] Import Target Project: ID={project.id}, URL={project.target}")

        # 2. 결과 파일 읽기
        result_dir = "./scan_results"
        if not os.path.exists(result_dir):
            logger.error(f"❌ {result_dir} 폴더가 없습니다.")
            return

        json_files = [f for f in os.listdir(result_dir) if f.endswith(".json")]
        if not json_files:
            logger.error("❌ 처리할 JSON 파일이 없습니다.")
            return

        logger.info(f"[*] Found {len(json_files)} result files.")

        # 3. 데이터 통합 (Aggregation)
        final_results = {
            'headers': {},
            'webtechnologies': [],
            'nuclei_vulns': [],
            'zap_results': {'alerts': []},
            'verifications': [],
            'nmap_results': [],
            'urls': []
        }
        
        # 중복 제거용 세트
        seen_vulns = set()
        seen_techs = set()
        
        count = 0
        for fname in json_files:
            try:
                with open(os.path.join(result_dir, fname), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # URL 수집 (파일명 등에서 추론하거나 데이터에서 추출)
                    # 여기서는 간단히 카운트만
                    count += 1
                    
                    # Nuclei 취약점 통합
                    if 'nuclei_vulns' in data:
                        for v in data['nuclei_vulns']:
                            # 중복 방지 키: URL + 템플릿ID
                            key = f"{v.get('url')}|{v.get('template_id')}"
                            if key not in seen_vulns:
                                final_results['nuclei_vulns'].append(v)
                                seen_vulns.add(key)
                    
                    # 기술 스택 통합
                    if 'webtechnologies' in data:
                        for t in data['webtechnologies']:
                            key = f"{t.get('name')}|{t.get('version')}"
                            if key not in seen_techs:
                                final_results['webtechnologies'].append(t)
                                seen_techs.add(key)
                                
                    # 헤더는 덮어쓰기 (가장 마지막 것 사용)
                    if 'headers' in data and data['headers']:
                        final_results['headers'].update(data['headers'])

            except Exception as e:
                logger.warning(f"⚠️ Failed to parse {fname}: {e}")

        logger.info(f"✅ Integrated: {len(final_results['nuclei_vulns'])} vulns, {len(final_results['webtechnologies'])} techs")

        # 4. DB 저장
        # 기존 결과가 있다면 업데이트하거나 새로 생성
        scan_result = ScanResult(
            project_id=project.id,
            timestamp=datetime.utcnow(),
            #status='completed',
            data=final_results
        )
        
        db.session.add(scan_result)
        db.session.commit()
        
        logger.info(f"🚀 Successfully saved to DB! (ScanResult ID: {scan_result.id})")
        print("\n[완료] 이제 대시보드 새로고침 하시면 결과가 보일 겁니다!")

if __name__ == "__main__":
    manual_import_results()
