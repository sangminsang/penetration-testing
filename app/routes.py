"""
Flask 라우트 정의

웹 페이지와 API 엔드포인트를 정의합니다.
"""

import json
import logging
import glob
import re
from pathlib import Path
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.models import Project, ScanResult
from app import db
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Blueprint 생성 (라우트를 그룹화)
bp = Blueprint("main", __name__)


@bp.route('/')
def index():
    """메인 페이지 - 프로젝트 목록으로 리다이렉트"""
    return redirect(url_for('main.projects'))


@bp.route('/projects')
def projects():
    """
    프로젝트 목록 페이지
    
    모든 프로젝트를 조회하여 목록 페이지를 표시합니다.
    """
    all_projects = Project.query.all()
    return render_template('projects.html', projects=all_projects)


@bp.route('/project/new', methods=['POST'])
def create_project():
    """
    새 프로젝트 생성
    
    사용자가 입력한 프로젝트 이름과 타겟 URL로 새 프로젝트를 생성합니다.
    """
    name = request.form.get('name')
    target = request.form.get('target')
    
    if name and target:
        project = Project(name=name, target_url=target)
        db.session.add(project)
        db.session.commit()
    
    return redirect(url_for('main.projects'))


@bp.route('/project/delete/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    """
    프로젝트 삭제
    
    프로젝트와 관련된 모든 스캔 결과를 함께 삭제합니다.
    """
    project = Project.query.get_or_404(project_id)
    
    # 관련 스캔 결과도 함께 삭제됨 (cascade 설정)
    db.session.delete(project)
    db.session.commit()
    
    return redirect(url_for('main.projects'))


def _get_scan_history_for_project(project):
    """
    프로젝트의 스캔 이력을 파일 시스템에서 조회
    
    Args:
        project: Project 객체
        
    Returns:
        List[Dict]: 타임스탬프 순으로 정렬된 스캔 이력 리스트
        [
            {
                'timestamp': '1768173854',
                'folder_name': 'testphp_vulnweb_com_1768173854',
                'folder_path': Path(...),
                'report_file': Path(...) or None,
                'ai_report_file': Path(...) or None,
                'display_name': '2024-01-15 14:30:54'
            },
            ...
        ]
    """
    from app.config import Config
    
    outputs_dir = Path(Config.SCAN_RESULTS_DIR) / "outputs"
    if not outputs_dir.exists():
        logger.warning(f"outputs 디렉토리가 존재하지 않음: {outputs_dir}")
        return []
    
    # 프로젝트 타겟 URL에서 호스트 추출
    target_url = project.target_url
    if not target_url:
        return []
    
    parsed = urlparse(target_url)
    target_host = parsed.hostname or parsed.netloc.split(':')[0]
    safe_target = target_host.replace('.', '_').replace(':', '_')
    
    logger.info(f"스캔 이력 검색: target_host={target_host}, safe_target={safe_target}")
    
    scan_history = []
    
    # outputs/ 폴더 내 모든 디렉토리 스캔
    for folder in outputs_dir.iterdir():
        if not folder.is_dir():
            continue
        
        folder_name = folder.name
        
        # 타겟 호스트와 매칭되는 폴더만 선택
        # 폴더명 형식: {host}_{timestamp} 또는 {host}_{timestamp}_{extra}
        if safe_target.lower() not in folder_name.lower():
            continue
        
        # 타임스탬프 추출 (폴더명 끝에 숫자 패턴)
        timestamp_match = re.search(r'(\d{10,})$', folder_name)
        if not timestamp_match:
            continue
        
        timestamp_str = timestamp_match.group(1)
        
        # 리포트 파일 확인
        report_file = folder / "final_integrated_report.json"
        ai_report_file = folder / "ai_report.md"
        
        # 파일이 존재하는 경우만 추가
        if report_file.exists() or ai_report_file.exists():
            # 타임스탬프를 datetime으로 변환
            try:
                timestamp_int = int(timestamp_str)
                dt = datetime.fromtimestamp(timestamp_int)
                display_name = dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, OSError):
                display_name = folder_name
            
            scan_history.append({
                'timestamp': timestamp_str,
                'folder_name': folder_name,
                'folder_path': folder,
                'report_file': report_file if report_file.exists() else None,
                'ai_report_file': ai_report_file if ai_report_file.exists() else None,
                'display_name': display_name,
                'datetime': dt if 'dt' in locals() else None
            })
    
    # 타임스탬프 순으로 정렬 (최신순)
    scan_history.sort(key=lambda x: int(x['timestamp']), reverse=True)
    
    logger.info(f"발견된 스캔 이력: {len(scan_history)}개")
    return scan_history


def _load_scan_data_from_folder(folder_path, timestamp=None):
    """
    특정 폴더에서 스캔 데이터 로드
    
    Args:
        folder_path: 스캔 결과 폴더 경로 (Path)
        timestamp: 타임스탬프 (선택적, None이면 최신)
        
    Returns:
        Dict: 스캔 데이터 또는 None
    """
    if not folder_path or not folder_path.exists():
        return None
    
    report_file = folder_path / "final_integrated_report.json"
    if not report_file.exists():
        logger.warning(f"리포트 파일이 존재하지 않음: {report_file}")
        return None
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
        
        # Katana URL 파일 로드
        endpoints = []
        katana_file_patterns = ['katana_urls_1.txt', 'katana_urls.txt']
        for pattern in katana_file_patterns:
            katana_file = folder_path / pattern
            if katana_file.exists():
                try:
                    with open(katana_file, 'r', encoding='utf-8') as kf:
                        lines = kf.readlines()
                        endpoints = [line.strip() for line in lines if line.strip()]
                    if endpoints:
                        logger.info(f"Katana URL 로드: {len(endpoints)}개")
                        break
                except Exception as e:
                    logger.warning(f"Katana URL 파일 읽기 실패: {e}")
        
        # 와일드카드 패턴 시도
        if not endpoints:
            for katana_file in folder_path.glob('katana_urls_*.txt'):
                try:
                    with open(katana_file, 'r', encoding='utf-8') as kf:
                        lines = kf.readlines()
                        endpoints = [line.strip() for line in lines if line.strip()]
                    if endpoints:
                        logger.info(f"Katana URL 로드 (glob): {len(endpoints)}개")
                        break
                except Exception as e:
                    logger.warning(f"Katana URL 파일 읽기 실패: {e}")
        
        if endpoints:
            scan_data['endpoints'] = endpoints
        
        return scan_data
    except json.JSONDecodeError as e:
        logger.error(f"JSON 파싱 실패: {e}")
        return None
    except Exception as e:
        logger.error(f"스캔 데이터 로드 실패: {e}", exc_info=True)
        return None


@bp.route('/dashboard/<int:project_id>')
def dashboard(project_id):
    """
    대시보드 페이지 (파일 시스템 기반)
    
    DB 상태를 무시하고 outputs/ 폴더에서 직접 스캔 결과를 로드합니다.
    """
    project = Project.query.get_or_404(project_id)
    
    logger.info(f"═══════════════════════════════════════════════════════════")
    logger.info(f"🔍 [대시보드 접근] project_id={project_id}, project_name={project.name}")
    logger.info(f"═══════════════════════════════════════════════════════════")
    
    # 파일 시스템에서 스캔 이력 조회
    scan_history = _get_scan_history_for_project(project)
    
    # 템플릿에 전달할 데이터 준비
    # scan_history를 템플릿에서 사용할 수 있도록 JSON 직렬화 가능한 형태로 변환
    scan_history_for_template = []
    for item in scan_history:
        scan_history_for_template.append({
            'timestamp': item['timestamp'],
            'folder_name': item['folder_name'],
            'display_name': item['display_name'],
            'has_report': item['report_file'] is not None,
            'has_ai_report': item['ai_report_file'] is not None
        })
    
    selected_timestamp = request.args.get('timestamp')  # URL 파라미터로 타임스탬프 선택 가능
    
    logger.info(f"📊 스캔 이력: {len(scan_history_for_template)}개 발견")
    logger.info(f"📝 scan_data는 API를 통해 로드됩니다 (템플릿 변수로 전달하지 않음)")
    
    return render_template(
        'dashboard.html',
        project=project,
        scan_history=scan_history_for_template,
        selected_timestamp=selected_timestamp
    )


@bp.route('/api/project/<int:project_id>/latest')
def get_latest_scan_data(project_id):
    """
    프로젝트의 최신 스캔 결과 반환 API
    
    로컬 폴더에서 가장 최신의 final_integrated_report.json을 찾아 JSON으로 반환합니다.
    
    Args:
        project_id: 프로젝트 ID
        
    Returns:
        JSON: 스캔 데이터 및 AI 리포트
        {
            'scan_data': {...},
            'ai_report_md': '...',
            'timestamp': '1768173854',
            'folder_name': 'testphp_vulnweb_com_1768173854'
        }
    """
    project = Project.query.get_or_404(project_id)
    
    # 스캔 이력 조회
    scan_history = _get_scan_history_for_project(project)
    
    if not scan_history:
        return jsonify({
            'scan_data': None,
            'ai_report_md': None
        }), 404
    
    # 최신 폴더 사용
    target_folder = scan_history[0]['folder_path']
    timestamp = scan_history[0]['timestamp']
    
    if not target_folder or not target_folder.exists():
        return jsonify({
            'scan_data': None,
            'ai_report_md': None
        }), 404
    
    # 스캔 데이터 로드
    scan_data = _load_scan_data_from_folder(target_folder)
    
    # scan_data가 None인 경우 빈 객체 반환
    if scan_data is None:
        scan_data = {}
    
    # AI 리포트 로드
    ai_report_md = None
    ai_report_file = target_folder / "ai_report.md"
    if ai_report_file.exists():
        try:
            with open(ai_report_file, 'r', encoding='utf-8') as f:
                ai_report_md = f.read()
        except Exception as e:
            logger.warning(f"AI 리포트 읽기 실패: {e}")
    
    # 반환 형식: { "scan_data": {...}, "ai_report_md": "..." }
    return jsonify({
        'scan_data': scan_data,
        'ai_report_md': ai_report_md
    })


@bp.route('/api/history/<int:project_id>/<timestamp>')
def get_scan_history(project_id, timestamp):
    """
    특정 타임스탬프의 스캔 결과 반환 API
    
    Args:
        project_id: 프로젝트 ID
        timestamp: 타임스탬프 문자열 (예: "1768173854")
        
    Returns:
        JSON: 스캔 데이터 및 AI 리포트
    """
    project = Project.query.get_or_404(project_id)
    
    # 스캔 이력 조회
    scan_history = _get_scan_history_for_project(project)
    
    # 해당 타임스탬프 찾기
    target_folder = None
    for history_item in scan_history:
        if history_item['timestamp'] == str(timestamp):
            target_folder = history_item['folder_path']
            break
    
    if not target_folder or not target_folder.exists():
        return jsonify({
            'scan_data': None,
            'ai_report_md': None
        }), 404
    
    # 스캔 데이터 로드
    scan_data = _load_scan_data_from_folder(target_folder, timestamp)
    
    # scan_data가 None인 경우 빈 객체 반환
    if scan_data is None:
        scan_data = {}
    
    # AI 리포트 로드
    ai_report_md = None
    ai_report_file = target_folder / "ai_report.md"
    if ai_report_file.exists():
        try:
            with open(ai_report_file, 'r', encoding='utf-8') as f:
                ai_report_md = f.read()
        except Exception as e:
            logger.warning(f"AI 리포트 읽기 실패: {e}")
    
    # 반환 형식: { "scan_data": {...}, "ai_report_md": "..." }
    return jsonify({
        'scan_data': scan_data,
        'ai_report_md': ai_report_md
    })


@bp.route('/api/cwe/metadata', methods=['GET'])
def get_cwe_metadata():
    """
    CWE 메타데이터 전체 반환 API
    
    Returns:
        JSON: 모든 CWE 메타데이터
    """
    from app.config import Config
    
    try:
        cwe_file = Path(Config.CWE_METADATA_PATH)
        if cwe_file.exists():
            with open(cwe_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                logger.info(f"✅ CWE 메타데이터 전체 반환: {len(metadata)}개")
                return jsonify(metadata), 200
        else:
            logger.warning(f"⚠️ CWE 메타데이터 파일 없음: {cwe_file}")
            return jsonify({'error': 'CWE metadata file not found'}), 404
    except Exception as e:
        logger.error(f"❌ CWE 메타데이터 로드 실패: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/cwe/metadata/<cwe_id>', methods=['GET'])
def get_cwe_metadata_by_id(cwe_id):
    """
    특정 CWE 메타데이터 반환 API
    
    Args:
        cwe_id: CWE ID (예: "CWE-416" 또는 "416")
        
    Returns:
        JSON: 특정 CWE 메타데이터
    """
    from app.config import Config
    
    try:
        cwe_file = Path(Config.CWE_METADATA_PATH)
        if cwe_file.exists():
            with open(cwe_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                # CWE-416 또는 416 형식 모두 지원
                cwe_key = cwe_id if cwe_id.startswith('CWE-') else f'CWE-{cwe_id}'
                if cwe_key in metadata:
                    return jsonify(metadata[cwe_key]), 200
                else:
                    logger.debug(f"⚠️ CWE {cwe_key} 메타데이터 없음")
                    return jsonify({'error': 'CWE not found'}), 404
        else:
            logger.warning(f"⚠️ CWE 메타데이터 파일 없음: {cwe_file}")
            return jsonify({'error': 'CWE metadata file not found'}), 404
    except Exception as e:
        logger.error(f"❌ CWE 메타데이터 로드 실패: {e}")
        return jsonify({'error': str(e)}), 500
