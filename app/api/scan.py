"""
스캔 API 엔드포인트

스캔 작업을 시작하고 관리하는 API를 제공합니다.
"""

from flask import Blueprint, request, jsonify
from app.models import Project, ScanResult
from app import db
from app.core.scanners.scan_orchestrator import ScanOrchestrator
from datetime import datetime
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)

# API Blueprint 생성
api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/scan/start', methods=['POST'])
def start_scan():
    """
    스캔 시작 API
    
    요청 본문:
    {
        "project_id": 1,
        "target_url": "https://example.com",
        "enable_poc_verification": true  # 선택사항, 기본값: true
    }
    
    응답:
    {
        "success": true,
        "scan_id": 123,
        "message": "스캔이 시작되었습니다"
    }
    """
    try:
        data = request.get_json()
        project_id = data.get('project_id')
        target_url = data.get('target_url')
        from app.config import Config
        enable_poc_verification = data.get('enable_poc_verification', Config.POC_VERIFICATION_ENABLED)  # ✅ Config 기본값 사용
        
        if not project_id or not target_url:
            return jsonify({
                'success': False,
                'error': 'project_id와 target_url이 필요합니다'
            }), 400
        
        # 프로젝트 확인
        project = Project.query.get(project_id)
        if not project:
            return jsonify({
                'success': False,
                'error': '프로젝트를 찾을 수 없습니다'
            }), 404
        
        # 스캔 결과 레코드 생성
        scan_result = ScanResult(
            project_id=project_id,
            scan_type='full',  # 전체 스캔
            status='running',
            timestamp=datetime.utcnow()
        )
        db.session.add(scan_result)
        db.session.commit()
        
        # 스캔 오케스트레이터를 통해 스캔 시작
        orchestrator = ScanOrchestrator()
        orchestrator.start_full_scan(target_url, scan_result.id, enable_poc_verification=enable_poc_verification)
        
        return jsonify({
            'success': True,
            'scan_id': scan_result.id,
            'message': '스캔이 시작되었습니다'
        })
        
    except Exception as e:
        logger.error(f"스캔 시작 실패: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/scan/<int:scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """
    스캔 상태 조회 API
    
    특정 스캔의 현재 상태를 반환합니다.
    """
    try:
        scan_result = ScanResult.query.get(scan_id)
        if not scan_result:
            return jsonify({
                'success': False,
                'error': '스캔을 찾을 수 없습니다'
            }), 404
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_result.status,
            'scan_type': scan_result.scan_type,
            'timestamp': scan_result.timestamp.isoformat() if scan_result.timestamp else None,
            'completed_at': scan_result.completed_at.isoformat() if scan_result.completed_at else None
        })
        
    except Exception as e:
        logger.error(f"스캔 상태 조회 실패: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/scan/<int:scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """
    스캔 결과 조회 API (메타데이터만 반환)
    
    완료된 스캔의 메타데이터를 반환합니다.
    실제 리포트는 /api/scan/<scan_id>/report 엔드포인트를 사용하세요.
    """
    try:
        scan_result = ScanResult.query.get(scan_id)
        if not scan_result:
            return jsonify({
                'success': False,
                'error': '스캔을 찾을 수 없습니다'
            }), 404
        
        if scan_result.status not in ['completed', 'partial_success']:
            return jsonify({
                'success': False,
                'error': '스캔이 아직 완료되지 않았습니다',
                'status': scan_result.status
            }), 400
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_result.status,
            'data': scan_result.data or {}
        })
        
    except Exception as e:
        logger.error(f"스캔 결과 조회 실패: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/scan/<int:scan_id>/report', methods=['GET'])
def get_integrated_report(scan_id):
    """
    통합 리포트 조회 API
    
    로컬에 저장된 통합 리포트(JSON) 파일을 읽어서 반환합니다.
    
    응답:
    {
        "success": true,
        "scan_id": 123,
        "report": { ... }  // final_integrated_report.json 내용
    }
    """
    try:
        scan_result = ScanResult.query.get(scan_id)
        if not scan_result:
            return jsonify({
                'success': False,
                'error': '스캔을 찾을 수 없습니다'
            }), 404
        
        # 스캔이 완료되지 않았거나 실패한 경우
        if scan_result.status not in ['completed', 'partial_success']:
            return jsonify({
                'success': False,
                'error': '스캔이 아직 완료되지 않았거나 실패했습니다',
                'status': scan_result.status
            }), 400
        
        # DB에서 통합 리포트 경로 가져오기
        scan_data = scan_result.data or {}
        integrated_report_path = scan_data.get('integrated_report_path')
        
        if not integrated_report_path:
            # 하위 호환성: scan_output_dir에서 직접 찾기
            scan_output_dir = scan_data.get('scan_output_dir')
            if scan_output_dir:
                integrated_report_path = str(Path(scan_output_dir) / "final_integrated_report.json")
            else:
                return jsonify({
                    'success': False,
                    'error': '통합 리포트 경로를 찾을 수 없습니다',
                    'hint': '스캔이 완료되지 않았거나 리포트가 생성되지 않았습니다'
                }), 404
        
        # 파일 경로 확인
        report_file = Path(integrated_report_path)
        if not report_file.exists():
            return jsonify({
                'success': False,
                'error': '통합 리포트 파일을 찾을 수 없습니다',
                'path': str(report_file),
                'hint': '파일이 삭제되었거나 경로가 잘못되었을 수 있습니다'
            }), 404
        
        # 파일 읽기
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            logger.info(f"통합 리포트 조회 성공: scan_id={scan_id}, path={report_file}")
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'status': scan_result.status,
                'report_path': str(report_file),
                'report': report_data
            })
            
        except json.JSONDecodeError as e:
            logger.error(f"통합 리포트 JSON 파싱 실패: {e}")
            return jsonify({
                'success': False,
                'error': '통합 리포트 파일이 유효한 JSON 형식이 아닙니다',
                'path': str(report_file)
            }), 500
        except Exception as e:
            logger.error(f"통합 리포트 파일 읽기 실패: {e}")
            return jsonify({
                'success': False,
                'error': f'통합 리포트 파일을 읽는 중 오류가 발생했습니다: {str(e)}',
                'path': str(report_file)
            }), 500
        
    except Exception as e:
        logger.error(f"통합 리포트 조회 실패: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/scan/<int:scan_id>/ai-report', methods=['GET'])
def get_ai_report(scan_id):
    """
    AI 분석 리포트 조회 API
    
    로컬에 저장된 AI 분석 리포트(마크다운) 파일을 읽어서 반환합니다.
    
    응답:
    {
        "success": true,
        "scan_id": 123,
        "report_path": "...",
        "report": "..."  // ai_report.md 내용 (마크다운 텍스트)
    }
    """
    try:
        scan_result = ScanResult.query.get(scan_id)
        if not scan_result:
            return jsonify({
                'success': False,
                'error': '스캔을 찾을 수 없습니다'
            }), 404
        
        # 스캔이 완료되지 않았거나 실패한 경우
        if scan_result.status not in ['completed', 'partial_success']:
            return jsonify({
                'success': False,
                'error': '스캔이 아직 완료되지 않았거나 실패했습니다',
                'status': scan_result.status
            }), 400
        
        # DB에서 AI 리포트 경로 가져오기
        scan_data = scan_result.data or {}
        ai_report_path = scan_data.get('ai_report_path')
        
        if not ai_report_path:
            # 하위 호환성: scan_output_dir에서 직접 찾기
            scan_output_dir = scan_data.get('scan_output_dir')
            if scan_output_dir:
                ai_report_path = str(Path(scan_output_dir) / "ai_report.md")
            else:
                return jsonify({
                    'success': False,
                    'error': 'AI 리포트 경로를 찾을 수 없습니다',
                    'hint': 'AI 분석이 실행되지 않았거나 Ollama 서버가 연결되지 않았을 수 있습니다'
                }), 404
        
        # 파일 경로 확인
        report_file = Path(ai_report_path)
        if not report_file.exists():
            return jsonify({
                'success': False,
                'error': 'AI 리포트 파일을 찾을 수 없습니다',
                'path': str(report_file),
                'hint': '파일이 삭제되었거나 경로가 잘못되었을 수 있습니다'
            }), 404
        
        # 파일 읽기 (마크다운 텍스트)
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report_content = f.read()
            
            logger.info(f"AI 리포트 조회 성공: scan_id={scan_id}, path={report_file}")
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'status': scan_result.status,
                'report_path': str(report_file),
                'report': report_content,
                'content_type': 'text/markdown'
            })
            
        except Exception as e:
            logger.error(f"AI 리포트 파일 읽기 실패: {e}")
            return jsonify({
                'success': False,
                'error': f'AI 리포트 파일을 읽는 중 오류가 발생했습니다: {str(e)}',
                'path': str(report_file)
            }), 500
        
    except Exception as e:
        logger.error(f"AI 리포트 조회 실패: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

