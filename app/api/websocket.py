from flask_socketio import emit
from flask import request
from app.models import ScanResult, Project
from app import db, create_app
import traceback
import requests
import re
import time
from app.services.intelligence import IntelligenceEngine

class ScanProgressEmitter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit_log(self, msg, stage='info', progress=0):
        self.socketio.emit('scan_progress', {'stage': stage, 'progress': progress, 'current_item': msg})

    def emit_tech(self, name, version=None, source="Recon", evidence="", confidence="High"):
        """
        기술 탐지 정보 전송 (Evidence 필드 포함)
        """
        self.socketio.emit('technology_detected', {
            'name': name, 
            'version': version or 'N/A', 
            'source': source,
            'evidence': evidence,
            'confidence': confidence
        })

    def emit_url(self, url, status_code=None):
        self.socketio.emit('url_discovered', {'url': url, 'status_code': status_code})

def register_socketio_handlers(socketio, scan_emitter):
    @socketio.on('start_scan')
    def handle_start_scan(data):
        target = data.get('target')
        project = Project.query.filter_by(target=target).first()
        socketio.start_background_task(run_integrated_scan, target, project.id if project else None, scan_emitter)

def run_integrated_scan(target, project_id, emitter):
    scan_data = {'technologies': [], 'urls': []}
    
    # 인텔리전스 엔진 초기화
    intelligence_engine = IntelligenceEngine()
    
    try:
        emitter.emit_log(f"🕵️ 통합 정찰 분석 개시: {target}", 'init', 5)
        
        # 1. L4 레이어: Nmap 기본 정찰
        from app.nmap_recon import run_recon
        clean_host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        emitter.emit_log("📡 [L4] 포트 스캔 및 서비스 배너 수집 중...", 'recon', 15)
        
        nmap_res = run_recon(clean_host)
        if nmap_res:
            for host in nmap_res:
                for port in host.get('ports', []):
                    if port.get('product'):
                        name = port['product']
                        version = port.get('version', '')
                        # 인텔리전스 엔진에 Nmap 결과 추가
                        intelligence_engine.add_finding(
                            tech_name=name,
                            version=version,
                            category="Service",
                            source_tool="Nmap",
                            evidence=f"Port {port['port']}/{port['protocol']} open banner"
                        )

        # 2. 강력한 통합 엔진(collect_web_info) 호출
        from app.core.recon.web import collect_web_info
        emitter.emit_log("🚀 [Deep Recon] 16개 기술 탐지 엔진 가동 중...", 'recon', 40)
        
        # 웹 스캔 수행
        web_info = collect_web_info(target)
        
        # 3. 데이터 정제 및 검증 (Intelligence Engine)
        emitter.emit_log("🧠 [AI Analysis] 수집된 데이터 교차 검증 및 정제 중...", 'analysis', 70)
        
        # web_info 통째로 엔진에 넘겨서 정제 (중복 제거, 버전 통합)
        refined_techs = intelligence_engine.refine_data(web_info, target)
        
        # 정제된 결과 전송 및 저장
        for tech in refined_techs:
            # 리스트로 된 근거(Evidence)를 보기 좋게 문자열로 결합
            evidence_str = " | ".join(tech['evidence'])
            source_str = ", ".join(tech['sources'])
            
            # 실시간 전송
            emitter.emit_tech(
                name=tech['name'], 
                version=tech['version'], 
                source=source_str, 
                evidence=evidence_str,
                confidence=tech['confidence']
            )
            
            # DB 저장용 데이터 구성
            scan_data['technologies'].append({
                'name': tech['name'],
                'version': tech['version'],
                'source': source_str,
                'evidence': evidence_str,
                'confidence': tech['confidence']
            })

        # 4. 크롤링 및 구조 분석
        from app.core.recon.crawler import WebCrawler
        emitter.emit_log("🕸️ [Structure] 사이트 내부 경로 수집 중...", 'crawling', 85)
        crawler = WebCrawler(target, max_depth=1)
        crawl_res = crawler.crawl()
        for u in crawl_res.get('urls', []):
            url_str = u['url'] if isinstance(u, dict) else u
            scan_data['urls'].append(url_str)
            emitter.emit_url(url_str, 200)

        # 5. 결과 저장
        if project_id:
            app, _ = create_app()
            with app.app_context():
                db.session.add(ScanResult(project_id=project_id, data=scan_data))
                db.session.commit()

        emitter.emit_log(f"✅ 분석 완료: 총 {len(refined_techs)}개 기술 스택 식별됨", 'completed', 100)
        emitter.socketio.emit('scan_completed', {})

    except Exception as e:
        traceback.print_exc()
        emitter.emit_log(f"❌ 오류 발생: {str(e)}", 'error')
