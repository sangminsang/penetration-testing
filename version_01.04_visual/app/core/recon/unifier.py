# app/core/recon/unifier.py
from typing import Dict, List, Any, Optional

class TechUnifier:
    """
    여러 스캔 소스에서 수집된 기술 정보를 통합하고 교차 검증하는 클래스
    (SocketIO 지원 추가)
    """
    def __init__(self, socketio=None):
        self.tech_stack: Dict[str, Dict[str, Any]] = {}
        self.socketio = socketio # 소켓 객체 저장

    def _emit(self, event: str, data: Dict[str, Any]):
        """소켓이 연결되어 있으면 이벤트 전송"""
        if self.socketio:
            try:
                self.socketio.emit(event, data)
            except Exception:
                pass

    def add_tech(self, name: str, version: str = "", category: str = "unknown", 
                 source: str = "unknown", confidence: int = 0):
        if not name or name.lower() == "unknown":
            return

        tech_key = name.lower()
        is_new = tech_key not in self.tech_stack
        
        # 1. 정보 업데이트/추가
        if is_new:
            self.tech_stack[tech_key] = {
                'name': name,
                'version': version,
                'category': category,
                'confidence': confidence,
                'sources': [source]
            }
        else:
            entry = self.tech_stack[tech_key]
            entry['confidence'] = min(100, entry['confidence'] + confidence)
            if source not in entry['sources']:
                entry['sources'].append(source)
            if (not entry['version'] or entry['version'] == "Unknown") and version:
                entry['version'] = version
            elif version and len(version) > len(entry['version']):
                entry['version'] = version

        # 2. [방송] 실시간 로그 전송
        # 예: "[+] Found Nginx (Confidence: 60) via Recog"
        log_msg = f"Detected {name} via {source}"
        if version: log_msg += f" (v{version})"
        
        self._emit('scan_log', {
            'message': log_msg,
            'level': 'success' if confidence > 80 else 'info',
            'confidence': self.tech_stack[tech_key]['confidence']
        })

        # 3. [방송] 기술 스택 업데이트 전송 (대시보드 게이지용)
        self._emit('tech_update', {
            'name': self.tech_stack[tech_key]['name'],
            'confidence': self.tech_stack[tech_key]['confidence'],
            'version': self.tech_stack[tech_key]['version'] or "Unknown",
            'category': self.tech_stack[tech_key]['category']
        })

    def get_results(self, min_confidence: int = 30) -> List[Dict[str, Any]]:
        results = []
        for tech in self.tech_stack.values():
            if tech['confidence'] >= min_confidence:
                results.append({
                    'name': tech['name'],
                    'version': tech['version'] or "Unknown",
                    'category': tech['category'],
                    'confidence': tech['confidence'],
                    'source': ", ".join(tech['sources']),
                    'type': 'unified'
                })
        return sorted(results, key=lambda x: x['confidence'], reverse=True)

    def merge_list(self, tech_list: List[Dict[str, Any]]):
        for item in tech_list:
            self.add_tech(
                name=item.get('name'),
                version=item.get('version', ''),
                category=item.get('category', 'unknown'),
                source=item.get('source', 'unknown'),
                confidence=item.get('confidence', 50)
            )
