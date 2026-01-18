"""
데이터베이스 모델 정의

프로젝트와 스캔 결과를 저장하는 데이터베이스 테이블을 정의합니다.
"""

from app import db
from datetime import datetime


class Project(db.Model):
    """
    프로젝트 모델
    
    각 보안 진단 프로젝트를 나타냅니다.
    하나의 프로젝트는 여러 개의 스캔 결과를 가질 수 있습니다.
    """
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # 프로젝트 이름
    target_url = db.Column(db.String(500), nullable=False)  # 타겟 URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 생성 시간
    
    # 관계: 하나의 프로젝트는 여러 스캔 결과를 가짐
    scan_results = db.relationship('ScanResult', backref='project', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Project {self.name}>'


class ScanResult(db.Model):
    """
    스캔 결과 모델
    
    각 스캔 작업의 결과를 저장합니다.
    JSON 형식으로 상세 결과를 저장합니다.
    """
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)  # 프로젝트 ID
    scan_type = db.Column(db.String(50), nullable=False)  # 스캔 타입: 'nmap', 'nuclei', 'zap', 'full'
    status = db.Column(db.String(20), default='pending')  # 상태: 'pending', 'running', 'completed', 'failed'
    data = db.Column(db.JSON)  # 스캔 결과 데이터 (JSON 형식)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # 스캔 시작 시간
    completed_at = db.Column(db.DateTime)  # 스캔 완료 시간
    
    def __repr__(self):
        return f'<ScanResult {self.id} - {self.scan_type}>'

