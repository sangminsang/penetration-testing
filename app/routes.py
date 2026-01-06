from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.models import Project, ScanResult
from app import db
import re

bp = Blueprint("main", __name__)

@bp.route('/')
def index():
    return redirect(url_for('main.projects'))

@bp.route('/projects')
def projects():
    all_projects = Project.query.all()
    return render_template('projects.html', projects=all_projects)

@bp.route('/project/new', methods=['POST'])
def create_project():
    name, target = request.form.get('name'), request.form.get('target')
    if name and target:
        db.session.add(Project(name=name, target=target))
        db.session.commit()
    return redirect(url_for('main.projects'))

@bp.route('/project/delete/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    ScanResult.query.filter_by(project_id=project_id).delete()
    db.session.delete(project)
    db.session.commit()
    return redirect(url_for('main.projects'))

# 1) live_scan
@bp.route('/live-scan/<int:project_id>')
def live_scan(project_id):
    project = Project.query.get_or_404(project_id)

    # 가장 최근 완료된 스캔 결과 가져오기
    last_scan = ScanResult.query.filter_by(project_id=project_id) \
                                .order_by(ScanResult.timestamp.desc()) \
                                .first()

    return render_template('live_scan_v2.html', project=project, last_scan=last_scan)

# 2) url_tree
@bp.route('/url-tree/<int:project_id>')
def url_tree(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('url_tree.html', project=project)

# 3) tree-data API
@bp.route('/api/project/<int:project_id>/tree-data')
def get_tree_data(project_id):
    last_scan = ScanResult.query.filter_by(project_id=project_id) \
                                .order_by(ScanResult.timestamp.desc()) \
                                .first()
    project = Project.query.get(project_id)

    tree = {"name": project.target, "children": []}
    if not last_scan or not last_scan.data.get('urls'):
        return jsonify(tree)

    urls = sorted(list(set(last_scan.data['urls'])))
    for url in urls:
        path_str = url.replace(project.target, "").strip("/")
        if not path_str:
            continue
        parts = [p for p in path_str.split('/') if p]
        curr = tree['children']
        for p in parts:
            node = next((item for item in curr if item["name"] == p), None)
            if not node:
                new_node = {"name": p, "children": []}
                curr.append(new_node)
                curr = new_node["children"]
            else:
                curr = node["children"]

    return jsonify(tree)