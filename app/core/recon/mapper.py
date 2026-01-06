"""
URL Tree Mapper
- Build hierarchical tree structure from URLs
- Calculate tree statistics
- Prepare data for visualization
- Map vulnerabilities to nodes
"""

from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class TreeNode:
    """Tree node representing a URL path segment"""

    def __init__(self, name: str, path: str = '', parent: Optional['TreeNode'] = None):
        self.name = name  # Segment name (e.g., 'api', 'users')
        self.path = path  # Full path (e.g., '/api/users')
        self.parent = parent
        self.children: Dict[str, 'TreeNode'] = {}

        # URL metadata
        self.status_code: int = 0
        self.content_type: str = ''
        self.size: int = 0
        self.method: str = 'GET'

        # Security data
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.technologies: List[str] = []
        self.interesting: bool = False

    def add_child(self, name: str, path: str) -> 'TreeNode':
        """Add child node"""
        if name not in self.children:
            self.children[name] = TreeNode(name, path, self)
        return self.children[name]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'path': self.path,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'size': self.size,
            'method': self.method,
            'vulnerabilities': self.vulnerabilities,
            'technologies': self.technologies,
            'interesting': self.interesting,
            'children': [child.to_dict() for child in self.children.values()],
            'vulnerability_count': len(self.vulnerabilities),
            'max_severity': self._get_max_severity()
        }

    def _get_max_severity(self) -> float:
        """Get maximum CVSS score from vulnerabilities"""
        if not self.vulnerabilities:
            return 0.0
        return max([v.get('cvss', 0) for v in self.vulnerabilities])


class URLTreeMapper:
    """Map URLs to hierarchical tree structure"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.root = TreeNode('root', '/')

    def build_tree(
        self,
        urls: List[Dict[str, Any]],
        cves: List[Dict[str, Any]] = None,
        technologies: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build tree structure from URL list

        Args:
            urls: List of discovered URLs with metadata
            cves: List of CVE vulnerabilities (optional)
            technologies: List of detected technologies (optional)

        Returns:
            Tree structure with statistics
        """
        logger.info(f"[MAPPER] Building tree from {len(urls)} URLs")

        # Add URLs to tree
        for url_data in urls:
            self._add_url_to_tree(url_data)

        # Map vulnerabilities to tree nodes
        if cves:
            self._map_vulnerabilities(cves)

        # Map technologies to tree nodes
        if technologies:
            self._map_technologies(technologies)

        # Calculate statistics
        stats = self._calculate_statistics()

        logger.info(f"[MAPPER] Tree built: {stats['total_nodes']} nodes, {stats['max_depth']} max depth")

        return {
            'tree': self.root.to_dict(),
            'statistics': stats,
            'base_url': self.base_url
        }

    def _add_url_to_tree(self, url_data: Dict[str, Any]):
        """Add URL to tree structure"""
        url = url_data.get('url') or url_data.get('full_url', '')

        # Parse URL path
        parsed = urlparse(url)
        path = parsed.path

        if not path or path == '/':
            # Root URL
            self.root.status_code = url_data.get('status_code', 0)
            self.root.content_type = url_data.get('content_type', '')
            self.root.size = url_data.get('size', 0)
            return

        # Split path into segments
        segments = [s for s in path.split('/') if s]

        # Build tree path
        current_node = self.root
        current_path = ''

        for i, segment in enumerate(segments):
            current_path += f'/{segment}'

            # Add or get child node
            if segment not in current_node.children:
                current_node = current_node.add_child(segment, current_path)
            else:
                current_node = current_node.children[segment]

            # If this is the last segment, add metadata
            if i == len(segments) - 1:
                current_node.status_code = url_data.get('status_code', 0)
                current_node.content_type = url_data.get('content_type', '')
                current_node.size = url_data.get('size', 0)
                current_node.interesting = url_data.get('interesting', False)

    def _map_vulnerabilities(self, cves: List[Dict[str, Any]]):
        """Map CVE vulnerabilities to tree nodes"""
        logger.info(f"[MAPPER] Mapping {len(cves)} vulnerabilities to tree")

        for cve in cves:
            # Get affected paths/endpoints
            product = cve.get('product', '').lower()
            version = cve.get('version', '')

            # Try to find matching nodes
            nodes_to_update = self._find_nodes_by_product(product)

            for node in nodes_to_update:
                vuln_data = {
                    'cve_id': cve.get('cve_id', 'N/A'),
                    'cvss': cve.get('cvss', 0),
                    'severity': cve.get('severity', 'Unknown'),
                    'description': cve.get('description', ''),
                    'product': product,
                    'version': version
                }
                node.vulnerabilities.append(vuln_data)

    def _map_technologies(self, technologies: List[Dict[str, Any]]):
        """Map detected technologies to tree nodes"""
        logger.info(f"[MAPPER] Mapping {len(technologies)} technologies to tree")

        for tech in technologies:
            name = tech.get('name', '').lower()

            # Map technology to relevant nodes
            if 'express' in name or 'node' in name:
                # Backend - map to API nodes
                self._add_tech_to_pattern(tech['name'], '/api')
            elif 'react' in name or 'vue' in name or 'angular' in name:
                # Frontend - map to root and static assets
                self._add_tech_to_pattern(tech['name'], '/')
                self._add_tech_to_pattern(tech['name'], '/static')
            elif 'nginx' in name or 'apache' in name:
                # Web server - map to root
                self.root.technologies.append(tech['name'])

    def _find_nodes_by_product(self, product: str) -> List[TreeNode]:
        """Find tree nodes related to a product"""
        nodes = []

        # Search keywords based on product
        keywords = []
        if 'express' in product:
            keywords = ['api', 'rest', 'graphql']
        elif 'react' in product or 'vue' in product:
            keywords = ['static', 'assets', 'js']
        elif 'mysql' in product or 'postgres' in product:
            keywords = ['api', 'db', 'database']

        # Find nodes matching keywords
        self._search_nodes(self.root, keywords, nodes)

        # If no specific nodes found, add to root
        if not nodes:
            nodes.append(self.root)

        return nodes

    def _search_nodes(self, node: TreeNode, keywords: List[str], results: List[TreeNode]):
        """Recursively search for nodes matching keywords"""
        # Check if node name matches any keyword
        for keyword in keywords:
            if keyword in node.name.lower():
                results.append(node)
                break

        # Search children
        for child in node.children.values():
            self._search_nodes(child, keywords, results)

    def _add_tech_to_pattern(self, tech_name: str, pattern: str):
        """Add technology to nodes matching pattern"""
        nodes = []
        self._find_nodes_by_path(self.root, pattern, nodes)

        for node in nodes:
            if tech_name not in node.technologies:
                node.technologies.append(tech_name)

    def _find_nodes_by_path(self, node: TreeNode, pattern: str, results: List[TreeNode]):
        """Find nodes by path pattern"""
        if pattern.lower() in node.path.lower():
            results.append(node)

        for child in node.children.values():
            self._find_nodes_by_path(child, pattern, results)

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate tree statistics"""
        stats = {
            'total_nodes': 0,
            'max_depth': 0,
            'total_vulnerabilities': 0,
            'critical_vulns': 0,  # CVSS >= 9.0
            'high_vulns': 0,       # CVSS >= 7.0
            'medium_vulns': 0,     # CVSS >= 4.0
            'low_vulns': 0,        # CVSS < 4.0
            'nodes_with_vulns': 0,
            'technologies_found': set()
        }

        self._collect_statistics(self.root, 0, stats)

        # Convert set to list
        stats['technologies_found'] = list(stats['technologies_found'])

        return stats

    def _collect_statistics(self, node: TreeNode, depth: int, stats: Dict[str, Any]):
        """Recursively collect statistics"""
        stats['total_nodes'] += 1
        stats['max_depth'] = max(stats['max_depth'], depth)

        # Vulnerability stats
        if node.vulnerabilities:
            stats['nodes_with_vulns'] += 1
            stats['total_vulnerabilities'] += len(node.vulnerabilities)

            for vuln in node.vulnerabilities:
                cvss = vuln.get('cvss', 0)
                if cvss >= 9.0:
                    stats['critical_vulns'] += 1
                elif cvss >= 7.0:
                    stats['high_vulns'] += 1
                elif cvss >= 4.0:
                    stats['medium_vulns'] += 1
                else:
                    stats['low_vulns'] += 1

        # Technology stats
        for tech in node.technologies:
            stats['technologies_found'].add(tech)

        # Recurse children
        for child in node.children.values():
            self._collect_statistics(child, depth + 1, stats)


def build_url_tree(
    urls: List[Dict[str, Any]],
    base_url: str,
    cves: List[Dict[str, Any]] = None,
    technologies: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Build URL tree structure with vulnerability mapping

    Args:
        urls: List of discovered URLs
        base_url: Base target URL
        cves: List of CVE vulnerabilities (optional)
        technologies: List of detected technologies (optional)

    Returns:
        Tree structure with statistics
    """
    mapper = URLTreeMapper(base_url)
    return mapper.build_tree(urls, cves, technologies)
