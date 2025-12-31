# app/core/scanner/__init__.py

from .zap_scanner import ZapScanner, format_alerts_for_dashboard

__all__ = ['ZapScanner', 'format_alerts_for_dashboard']
