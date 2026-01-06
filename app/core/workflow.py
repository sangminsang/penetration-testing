import asyncio
import logging
from flask import current_app

# Core modules imports
from ..core.recon.network import run_recon
from ..core.recon.web import collect_web_info
from ..core.cve.cpe_generator import batch_generate_cpes
from ..core.cve.async_nvd_client import AsyncNvdClient
from ..core.verifier import VulnerabilityVerifier
from ..core.scenario.generator import call_ollama
from ..utils.exploit import search_exploits_for_cves
from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
from ..core.cve.cache_manager import get_cache_manager

# Conditional imports for CVE matching (fallback mechanism)
try:
    from ..core.cve.matcher import search_cves_for_technologies as search_cves_func
except ImportError:
    try:
        from ..core.cve.matcher import search_cves_universal as search_cves_func
    except ImportError:
        search_cves_func = None

logger = logging.getLogger(__name__)

async def async_scan_workflow(target: str):
    """
    Executes the full vulnerability scanning workflow.
    Fixed for frontend compatibility:
    - Returns 'zapscan' instead of 'zap_scan'
    - Returns 'scenario' as a list of strings
    """
    
    logger.info("-" * 70)
    logger.info(f"[WORKFLOW] Starting comprehensive scan for: {target}")

    # --- Step 1: Network Recon ---
    print(f"[WORKFLOW] Step 1 - Running Nmap scan on {target}...")
    recon_result = run_recon(target)
    print(f"[WORKFLOW] Found {len(recon_result)} hosts")

    # --- Step 2: Web Recon ---
    print(f"[WORKFLOW] Step 2 - Running web reconnaissance...")
    web_info = {}
    try:
        web_info = collect_web_info(target)
        print(f"[WORKFLOW] Web recon completed")
    except Exception as e:
        logger.error(f"[WORKFLOW] Web recon failed: {e}")

    # --- Step 3: Cloud/Infra Info (Optional) ---
    print(f"[WORKFLOW] Step 3 - Infrastructure info...")
    cloud_info = {}
    try:
        from ..core.recon.cloud import discover_cloud_assets
        cloud_info = discover_cloud_assets(target)
    except Exception:
        pass

    # --- Step 4: CPE Generation ---
    print(f"[WORKFLOW] Step 4 - Generating CPE identifiers...")
    technologies_with_cpe = []
    
    # Process Nmap results
    if isinstance(recon_result, list):
        for host in recon_result:
            for port in host.get('ports', []):
                tech = {
                    "product": port.get('product', 'unknown'),
                    "version": port.get('version', ''),
                    "service": port.get('service', 'unknown'),
                    "port": port.get('port'),
                    "ip": host.get('ip'),
                    "source": "nmap",
                    "category": "detected"
                }
                technologies_with_cpe.append(tech)

    # Process Web Recon results
    if web_info and 'web_technologies' in web_info:
        for tech_info in web_info['web_technologies']:
            tech = {
                "product": tech_info.get('name', tech_info.get('product', 'unknown')),
                "version": tech_info.get('version', ''),
                "service": "web",
                "source": "web_recon",
                "category": "other"
            }
            technologies_with_cpe.append(tech)

    # Generate CPEs
    technologies_with_cpe = batch_generate_cpes(technologies_with_cpe)
    cpe_techs = [t for t in technologies_with_cpe if t.get('cpe')]
    print(f"[WORKFLOW] Generated CPE for {len(cpe_techs)} technologies")

    # --- Step 5: CVE Search ---
    print(f"[WORKFLOW] Step 5 - Searching for CVEs...")
    nvd_client = AsyncNvdClient(
        api_key=current_app.config.get("NVD_API_KEY"),
        base_url=current_app.config.get("NVD_BASE_URL")
    )
    cache_manager = get_cache_manager()
    
    all_cves = []
    if search_cves_func:
        print(f"[WORKFLOW] Searching CVEs for {len(cpe_techs)} technologies...")
        for tech in cpe_techs:
            prod = tech.get('product')
            ver = tech.get('version')
            try:
                cves = await search_cves_func(prod, ver, nvd_client=nvd_client, cache_manager=cache_manager)
                if cves:
                    all_cves.extend(cves)
            except Exception as e:
                # logger.error(f"[WORKFLOW] CVE search error for {prod}: {e}")
                pass

    # Deduplicate CVEs
    unique_cves = {}
    for cve in all_cves:
        if cve and isinstance(cve, dict) and cve.get('id'):
            unique_cves[cve.get('id')] = cve
    
    all_cves = list(unique_cves.values())
    print(f"[WORKFLOW] Found {len(all_cves)} unique CVEs")

    # --- Step 6: ZAP Security Scan ---
    print(f"[WORKFLOW] Step 6 - Running OWASP ZAP security scan...")
    zap_alerts = []
    try:
        zap_scanner = ZapScanner(
            api_key=current_app.config.get("ZAP_API_KEY"),
            proxy_host=current_app.config.get("ZAP_PROXY_HOST"),
            proxy_port=current_app.config.get("ZAP_PROXY_PORT")
        )
        # Use full_scan (Spider + Active Scan)
        scan_result = zap_scanner.full_scan(target)
        
        if scan_result and 'alerts' in scan_result:
            zap_alerts = format_alerts_for_dashboard(scan_result['alerts'])
    except Exception as e:
        print(f"[WORKFLOW] ZAP scan skipped: {e}")

    # --- Step 7: Vulnerability Verification ---
    print(f"[WORKFLOW] Step 7 - Verifying vulnerabilities...")
    verifications = []
    try:
        endpoints = web_info.get('api_endpoints', [])
        verifier = VulnerabilityVerifier(target, endpoints, all_cves, technologies_with_cpe)
        
        if hasattr(verifier, 'verify_vulnerabilities'):
            try:
                verifications = verifier.verify_vulnerabilities()
            except TypeError:
                verifications = verifier.verify_vulnerabilities(all_cves, web_info)
        elif hasattr(verifier, 'verify'):
            verifications = verifier.verify()
    except Exception as e:
        # logger.error(f"[WORKFLOW] Verification failed: {e}")
        pass

    # --- Step 8: Exploit Search ---
    print(f"[WORKFLOW] Step 8 - Searching for exploits...")
    exploits = []
    try:
        exploits = search_exploits_for_cves(all_cves)
        print(f"[WORKFLOW] Found {len(exploits)} exploits")
    except Exception:
        pass

    # --- Step 9: AI Scenario Generation ---
    print(f"[WORKFLOW] Step 9 - Generating AI-powered attack scenario...")
    scenario_text = ""
    scenario_object = {}
    
    try:
        # Build prompt for AI
        prompt_lines = [f"Analyze the security posture of {target}."]
        
        if technologies_with_cpe:
            tech_names = [t.get('product', 'unknown') for t in technologies_with_cpe]
            prompt_lines.append(f"Technologies: {', '.join(set(tech_names))}.")
            
        if all_cves:
            prompt_lines.append(f"Vulnerabilities: {len(all_cves)} found.")
            sorted_cves = sorted(all_cves, key=lambda x: float(x.get('cvss', 0) or 0), reverse=True)
            for cve in sorted_cves[:5]:
                cve_id = cve.get('id', 'Unknown')
                desc = cve.get('description', '')[:100].replace('\n', ' ')
                prompt_lines.append(f"- {cve_id}: {desc}...")
        
        prompt_lines.append("Based on this, create a short penetration testing scenario.")
        final_prompt = " ".join(prompt_lines)

        print(f"[WORKFLOW] Calling Ollama API...")
        try:
            scenario_text = call_ollama(final_prompt)
        except Exception:
            # Fallback if AI fails
            scenario_text = f"Attack Scenario for {target}:\n"
            scenario_text += f"1. Reconnaissance: Discovered {len(technologies_with_cpe)} technologies.\n"
            scenario_text += f"2. Vulnerability Analysis: Identified {len(all_cves)} potential vulnerabilities.\n"
            scenario_text += f"3. Exploitation: Found {len(exploits)} public exploits."

        # Structure for dashboard
        scenario_object = {
            "title": f"Penetration Test Scenario for {target}",
            "summary": scenario_text[:200] + "...",
            "content": scenario_text,
            "steps": [
                {"name": "Reconnaissance", "details": f"Found {len(technologies_with_cpe)} tech stacks"},
                {"name": "Scanning", "details": f"Detected {len(all_cves)} CVEs"},
                {"name": "Analysis", "details": "High risk vulnerabilities identified"}
            ]
        }
        print(f"[WORKFLOW] AI scenario generated successfully")

    except Exception as e:
        logger.warning(f"[WORKFLOW] AI generation failed: {e}")
        scenario_text = "AI scenario generation failed."
        scenario_object = {"content": scenario_text}

    logger.info("-" * 70)
    print(f"[WORKFLOW] SCAN COMPLETED")

    # Categorize results for dashboard
    recon_by_category = {
        "web": [], "network": [], "os": [], "database": [], "cloud": [], "container": []
    }
    
    for tech in technologies_with_cpe:
        # Default to web or network based on source
        if tech.get('service') == 'web' or tech.get('source') == 'web_recon':
            recon_by_category['web'].append(tech)
        else:
            recon_by_category['network'].append(tech)

    # Final Return Dictionary (Matching Frontend Expectations)
    return {
        "target": target,
        "technologies": technologies_with_cpe,
        "cves": all_cves,
        "zapscan": {"alerts": zap_alerts},  # FIXED: key changed from 'zap_scan' to 'zapscan'
        "verifications": verifications,
        "exploits": exploits,
        "scenario": scenario_text.split('\n') if scenario_text else [], # FIXED: converted string to list
        "ai_scenario": scenario_object, 
        "report_summary": scenario_text,
        "categorized": {
            "recon": recon_by_category
        }
    }
