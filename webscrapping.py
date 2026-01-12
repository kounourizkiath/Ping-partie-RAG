import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from tqdm import tqdm
import re
import time
import random

# ===============================
# CONFIGURATION
# ===============================
BASE_DIR = "data"
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
})

# ===============================
# SOURCES DE DONNÉES SECURE OPS (AUGMENTÉES)
# ===============================
SOURCES = {
    "owasp_cheatsheets": [
        # Top 40 OWASP Cheat Sheets les plus pertinents
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/NodeJS_Docker_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html",
    ],
    "owasp_top10": [
        # OWASP Top 10 (2021 et Web/API)
        "https://owasp.org/www-project-top-ten/",
        "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    ],
    "cisa_alerts": [
        # CISA - Pages principales
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "https://www.cisa.gov/topics/cybersecurity-best-practices",
        "https://www.cisa.gov/stopransomware",
        "https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience",
    ],
    "nist_resources": [
        # NIST Framework et guides
        "https://www.nist.gov/cyberframework",
        "https://csrc.nist.gov/publications/sp800",
    ],
    "mitre_attack": [
        # MITRE ATT&CK - Toutes les tactiques + techniques populaires
        "https://attack.mitre.org/tactics/TA0001/",  # Initial Access
        "https://attack.mitre.org/tactics/TA0002/",  # Execution
        "https://attack.mitre.org/tactics/TA0003/",  # Persistence
        "https://attack.mitre.org/tactics/TA0004/",  # Privilege Escalation
        "https://attack.mitre.org/tactics/TA0005/",  # Defense Evasion
        "https://attack.mitre.org/tactics/TA0006/",  # Credential Access
        "https://attack.mitre.org/tactics/TA0007/",  # Discovery
        "https://attack.mitre.org/tactics/TA0008/",  # Lateral Movement
        "https://attack.mitre.org/tactics/TA0009/",  # Collection
        "https://attack.mitre.org/tactics/TA0011/",  # Command and Control
        "https://attack.mitre.org/tactics/TA0010/",  # Exfiltration
        "https://attack.mitre.org/tactics/TA0040/",  # Impact
        "https://attack.mitre.org/matrices/enterprise/",  # Enterprise Matrix
        "https://attack.mitre.org/techniques/T1566/",  # Phishing
        "https://attack.mitre.org/techniques/T1059/",  # Command and Scripting Interpreter
        "https://attack.mitre.org/techniques/T1055/",  # Process Injection
        "https://attack.mitre.org/techniques/T1003/",  # OS Credential Dumping
        "https://attack.mitre.org/techniques/T1021/",  # Remote Services
        "https://attack.mitre.org/techniques/T1071/",  # Application Layer Protocol
        "https://attack.mitre.org/techniques/T1078/",  # Valid Accounts
        "https://attack.mitre.org/techniques/T1053/",  # Scheduled Task/Job
        "https://attack.mitre.org/techniques/T1027/",  # Obfuscated Files or Information
        "https://attack.mitre.org/techniques/T1204/",  # User Execution
    ],
    "pci_dss": [
        # PCI DSS Resources
        "https://www.pcisecuritystandards.org/document_library/",
    ],
    "cis_benchmarks": [
        # CIS Controls
        "https://www.cisecurity.org/controls",
    ],
    "cve_resources": [
        # CVE et vulnérabilités
        "https://www.cve.org/About/Overview",
        "https://cve.mitre.org/cve/search_cve_list.html",
    ],
    "security_blogs": [
        # Blogs de sécurité reconnus
        "https://krebsonsecurity.com/",
        "https://www.schneier.com/",
        "https://www.darkreading.com/",
    ],
    "cert_resources": [
        # CERT et alertes
        "https://www.cert.ssi.gouv.fr/",
        "https://www.cert.europa.eu/",
    ],
    "iso_standards": [
        # ISO 27001/27002 info
        "https://www.iso.org/standard/27001",
    ],
    "github_awesome_lists": [
        # Awesome Security Lists (pages principales)
        "https://github.com/sbilly/awesome-security",
        "https://github.com/Hack-with-Github/Awesome-Hacking",
        "https://github.com/qazbnm456/awesome-web-security",
        "https://github.com/paragonie/awesome-appsec",
        "https://github.com/enaqx/awesome-pentest",
        "https://github.com/hslatman/awesome-threat-intelligence",
        "https://github.com/rshipp/awesome-malware-analysis",
        "https://github.com/onlurking/awesome-infosec",
    ],
    "security_tools_docs": [
        # Documentation d'outils de sécurité populaires
        "https://nmap.org/book/man.html",
        "https://portswigger.net/burp/documentation",
        "https://www.metasploit.com/",
        "https://www.wireshark.org/docs/",
    ],
    "security_frameworks": [
        # Frameworks de sécurité
        "https://www.cisecurity.org/controls/cis-controls-list",
        "https://www.asd.gov.au/publications/essential-eight-maturity-model",
        "https://www.ncsc.gov.uk/collection/cyber-security-design-principles",
        "https://cheatsheetseries.owasp.org/IndexTopTen.html",
    ],
    "compliance_resources": [
        # Ressources de conformité
        "https://gdpr.eu/checklist/",
        "https://www.hipaajournal.com/hipaa-compliance-checklist/",
        "https://www.sox-online.com/",
    ],
    "incident_response": [
        # Réponse aux incidents
        "https://www.cisa.gov/incident-response",
        "https://www.sans.org/white-papers/incident-handlers-handbook/",
    ],
    "vulnerability_databases": [
        # Bases de données de vulnérabilités
        "https://www.exploit-db.com/",
        "https://vuldb.com/",
        "https://www.rapid7.com/db/",
    ],
    "security_training": [
        # Ressources de formation
        "https://www.cybrary.it/catalog/",
        "https://tryhackme.com/",
        "https://www.hackthebox.com/",
    ],
    "red_team_resources": [
        # Red Team
        "https://github.com/yeyintminthuhtut/Awesome-Red-Teaming",
        "https://www.ired.team/",
    ],
    "blue_team_resources": [
        # Blue Team
        "https://github.com/fabacab/awesome-cybersecurity-blueteam",
    ],
    "devsecops_resources": [
        # DevSecOps
        "https://github.com/TaptuIT/awesome-devsecops",
        "https://owasp.org/www-project-devsecops-guideline/",
    ],
    "zero_trust": [
        # Zero Trust Architecture
        "https://www.cisa.gov/zero-trust-maturity-model",
        "https://www.nist.gov/publications/zero-trust-architecture",
    ],
    "container_security": [
        # Sécurité des conteneurs
        "https://kubernetes.io/docs/concepts/security/",
        "https://docs.docker.com/engine/security/",
    ],
    "api_security": [
        # Sécurité API
        "https://owasp.org/www-project-api-security/",
        "https://apisecurity.io/",
    ],
    "web_security": [
        # Sécurité Web
        "https://portswigger.net/web-security",
        "https://developer.mozilla.org/en-US/docs/Web/Security",
    ],
    "network_security": [
        # Sécurité Réseau
        "https://www.cisco.com/c/en/us/products/security/what-is-network-security.html",
    ],
    "iot_security": [
        # Sécurité IoT
        "https://www.iotsecurityfoundation.org/best-practice-guidelines/",
    ],
    "mobile_security": [
        # Sécurité Mobile
        "https://owasp.org/www-project-mobile-top-10/",
        "https://github.com/OWASP/owasp-mastg",
    ],
    "splunk_siem": [
        # Splunk Documentation et Best Practices
        "https://docs.splunk.com/Documentation/Splunk/latest/Security/Secureyourdeployment",
        "https://docs.splunk.com/Documentation/Splunk/latest/Security/IntroductiontosecuringaSplunkEnterprisedeployment",
        "https://docs.splunk.com/Documentation/ES/latest/User/Howtouse",
        "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions",
        "https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/WelcometotheSearchTutorial",
        "https://www.splunk.com/en_us/blog/security.html",
        "https://research.splunk.com/",
        "https://lantern.splunk.com/Security",
        "https://www.splunk.com/en_us/blog/tips-and-tricks/splunk-clara-d-analytics-stories.html",
    ],
    "elastic_siem": [
        # Elastic Stack / ELK Security
        "https://www.elastic.co/guide/en/security/current/index.html",
        "https://www.elastic.co/guide/en/siem/guide/current/siem-overview.html",
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html",
        "https://www.elastic.co/blog/category/security",
        "https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-overview.html",
    ],
    "sentinel_siem": [
        # Microsoft Sentinel (Azure SIEM)
        "https://learn.microsoft.com/en-us/azure/sentinel/overview",
        "https://learn.microsoft.com/en-us/azure/sentinel/best-practices",
        "https://learn.microsoft.com/en-us/azure/sentinel/hunting",
        "https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in",
        "https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/bg-p/MicrosoftSentinelBlog",
    ],
    "qradar_siem": [
        # IBM QRadar
        "https://www.ibm.com/docs/en/qradar-common",
        "https://www.ibm.com/docs/en/qsip/7.5",
    ],
    "chronicle_siem": [
        # Google Chronicle Security
        "https://cloud.google.com/chronicle/docs/overview",
        "https://cloud.google.com/chronicle/docs/detection",
    ],
    "servicenow_security": [
        # ServiceNow Security Operations
        "https://www.servicenow.com/products/security-operations.html",
        "https://docs.servicenow.com/bundle/vancouver-security-management/page/product/security-operations/concept/security-operations.html",
        "https://docs.servicenow.com/bundle/vancouver-security-management/page/product/threat-intelligence/concept/threat-intel-intro.html",
        "https://docs.servicenow.com/bundle/vancouver-security-management/page/product/vulnerability-response/concept/vulnerability-response.html",
    ],
    "sumo_logic_siem": [
        # Sumo Logic
        "https://www.sumologic.com/solutions/cloud-siem/",
        "https://help.sumologic.com/docs/cse/",
    ],
    "datadog_security": [
        # Datadog Security Monitoring
        "https://docs.datadoghq.com/security/",
        "https://docs.datadoghq.com/security/cloud_siem/",
        "https://www.datadoghq.com/blog/tag/security/",
    ],
    "wazuh_siem": [
        # Wazuh (Open Source SIEM)
        "https://documentation.wazuh.com/current/index.html",
        "https://documentation.wazuh.com/current/user-manual/index.html",
        "https://documentation.wazuh.com/current/user-manual/capabilities/index.html",
    ],
    "soc_operations": [
        # SOC Best Practices
        "https://www.sans.org/white-papers/building-world-class-security-operations-center-roadmap/",
        "https://www.cisa.gov/sites/default/files/publications/SOC-CMM-Version-1.pdf",
        "https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center",
    ],
    "log_management": [
        # Log Management Best Practices
        "https://www.graylog.org/post/log-management-best-practices",
        "https://www.loggly.com/ultimate-guide/centralizing-with-syslog/",
    ],
    "siem_use_cases": [
        # SIEM Use Cases et Détection
        "https://www.cyberark.com/resources/blog/siem-use-cases",
        "https://www.exabeam.com/security-operations-center/siem-use-cases/",
    ],
    "threat_hunting": [
        # Threat Hunting
        "https://www.threathunting.net/",
        "https://www.sans.org/white-papers/who-what-where-when-why-how-effective-threat-hunting/",
        "https://github.com/ThreatHuntingProject/ThreatHunting",
    ],
    "sigma_rules": [
        # Sigma Detection Rules
        "https://github.com/SigmaHQ/sigma",
    ],
    "yara_rules": [
        # YARA Rules pour détection
        "https://github.com/Yara-Rules/rules",
        "https://yara.readthedocs.io/en/stable/",
    ],
    "osquery_security": [
        # osquery pour monitoring
        "https://osquery.io/",
        "https://osquery.readthedocs.io/en/stable/",
    ],
    "sans_resources": [
        # SANS Institute
        "https://www.sans.org/blog/",
        "https://www.sans.org/security-resources/",
        "https://www.sans.org/top25-software-errors/",
    ],
    "threat_intel": [
        # Threat Intelligence
        "https://www.sentinelone.com/blog/",
        "https://www.crowdstrike.com/blog/",
    ],
    "microsoft_security": [
        # Microsoft Security
        "https://www.microsoft.com/en-us/security/business/security-101",
        "https://learn.microsoft.com/en-us/security/",
    ],
    "aws_security": [
        # AWS Security Best Practices
        "https://aws.amazon.com/security/",
        "https://docs.aws.amazon.com/security/",
    ],
    "azure_security": [
        # Azure Security
        "https://azure.microsoft.com/en-us/products/category/security/",
        "https://learn.microsoft.com/en-us/azure/security/",
    ],
    "gcp_security": [
        # Google Cloud Security
        "https://cloud.google.com/security",
        "https://cloud.google.com/security/best-practices",
    ]
}

# ===============================
# UTILS
# ===============================
def filename_from_url(url):
    """Génère un nom de fichier propre à partir de l'URL."""
    path = urlparse(url).path.strip("/")
    # Ajouter le domaine pour éviter les collisions
    domain = urlparse(url).netloc.replace("www.", "").replace(".", "_")
    clean_path = re.sub(r'[^\w\-_\.]', '_', path)
    filename = f"{domain}_{clean_path}"
    return filename[:150] or "index"

def clean_html_to_text(html):
    """Nettoie le HTML pour extraire le texte pertinent pour le RAG."""
    soup = BeautifulSoup(html, "html.parser")

    # Suppression des éléments non pertinents
    for tag in soup([
        "script", "style", "nav", "footer", "header",
        "aside", "noscript", "svg", "form", "button",
        "meta", "link", "img", "iframe", "input", "select",
        "textarea"
    ]):
        tag.decompose()

    # Supprimer les classes communes de navigation et publicités
    for selector in [
        ".sidebar", ".toc", ".menu", ".breadcrumb", 
        ".footer", ".header", ".ad", ".advertisement",
        ".navigation", ".navbar", ".cookie", ".banner",
        "[class*='social']", "[class*='share']"
    ]:
        for element in soup.select(selector):
            element.decompose()

    text = soup.get_text("\n", strip=True)
    
    # Nettoyage avancé des lignes
    lines = []
    for line in text.splitlines():
        line = line.strip()
        # Filtrer les lignes trop courtes, répétitives ou inutiles
        if (len(line) > 20 and 
            not line.lower().startswith(("©", "cookie", "sign in", "log in", "menu")) and
            not all(c in "=-_*#" for c in line)):  # Lignes de séparation
            lines.append(line)
    
    return "\n".join(lines)

# ===============================
# SCRAPING LOGIC
# ===============================
def scrape_and_save(url, dest_path, max_retries=3):
    """Scrape une URL avec retry et sauvegarde."""
    for attempt in range(max_retries):
        try:
            # Délai aléatoire pour éviter le rate limiting
            time.sleep(random.uniform(1.5, 3.5))
            
            r = SESSION.get(url, timeout=30, allow_redirects=True)
            r.raise_for_status()

            text = clean_html_to_text(r.text)

            # Vérifier la taille minimale (réduite à 300 pour capturer plus de contenu)
            if len(text) < 300:
                print(f"⚠️  Contenu trop court pour {url} ({len(text)} caractères)")
                return False

            # Créer le répertoire parent
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            with open(dest_path, "w", encoding="utf-8") as f:
                f.write(f"Source: {url}\n")
                f.write(f"Scraped: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write(text)

            return True
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(f"🚫 Accès interdit (403) pour {url}")
                return False
            elif e.response.status_code == 404:
                print(f"❌ Page non trouvée (404) pour {url}")
                return False
            else:
                print(f"❌ Erreur HTTP {e.response.status_code} pour {url}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                return False
                
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(5)
                continue
            print(f"❌ Erreur de requête pour {url}: {str(e)[:100]}")
            return False
            
        except Exception as e:
            print(f"❌ Erreur inattendue pour {url}: {str(e)[:100]}")
            return False
    
    return False

# ===============================
# MAIN
# ===============================
def main():
    saved = 0
    skipped = 0
    results_by_source = {}
    
    total_urls = sum(len(urls) for urls in SOURCES.values())
    print(f"🎯 Objectif: Scraper ~200 documents SecOps pertinents")
    print(f"📚 Total des URLs à scraper: {total_urls}")
    print(f"📁 Dossier de destination: {BASE_DIR}\n")
    print(f"⏰ Temps estimé: ~{total_urls * 2.5 / 60:.1f} minutes\n")

    for source, urls in SOURCES.items():
        print(f"\n{'='*80}")
        print(f"📥 Scraping source: {source} ({len(urls)} URLs)")
        print(f"{'='*80}")
        
        source_saved = 0
        source_skipped = 0
        
        for url in tqdm(urls, desc=source):
            filename = filename_from_url(url) + ".txt"
            dest = os.path.join(BASE_DIR, source, filename)

            if scrape_and_save(url, dest):
                saved += 1
                source_saved += 1
            else:
                skipped += 1
                source_skipped += 1
        
        results_by_source[source] = {
            "saved": source_saved,
            "skipped": source_skipped,
            "total": len(urls)
        }

    print("\n" + "="*80)
    print("✅ SCRAPING TERMINÉ")
    print("="*80)
    print(f"\n📊 RÉSULTATS GLOBAUX:")
    print(f"   📄 Fichiers créés avec succès: {saved}")
    print(f"   ⏭️  URLs ignorées: {skipped}")
    print(f"   💯 Taux de réussite global: {(saved/(saved+skipped)*100):.1f}%")
    print(f"   📁 Destination: {os.path.abspath(BASE_DIR)}")
    
    print(f"\n📋 DÉTAILS PAR SOURCE:")
    for source, stats in results_by_source.items():
        rate = (stats["saved"]/stats["total"]*100) if stats["total"] > 0 else 0
        print(f"   • {source:30s}: {stats['saved']:3d}/{stats['total']:3d} ({rate:5.1f}%)")
    
    if saved >= 150:
        print(f"\n🎉 Objectif atteint ! Vous avez {saved} documents pour votre RAG.")
    elif saved >= 100:
        print(f"\n👍 Bon résultat ! {saved} documents récupérés.")
    else:
        print(f"\n⚠️  Seulement {saved} documents récupérés. Considérez d'ajouter plus de sources.")

if __name__ == "__main__":
    main()