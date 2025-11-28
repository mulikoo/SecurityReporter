import argparse
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import requests
from parsers import ReportParser

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL") 
OUTPUT_FILE = "output/security_report.html"

def generate_html(findings):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')
    
    html_content = template.render(
        findings=findings,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[+] Отчет сохранен в {OUTPUT_FILE}")
    return OUTPUT_FILE

def send_slack_notification(findings, report_link="http://ci-server/job/last/artifact/report.html"):
    if not SLACK_WEBHOOK_URL:
        print("[-] Slack Webhook не задан, пропуск уведомления.")
        return

    high_sev = sum(1 for f in findings if f.severity in ['High', 'Critical'])
    total = len(findings)
    
    color = "#FF0000" if high_sev > 0 else "#36a64f"
    
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"DevSecOps Scan Report: {total} Issues Found",
                "text": f"High Severity: {high_sev}\nTotal Issues: {total}\n <{report_link}|Открыть полный отчет>",
                "footer": "Security Reporter Bot"
            }
        ]
    }
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print("[+] Уведомление в Slack отправлено.")
        else:
            print(f"[-] Ошибка отправки в Slack: {response.text}")
    except Exception as e:
        print(f"[-] Ошибка сети: {e}")

def main():
    parser = argparse.ArgumentParser(description="Universal DevSecOps Reporter")
    parser.add_argument('--bandit', help='Path to Bandit JSON report')
    parser.add_argument('--zap', help='Path to OWASP ZAP JSON report')
    parser.add_argument('--junit', help='Path to JUnit XML report')
    
    args = parser.parse_args()
    
    report_parser = ReportParser()
    
    if args.bandit and os.path.exists(args.bandit):
        print(f"[*] Parsing Bandit: {args.bandit}")
        report_parser.parse_bandit(args.bandit)
        
    if args.zap and os.path.exists(args.zap):
        print(f"[*] Parsing ZAP: {args.zap}")
        report_parser.parse_zap(args.zap)

    if args.junit and os.path.exists(args.junit):
        print(f"[*] Parsing JUnit: {args.junit}")
        report_parser.parse_junit(args.junit)
        
    findings = report_parser.get_findings()
    
    generate_html(findings)
    
    if findings:
        send_slack_notification(findings)
    else:
        print("[*] Проблем не найдено, отчет чист.")

if __name__ == "__main__":
    main()