import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass

@dataclass
class Finding:
    tool: str
    severity: str
    description: str
    location: str

class ReportParser:
    def __init__(self):
        self.findings = []

    def parse_bandit(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data.get('results', []):
                    self.findings.append(Finding(
                        tool="Bandit",
                        severity=item.get('issue_severity'),
                        description=item.get('issue_text'),
                        location=f"{item.get('filename')}:{item.get('line_number')}"
                    ))
        except Exception as e:
            print(f"Ошибка парсинга Bandit: {e}")

    def parse_zap(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                site = data.get('site', [{}])[0]
                for alert in site.get('alerts', []):
                    self.findings.append(Finding(
                        tool="OWASP ZAP",
                        severity=alert.get('riskdesc').split(' ')[0], 
                        description=alert.get('name'),
                        location="URL: " + alert.get('instances', [{}])[0].get('uri', 'N/A')
                    ))
        except Exception as e:
            print(f"Ошибка парсинга ZAP: {e}")

    def parse_junit(self, filepath, tool_name="Tests"):
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for testcase in root.iter('testcase'):
                failure = testcase.find('failure')
                if failure is not None:
                    self.findings.append(Finding(
                        tool=tool_name,
                        severity="High",
                        description=f"Test Failed: {testcase.get('name')} - {failure.get('message')}",
                        location=testcase.get('classname')
                    ))
        except Exception as e:
            print(f"Ошибка парсинга JUnit: {e}")

    def get_findings(self):
        return self.findings