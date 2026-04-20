import json
import re
from typing import List, Dict, Any, Tuple

class ComplianceRule:
    def __init__(self, name: str, pattern: str, match_type: str = "keyword", action: str = "block"):
        self.name = name
        self.pattern = pattern
        self.match_type = match_type
        self.action = action
        if match_type == "regex":
            self.compiled_pattern = re.compile(pattern, re.IGNORECASE)
        else:
            self.keywords = [kw.strip() for kw in pattern.split('|')]
    
    def matches(self, text: str) -> bool:
        if self.match_type == "regex":
            return bool(self.compiled_pattern.search(text))
        else:
            return any(kw in text for kw in self.keywords)


class ComplianceRuleEngine:
    def __init__(self, rules_config_path: str = "config/compliance_rules.json"):
        self.rules = self._load_rules(rules_config_path)
    
    def _load_rules(self, path: str) -> List[ComplianceRule]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            return [ComplianceRule(**rule) for rule in rules_data]
        except FileNotFoundError:
            print(f"Warning: Config file {path} not found. Using default rules.")
            return self._default_rules()
    
    def _default_rules(self) -> List[ComplianceRule]:
        return [
            ComplianceRule("SKIP_APPROVAL", "跳过审批|不需要审批|直接支付|绕过审核", "keyword", "block"),
            ComplianceRule("TRANSFER_TO_PRIVATE", "转至私人账户|支付到私人|汇款到个人账户", "keyword", "block"),
            ComplianceRule("FINANCIAL_VIOLATION", "拆分发票|规避审核|私下交易|虚开发票", "keyword", "block"),
        ]
    
    def evaluate(self, text: str) -> Tuple[bool, List[str]]:
        triggered = []
        for rule in self.rules:
            if rule.matches(text):
                triggered.append(rule.name)
        return len(triggered) == 0, triggered


class OutputProcessor:
    def __init__(self, compliance_engine: ComplianceRuleEngine = None):
        self.compliance_engine = compliance_engine or ComplianceRuleEngine()
    
    async def process(self, ai_output: str) -> Tuple[str, bool, Dict[str, Any]]:
        is_compliant, triggered_rules = self.compliance_engine.evaluate(ai_output)
        if not is_compliant:
            audit_info = {
                "action": "blocked",
                "triggered_rules": triggered_rules,
                "original_output": ai_output[:500]
            }
            processed_output = f"根据企业安全合规策略，检测到违规内容：{', '.join(triggered_rules)}。此输出已被拦截。"
            return processed_output, False, audit_info
        else:
            return ai_output, True, {"action": "passed"}
