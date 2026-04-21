import json
import re
from typing import List, Dict, Any, Tuple

class ComplianceRule:
    def __init__(self, name: str, pattern: str, match_type: str = "keyword", action: str = "block", severity: str="medium", risk_score: int = 0):
        self.name = name
        self.pattern = pattern
        self.match_type = match_type
        self.action = action
        self.severity = severity
        self.risk_score = risk_score
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
        self.rules_config_path = rules_config_path
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
    def reload_rules(self):
        """热重载合规规则"""
        self.rules = self._load_rules(self.rules_config_path)

    def evaluate(self, text: str):
        triggered = []
        total_score = 0
        max_risk_rule = None
        for rule in self.rules:
            if rule.matches(text):
                triggered.append(rule.name)
                total_score += rule.risk_score
                if max_risk_rule is None or rule.risk_score > max_risk_rule.risk_score:
                    max_risk_rule = rule
        is_safe = total_score < 70   # 阈值可配置，超过70分拦截
        return is_safe, triggered, total_score, max_risk_rule

class OutputProcessor:
    def __init__(self, compliance_engine: ComplianceRuleEngine = None):
        self.compliance_engine = compliance_engine or ComplianceRuleEngine()
    
    async def process(self, ai_output: str) -> Tuple[str, bool, Dict[str, Any]]:
        is_compliant, triggered_rules, total_score, max_risk_rule = self.compliance_engine.evaluate(ai_output)
    
        if not is_compliant:
            # 提取触发规则中的关键词（取第一个匹配到的关键词作为示例）
            keyword_found = ""
            if max_risk_rule and max_risk_rule.match_type == "keyword":
                for kw in max_risk_rule.keywords:
                    if kw in ai_output:
                        keyword_found = kw
                        break
            # 生成可解释性输出
            if keyword_found:
                # 对关键词进行脱敏显示：首字 + *** + 尾字
                if len(keyword_found) >= 3:
                    masked_keyword = keyword_found[0] + "***" + keyword_found[-1]
                else:
                    masked_keyword = keyword_found[0] + "***"
                severity_text = "重度" if max_risk_rule.severity == "high" else "中度"
                reply = f"“{masked_keyword}” 涉及到 {severity_text}风险，建议您规避该风险并重新使用。"
            else:
                reply = f"检测到违规内容（{', '.join(triggered_rules)}），风险分数 {total_score}，已被拦截。"
        
            audit_info = {
                "action": "blocked",
                "triggered_rules": triggered_rules,
                "total_risk_score": total_score,
                "original_output": ai_output[:200]
            }
            return reply, False, audit_info
        else:
            return ai_output, True, {"action": "passed"}
