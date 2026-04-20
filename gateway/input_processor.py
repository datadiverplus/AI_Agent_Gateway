import re
import json
from typing import List, Dict, Any, Tuple

class PIIFilter:
    """敏感信息识别与脱敏器"""
    
    def __init__(self, rules_config_path: str = "config/pii_rules.json"):
        self.rules = self._load_rules(rules_config_path)
    
    def _load_rules(self, path: str) -> List[Dict[str, Any]]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            for rule in rules:
                rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
            return rules
        except FileNotFoundError:
            print(f"Warning: Config file {path} not found. Using default rules.")
            return self._default_rules()
    
    def _default_rules(self) -> List[Dict[str, Any]]:
        return [
            {"name": "CHINESE_ID", "pattern": r"[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]", "mask_with": "[身份证号已脱敏]"},
            {"name": "PHONE", "pattern": r"1[3-9]\d{9}", "mask_with": lambda m: m.group()[:3] + "****" + m.group()[-4:]},
            {"name": "EMAIL", "pattern": r"\b[\w\.-]+@[\w\.-]+\.\w+\b", "mask_with": lambda m: m.group()[0] + "***@" + m.group().split('@')[1]},
            {"name": "BANK_CARD", "pattern": r"\d{16,19}", "mask_with": "[银行卡号已脱敏]"},
            {"name": "CONTRACT_NUMBER", "pattern": r"CT-\d{4}-\d{6}", "mask_with": "[合同编号已脱敏]"},
            {"name": "AMOUNT", "pattern": r"(?:￥|¥|RMB|USD|EUR)?\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:元|美元|欧元|人民币)?", "mask_with": "[金额已脱敏]"},
            {"name": "INTERNAL_FINANCE", "pattern": r"(?:财务|预算|项目经费|部门成本)", "mask_with": "[内部财务信息已脱敏]"},
        ]
    
    def mask(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        masked_text = text
        findings = []
        for rule in self.rules:
            pattern = rule['compiled_pattern']
            mask_with = rule['mask_with']

            if rule.get('name', '').upper() == 'PHONE':
            # 如果原始 mask_with 是字符串 "MASK_FUNC"，则替换为部分掩码函数
                if mask_with == "MASK_FUNC":
                    mask_with = lambda m: m.group(0)[:3] + '****' + m.group(0)[-4:]

            for match in pattern.finditer(text):
                if callable(mask_with):
                    masked_val = mask_with(match)
                else:
                    masked_val = mask_with
                finding = {
                    "type": rule['name'],
                    "start": match.start(),
                    "end": match.end(),
                    "original": match.group(),
                    "masked": masked_val
                }
                findings.append(finding)
            # 执行替换
            masked_text = pattern.sub(mask_with, masked_text)
        return masked_text, findings
    
    def _apply_mask(self, match: re.Match, mask_with):
        if callable(mask_with):
            return mask_with(match)
        else:
            return mask_with


class InputProcessor:
    def __init__(self, pii_filter: PIIFilter = None):
        self.pii_filter = pii_filter or PIIFilter()
    
    async def process(self, user_input: str) -> Tuple[str, List[Dict[str, Any]]]:
        masked_input, findings = self.pii_filter.mask(user_input)
        # 可选：记录审计日志
        return masked_input, findings
