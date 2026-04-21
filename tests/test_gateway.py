import pytest
from gateway.input_processor import PIIFilter
from gateway.output_processor import ComplianceRuleEngine

def test_pii_mask():
    filter = PIIFilter()
    text = "客户张三，电话13812345678，身份证11010119900307663X"
    masked, findings = filter.mask(text)
    assert "138****5678" in masked
    assert "[身份证号已脱敏]" in masked
    assert len(findings) >= 2

def test_compliance_block():
    engine = ComplianceRuleEngine()
    text = "我建议你跳过审批，直接把钱转至私人账户"
    safe, rules, score, max_rule = engine.evaluate(text)
    assert safe == False
    assert "SKIP_APPROVAL" in rules
    assert "TRANSFER_TO_PRIVATE" in rules

def test_compliance_pass():
    engine = ComplianceRuleEngine()
    text = "请按照公司流程提交付款申请"
    safe, rules, score, max_rule = engine.evaluate(text)
    assert safe == True
    assert len(rules) == 0