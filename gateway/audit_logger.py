import json
import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict, Counter

class AuditLogger:
    def __init__(self, log_file_path: str = "audit_log.jsonl"):
        self.log_file_path = log_file_path

    def log_event(self, event: Dict[str, Any]) -> None:
        event["timestamp"] = datetime.datetime.utcnow().isoformat()
        event["event_id"] = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        with open(self.log_file_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')

    def read_events(self, start_date: Optional[datetime.datetime] = None,
                    end_date: Optional[datetime.datetime] = None) -> List[Dict[str, Any]]:
        """读取指定时间范围内的所有事件"""
        events = []
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    event = json.loads(line.strip())
                    ts = datetime.datetime.fromisoformat(event["timestamp"])
                    if start_date and ts < start_date:
                        continue
                    if end_date and ts > end_date:
                        continue
                    events.append(event)
        except FileNotFoundError:
            pass
        return events


class RiskReporter:
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger

    def generate_summary(self, start_date: datetime.datetime, end_date: datetime.datetime) -> Dict[str, Any]:
        events = self.audit_logger.read_events(start_date, end_date)
        total_interactions = len([e for e in events if e.get("event_type") == "input_processed"])
        blocked_outputs = len([e for e in events if e.get("event_type") == "output_checked" and not e.get("is_safe")])
        
        # 统计PII类型
        pii_counter = Counter()
        for e in events:
            if e.get("event_type") == "input_processed":
                for finding in e.get("pii_findings", []):
                    pii_counter[finding.get("type")] += 1
        
        # 统计触发的合规规则
        rule_counter = Counter()
        for e in events:
            if e.get("event_type") == "output_checked" and not e.get("is_safe"):
                for rule in e.get("triggered_rules", []):
                    rule_counter[rule] += 1
        
        # 按用户统计风险
        user_risk = defaultdict(int)
        for e in events:
            if e.get("event_type") == "output_checked" and not e.get("is_safe"):
                user_risk[e.get("user_id", "unknown")] += 1
        high_risk_users = [{"user_id": uid, "risk_count": cnt} for uid, cnt in user_risk.items() if cnt > 5]
        high_risk_users.sort(key=lambda x: x["risk_count"], reverse=True)
        
        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_interactions": total_interactions,
            "blocked_outputs": blocked_outputs,
            "block_rate": blocked_outputs / total_interactions if total_interactions > 0 else 0,
            "pii_detections": {
                "total": sum(pii_counter.values()),
                "by_type": dict(pii_counter.most_common())
            },
            "triggered_rules": dict(rule_counter.most_common()),
            "high_risk_users": high_risk_users[:10]  # 前10名高风险用户
        }

    def generate_report(self, start_date: datetime.datetime, end_date: datetime.datetime, format: str = "json") -> str:
        summary = self.generate_summary(start_date, end_date)
        if format == "json":
            return json.dumps(summary, indent=2, ensure_ascii=False)
        else:
            # 文本格式报告（适合邮件或展示）
            lines = [
                "=" * 60,
                "企业AI安全使用及风险报告",
                f"报告周期：{summary['period']['start']} 至 {summary['period']['end']}",
                "=" * 60,
                f"总交互次数：{summary['total_interactions']}",
                f"拦截违规输出：{summary['blocked_outputs']} (占比 {summary['block_rate']:.2%})",
                "\n--- 敏感信息检测统计 ---",
                f"总发现敏感信息次数：{summary['pii_detections']['total']}",
                "各类敏感信息频次：",
            ]
            for pii_type, count in summary['pii_detections']['by_type'].items():
                lines.append(f"  - {pii_type}: {count} 次")
            lines.append("\n--- 触发合规规则统计 ---")
            for rule, count in summary['triggered_rules'].items():
                lines.append(f"  - {rule}: {count} 次")
            lines.append("\n--- 高风险用户 TOP 10 ---")
            for user in summary['high_risk_users']:
                lines.append(f"  - 用户 {user['user_id']}: 触发 {user['risk_count']} 次违规")
            lines.append("=" * 60)
            return "\n".join(lines)