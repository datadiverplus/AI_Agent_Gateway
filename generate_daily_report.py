"""
每天自动生成《企业AI安全使用及风险报告》
用法：python generate_daily_report.py
建议配置为每日定时任务（Windows 任务计划程序 / Linux cron）
"""
import datetime
import os
from gateway.audit_logger import AuditLogger, RiskReporter

# 确保 reports 目录存在
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def main():
    # 设定报告周期：昨天 00:00:00 到 23:59:59
    end = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - datetime.timedelta(days=1)
    
    # 生成报告
    logger = AuditLogger()
    reporter = RiskReporter(logger)
    report_text = reporter.generate_report(start, end, format="text")
    
    # 保存为文本文件
    filename = f"{REPORT_DIR}/risk_report_{end.date()}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    
    print(f"报告已生成：{filename}")
    # 可选：发送邮件或调用企业微信/钉钉机器人

if __name__ == "__main__":
    main()