"""
企业级 AI Agent Gateway
功能：
1. 敏感信息自动识别与脱敏
2. AI 输出内容合规监测与拦截
3. 交互日志审计与风险报告生成
"""
import json
import datetime
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
import os
from fastapi import Header, HTTPException

# 导入三大核心模块
from gateway.input_processor import InputProcessor, PIIFilter
from gateway.output_processor import OutputProcessor, ComplianceRuleEngine
from gateway.audit_logger import AuditLogger, RiskReporter

#初始化组件
# 使用默认配置（config目录下的JSON文件）
pii_filter = PIIFilter(rules_config_path="config/pii_rules.json")
compliance_engine = ComplianceRuleEngine(rules_config_path="config/compliance_rules.json")
input_processor = InputProcessor(pii_filter=pii_filter)
output_processor = OutputProcessor(compliance_engine=compliance_engine)
audit_logger = AuditLogger(log_file_path="audit_log.jsonl")
risk_reporter = RiskReporter(audit_logger)

#FastAPI 应用
app = FastAPI(
    title="企业级 AI Agent Gateway",
    description="硅基同事 - 安全合规官，实现数据安全、内容合规与审计自动化",
    version="1.0.0"
)

#请求/响应模型
class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]   # [{"role": "user", "content": "..."}]
    user_id: Optional[str] = "anonymous"

class ChatResponse(BaseModel):
    reply: str
    safe: bool
    audit_id: str

#API 端点
@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    """
    核心聊天接口：
    1. 提取用户输入
    2. 敏感信息脱敏
    3. 调用大模型（当前为模拟，可替换为真实API）
    4. 输出合规检测与拦截
    5. 记录审计日志
    """
    # 1. 提取用户输入（最后一条 role 为 user 的消息）
    user_input = ""
    for msg in request.messages:
        if msg.get("role") == "user":
            user_input = msg.get("content", "")
            break
    
    if not user_input:
        raise HTTPException(status_code=400, detail="未找到用户消息")
    
    # 2. 输入脱敏处理
    masked_input, pii_findings = await input_processor.process(user_input)
    
    # 记录输入处理审计事件
    audit_logger.log_event({
        "event_type": "input_processed",
        "user_id": request.user_id,
        "original_length": len(user_input),
        "masked_length": len(masked_input),
        "pii_findings": pii_findings
    })
    
    # 3. 调用大模型（此处使用模拟回复，实际可替换为 OpenAI / 内部模型）
    # TODO: 替换为真实的大模型 API 调用，传入 masked_input
    # 临时测试：如果用户输入包含“测试热加载”，则 AI 输出触发热加载规则的关键词
    if "测试热加载" in masked_input:
        ai_output = "测试热加载"
    else:
        ai_output = f"这是对「{masked_input}」的模拟回复。"
    
    # 4. 输出合规检测
    safe_output, is_safe, audit_info = await output_processor.process(ai_output)
    
    # 记录输出检测审计事件
    audit_logger.log_event({
        "event_type": "output_checked",
        "user_id": request.user_id,
        "is_safe": is_safe,
        "triggered_rules": audit_info.get("triggered_rules", []),
        "original_output_preview": ai_output[:200]   # 仅记录前200字符，保护隐私
    })
    
    # 5. 返回最终结果
    return ChatResponse(
        reply=safe_output,
        safe=is_safe,
        audit_id=audit_info.get("event_id", "")
    )


@app.get("/reports/risk")
async def get_risk_report(
    start_date: Optional[str] = Query(None, description="开始日期 ISO格式，如 2026-04-01"),
    end_date: Optional[str] = Query(None, description="结束日期 ISO格式"),
    format: str = Query("json", description="输出格式: json 或 text")
):
    """
    生成《企业AI安全使用及风险报告》
    - 统计周期内的交互总数、拦截次数、敏感信息分布、触发规则排名、高风险用户
    """
    # 解析日期范围
    if start_date:
        start = datetime.datetime.fromisoformat(start_date)
    else:
        start = datetime.datetime.utcnow() - datetime.timedelta(days=7)   # 默认最近7天
    if end_date:
        end = datetime.datetime.fromisoformat(end_date)
    else:
        end = datetime.datetime.utcnow()
    
    # 生成报告
    report_text = risk_reporter.generate_report(start, end, format=format)
    
    if format == "json":
        return JSONResponse(content=json.loads(report_text))
    else:
        return Response(content=report_text, media_type="text/plain; charset=utf-8")


@app.get("/health")
async def health_check():
    """健康检查接口"""
    return {"status": "healthy", "service": "AI Agent Gateway"}

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me-in-production")

@app.post("/admin/reload")
async def reload_rules(x_admin_token: str = Header(...)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")
    pii_filter.reload_rules()
    compliance_engine.reload_rules()
    return {"status": "Rules reloaded successfully", "message": "敏感信息和合规规则已热更新"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True   # 开发模式热重载，生产环境可改为 False
    )