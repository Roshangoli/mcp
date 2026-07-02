import json
from typing import Optional, Any, Dict


class AuditLogger:
    def __init__(self, database):
        self.db = database

    def log_tool_call(self, tool_name: str, company_id: Optional[int],
                     user_email: Optional[str], role: Optional[str],
                     input_params: Dict[str, Any], success: bool,
                     result: Any, error: Optional[str] = None,
                     execution_time_ms: Optional[float] = None,
                     result_count: Optional[int] = None,
                     session_id: Optional[str] = None) -> int:
        sanitized_params = self._sanitize_params(input_params)
        params_json = json.dumps(sanitized_params)

        # Redact secrets from result if necessary
        result_text = ""
        if error:
            result_text = f"ERROR: {error}"
        elif tool_name == "rotate_api_key" and isinstance(result, str):
            # Special case: Mask the new API key in logs
            result_text = "API key rotated successfully (new key redacted from logs)"
        elif isinstance(result, str):
            result_text = result[:500]  # Limit length
        elif isinstance(result, dict):
            result_text = json.dumps(result)[:500]
        else:
            result_text = str(result)[:500]

        log_id = self.db.create_audit_log(
            tool_name=tool_name,
            company_id=company_id,
            user_email=user_email,
            role=role,
            input_params=params_json,
            result=result_text,
            success=success,
            execution_time_ms=execution_time_ms,
            result_count=result_count,
            session_id=session_id
        )

        return log_id

    def log_authentication_failure(self, tool_name: str, error: str) -> int:
        return self.log_tool_call(
            tool_name=tool_name,
            company_id=None,
            user_email=None,
            role=None,
            input_params={"error": "authentication_failed"},
            success=False,
            result=None,
            error=error
        )

    def log_authorization_failure(self, tool_name: str, user_email: str,
                                  role: str, error: str) -> int:
        return self.log_tool_call(
            tool_name=tool_name,
            company_id=None,
            user_email=user_email,
            role=role,
            input_params={"error": "authorization_failed"},
            success=False,
            result=None,
            error=error
        )

    def log_rate_limit_exceeded(self, tool_name: str, user_email: str) -> int:
        return self.log_tool_call(
            tool_name=tool_name,
            company_id=None,
            user_email=user_email,
            role=None,
            input_params={"error": "rate_limit_exceeded"},
            success=False,
            result=None,
            error="Rate limit exceeded"
        )

    def log_validation_error(self, tool_name: str, company_id: Optional[int],
                            user_email: str, role: str,
                            input_params: Dict[str, Any], error: str) -> int:
        return self.log_tool_call(
            tool_name=tool_name,
            company_id=company_id,
            user_email=user_email,
            role=role,
            input_params=input_params,
            success=False,
            result=None,
            error=error
        )

    @staticmethod
    def _sanitize_params(params: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = params.copy()

        # Enhanced API key masking (first4****last4 format)
        if "api_key" in sanitized and isinstance(sanitized["api_key"], str):
            key = sanitized["api_key"]
            if len(key) > 12:
                # Show first 4 and last 4 characters
                sanitized["api_key"] = key[:4] + "****" + key[-4:]
            elif len(key) > 4:
                # Show first 4 only
                sanitized["api_key"] = key[:4] + "****"
            else:
                # Too short, mask completely
                sanitized["api_key"] = "****"

        return sanitized

    def get_recent_logs(self, company_id: Optional[int] = None,
                       limit: int = 50) -> str:
        logs = self.db.get_audit_logs(company_id=company_id, limit=limit)

        if not logs:
            return "No audit logs found"

        output = []
        output.append("=== RECENT AUDIT LOGS ===\n")

        for log in logs:
            output.append(f"[{log['timestamp']}]")
            output.append(f"  Tool: {log['tool_name']}")
            output.append(f"  User: {log['user_email'] or 'N/A'} (Role: {log['role'] or 'N/A'})")
            output.append(f"  Company ID: {log['company_id'] or 'N/A'}")
            output.append(f"  Success: {log['success']}")
            output.append(f"  Result: {log['result'][:100]}...")
            output.append("")

        return "\n".join(output)


def create_audit_logger(database):
    return AuditLogger(database)
