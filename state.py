from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional

class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"

class AnalysisVerdict(Enum):
    VULNERABLE = "vulnerable"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNCERTAIN = "uncertain"
    ERROR_ENCOUNTERED = "error_encountered"

@dataclass
class HttpRequest:
    url: str
    name: Optional[str] = None
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    json_data: Optional[Dict[str, Any]] = None

@dataclass
class HttpResponse:
    status_code: int
    headers: Dict[str, str]
    content: str
    response_time: float
    error_message: Optional[str] = None

@dataclass
class AttemptDetail:
    payload: str
    response_status_code: int
    response_content_preview: str
    response_time: float
    llm_strategy_for_payload: Optional[str] = None
    response_error_message: Optional[str] = None
    analysis_verdict: Optional[AnalysisVerdict] = None
    analysis_confidence: Optional[float] = None
    analysis_reasoning: Optional[str] = None
    analysis_key_observations: List[str] = field(default_factory=list)

@dataclass
class PentestState:
    target_request: HttpRequest
    vulnerability_type: VulnerabilityType
    target_parameter: str
    max_total_attempts: int = 15
    target_parameter_baseline_value: Optional[str] = None
    current_attack_strategy_summary: Optional[str] = None
    consecutive_no_progress_attempts: int = 0
    max_consecutive_no_progress_per_strategy: int = 3
    current_payload_batch: List[str] = field(default_factory=list)
    current_payload_batch_index: int = 0
    current_payload: Optional[str] = None
    current_llm_payload_strategy: Optional[str] = None
    baseline_response: Optional[HttpResponse] = None
    current_response: Optional[HttpResponse] = None
    detailed_attempt_history: List[AttemptDetail] = field(default_factory=list)
    overall_attempt_count: int = 0
    individual_execution_count: int = 0
    vulnerabilities_found: List[Dict[str, Any]] = field(default_factory=list)
    final_report: Optional[str] = None
    stop_reason: Optional[str] = None
    executive_summary_verdict: Optional[str] = None
    executive_summary_reasoning: Optional[str] = None
    confidence_threshold_vulnerable: float = 0.85
    next_edge: Optional[str] = None

    def add_vulnerability_to_report(self, attempt: AttemptDetail):
        concise_reason = f"Payload '{attempt.payload}' led to '{attempt.analysis_verdict.value if attempt.analysis_verdict else 'N/A'}' verdict. Analyzer observed: {attempt.analysis_reasoning or 'No specific reasoning.'}"
        entry = {
            "vulnerability_type": self.vulnerability_type.value,
            "target_parameter": self.target_parameter,
            "payload": attempt.payload,
            "llm_strategy": attempt.llm_strategy_for_payload,
            "analysis_verdict": attempt.analysis_verdict.value if attempt.analysis_verdict else "N/A",
            "analysis_confidence": attempt.analysis_confidence,
            "analysis_reasoning": attempt.analysis_reasoning,
            "concise_reason_for_vulnerability": concise_reason,
            "response_status": attempt.response_status_code,
            "request_name": self.target_request.name or self.target_request.url
        }
        self.vulnerabilities_found.append(entry)
        if not self.executive_summary_verdict or self.executive_summary_verdict != "VULNERABLE":
            if attempt.analysis_verdict == AnalysisVerdict.VULNERABLE and \
               (attempt.analysis_confidence or 0.0) >= self.confidence_threshold_vulnerable:
                self.executive_summary_verdict = "VULNERABLE"
                self.executive_summary_reasoning = concise_reason

def verdict_str_to_enum(verdict: str) -> AnalysisVerdict:
    try:
        return AnalysisVerdict(verdict)
    except ValueError:
        verdict = verdict.lower()
        if "vulnerable" in verdict:
            return AnalysisVerdict.VULNERABLE
        elif "potential" in verdict:
            return AnalysisVerdict.POTENTIALLY_VULNERABLE
        elif "not" in verdict:
            return AnalysisVerdict.NOT_VULNERABLE
        elif "error" in verdict:
            return AnalysisVerdict.ERROR_ENCOUNTERED
        return AnalysisVerdict.UNCERTAIN