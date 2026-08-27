from pydantic import BaseModel


class PromptCheckRequest(BaseModel):
    user_id: str
    prompt: str


class PromptCheckResponse(BaseModel):
    verdict: str            # "benign" | "suspected_injection" | "confirmed_injection"
    flagged_span: str | None
    reason: str


class PackageVerdict(BaseModel):
    package: str
    line_number: int
    full_statement: str
    verdict: str             # clean | unverified | typosquat | hallucinated | malicious
    reason: str
    source: str               # which tool/check produced the verdict


class CodeScanResponse(BaseModel):
    results: list[PackageVerdict]


class AuditEvent(BaseModel):
    id: int
    user_id: str
    timestamp: str
    scan_type: str
    verdict: str
    flagged_item: str | None
    reason: str | None
    severity: str


class UserSummary(BaseModel):
    user_id: str
    total_flags: int
    high_severity_count: int
    last_flag_at: str
