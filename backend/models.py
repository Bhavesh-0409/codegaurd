from pydantic import BaseModel


class PromptCheckRequest(BaseModel):
    user_id: str
    prompt: str


class PromptCheckResponse(BaseModel):
    security_status: str       # "safe" | "malicious"
    scope_status: str          # "in_scope" | "out_of_scope"
    reasoning_notes: str
    response_output: str | None = None


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


class FixRequest(BaseModel):
    vulnerable_code: str
    file_name: str | None = None


class FixResponse(BaseModel):
    patched_code: str
