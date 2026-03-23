import os, time, json, logging
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s terraguard %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("terraguard")

app = FastAPI(title="TerraGuard", version="1.0.0")
client = AsyncOpenAI(
    api_key=os.environ["DEEPSEEK_API_KEY"],
    base_url="https://api.deepseek.com",
)

PROXY_SECRET = os.environ.get("TERRAGUARD_PROXY_SECRET", "")
MAX_LEN = 8000

ANALYZE_SYSTEM = """You are a senior cloud security engineer specializing in Terraform and IaC security.
Analyze the provided Terraform HCL code or diff and identify security issues.

Return ONLY a JSON object with this exact structure, no markdown:
{
  "summary": "One sentence summary of overall security posture",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "issues": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "IAM|NETWORK|ENCRYPTION|SECRETS|LOGGING|COMPLIANCE|OTHER",
      "title": "Short title",
      "description": "What the issue is and why it matters",
      "resource": "resource type and name if identifiable",
      "recommendation": "Specific fix"
    }
  ],
  "passed_checks": ["List of security best practices correctly implemented"],
  "total_issues": 0
}

Focus on: overly permissive IAM (wildcards, admin), Security Groups open to 0.0.0.0/0,
unencrypted storage, public access on private resources, missing logging,
insecure protocols, hardcoded secrets, missing MFA, overly broad CIDRs."""

SECRETS_SYSTEM = """You are a secrets detection expert for Terraform HCL code.
Scan the provided code and identify hardcoded secrets, credentials, or sensitive values.

Return ONLY a JSON object with this exact structure, no markdown:
{
  "secrets_found": false,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "type": "API_KEY|PASSWORD|TOKEN|CERTIFICATE|CONNECTION_STRING|OTHER",
      "description": "What was found",
      "location": "variable or resource name where found",
      "recommendation": "How to fix using variables, SSM, Vault, etc."
    }
  ],
  "total_findings": 0,
  "remediation_summary": "Overall advice for secrets management in this codebase"
}"""


class HCLRequest(BaseModel):
    hcl: str


def check_secret(request: Request):
    if PROXY_SECRET and request.headers.get("x-rapidapi-proxy-secret") != PROXY_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "terraguard"}


@app.post("/analyze")
async def analyze(body: HCLRequest, request: Request):
    check_secret(request)
    hcl = body.hcl[:MAX_LEN]
    log.info(f"analyze hcl_len={len(hcl)}")
    t0 = time.monotonic()
    resp = await client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": ANALYZE_SYSTEM},
            {"role": "user", "content": f"Analyze this Terraform HCL:\n\n{hcl}"},
        ],
        temperature=0.1,
        max_tokens=2000,
    )
    elapsed = time.monotonic() - t0
    raw = resp.choices[0].message.content.strip()
    log.info(f"analyze done elapsed={elapsed:.3f}s")
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


@app.post("/secrets")
async def secrets(body: HCLRequest, request: Request):
    check_secret(request)
    hcl = body.hcl[:MAX_LEN]
    log.info(f"secrets hcl_len={len(hcl)}")
    t0 = time.monotonic()
    resp = await client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": SECRETS_SYSTEM},
            {"role": "user", "content": f"Scan for secrets in this Terraform HCL:\n\n{hcl}"},
        ],
        temperature=0.1,
        max_tokens=1500,
    )
    elapsed = time.monotonic() - t0
    raw = resp.choices[0].message.content.strip()
    log.info(f"secrets done elapsed={elapsed:.3f}s")
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}
