import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from parser import JSParser, ExtractedEndpoint, ExtractedSecret, ExtractedFlag, ParseResult
from normalizer import SchemaNormalizer

app = FastAPI(
    title="JS API Extractor Engine",
    description="REST Service providing AST and Regex reverse-engineering of JavaScript assets into OpenAPI specifications, Secrets, and Feature Flags.",
    version="1.1.0"
)

parser = JSParser()
normalizer = SchemaNormalizer()

# In-memory session store
global_endpoints: List[ExtractedEndpoint] = []
global_secrets: List[ExtractedSecret] = []
global_flags: List[ExtractedFlag] = []

class ParseRequest(BaseModel):
    source: str
    url: Optional[str] = ""

class ParseResponse(BaseModel):
    status: str
    endpoint_count: int
    secret_count: int
    flag_count: int
    endpoints: List[ExtractedEndpoint]
    secrets: List[ExtractedSecret]
    flags: List[ExtractedFlag]

@app.get("/")
def health_check():
    return {"status": "ok", "service": "JS API Extractor Bridge"}

@app.post("/parse", response_model=ParseResponse)
def parse_javascript(req: ParseRequest):
    if not req.source:
        raise HTTPException(status_code=400, detail="JavaScript source code string is required.")
    
    result = parser.parse_code(req.source, source_url=req.url or "")
    
    # Store unique endpoints
    seen_ep = {f"{ep.method}:{ep.path}" for ep in global_endpoints}
    for ep in result.endpoints:
        key = f"{ep.method}:{ep.path}"
        if key not in seen_ep:
            seen_ep.add(key)
            global_endpoints.append(ep)

    # Store unique secrets
    seen_sec = {f"{s.secret_type}:{s.value}" for s in global_secrets}
    for s in result.secrets:
        key = f"{s.secret_type}:{s.value}"
        if key not in seen_sec:
            seen_sec.add(key)
            global_secrets.append(s)

    # Store unique flags
    seen_flg = {f"{f.flag_type}:{f.name}" for f in global_flags}
    for flg in result.flags:
        key = f"{flg.flag_type}:{flg.name}"
        if key not in seen_flg:
            seen_flg.add(key)
            global_flags.append(flg)

    return ParseResponse(
        status="success",
        endpoint_count=len(result.endpoints),
        secret_count=len(result.secrets),
        flag_count=len(result.flags),
        endpoints=result.endpoints,
        secrets=result.secrets,
        flags=result.flags
    )

@app.get("/endpoints", response_model=List[ExtractedEndpoint])
def get_endpoints():
    return global_endpoints

@app.get("/secrets", response_model=List[ExtractedSecret])
def get_secrets():
    return global_secrets

@app.get("/flags", response_model=List[ExtractedFlag])
def get_flags():
    return global_flags

@app.delete("/inventory")
def clear_inventory():
    global global_endpoints, global_secrets, global_flags
    global_endpoints = []
    global_secrets = []
    global_flags = []
    return {"status": "cleared"}

@app.get("/export/openapi")
def export_openapi():
    return normalizer.to_openapi(global_endpoints)

@app.get("/export/postman")
def export_postman():
    return normalizer.to_postman(global_endpoints)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
