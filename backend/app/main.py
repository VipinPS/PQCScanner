from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import repos, scans, findings, cbom, reports, playbooks, auth, secrets, projects, artifacts, network, cicd, runtime
from app.db.database import engine, Base, run_migrations
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

Base.metadata.create_all(bind=engine)
run_migrations()

app = FastAPI(
    title="PQCScanner API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    swagger_ui_parameters={"persistAuthorization": True},
)
app.add_middleware(CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000",
                   "http://9.30.219.14:5173", "http://9.30.219.14:3000",
                   "http://9.30.219.14:8000"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

app.include_router(auth.router,       prefix="/api/auth",      tags=["Auth"])
app.include_router(repos.router,      prefix="/api/repos",     tags=["Repos"])
app.include_router(scans.router,      prefix="/api/scans",     tags=["Scans"])
app.include_router(findings.router,   prefix="/api/findings",  tags=["Findings"])
app.include_router(cbom.router,       prefix="/api/cbom",      tags=["CBOM"])
app.include_router(reports.router,    prefix="/api/reports",   tags=["Reports"])
app.include_router(playbooks.router,  prefix="/api/playbooks", tags=["Playbooks"])
app.include_router(secrets.router,    prefix="/api/secrets",   tags=["Secrets"])
app.include_router(projects.router,   prefix="/api/projects",  tags=["Projects"])
app.include_router(artifacts.router,  prefix="/api/artifacts", tags=["Artifacts"])
app.include_router(network.router,    prefix="/api/network",   tags=["Network"])
app.include_router(cicd.router,       prefix="/api/cicd",      tags=["CICD"])
app.include_router(runtime.router,    prefix="/api/runtime",   tags=["Runtime Agent"])

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "pqc-platform", "version": "2.0.0"}
