from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Repo
from app.api.auth import require_role
from pydantic import BaseModel
from typing import Optional
import uuid, logging

logger = logging.getLogger(__name__)

router = APIRouter()

class RepoCreate(BaseModel):
    name: str
    url: str
    provider: str = "github"
    language: Optional[str] = None
    branch: str = "main"
    project_id: Optional[str] = None

@router.get("/")
def list_repos(project_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Repo)
    if project_id:
        q = q.filter(Repo.project_id == project_id)
    return q.all()

@router.post("/", status_code=201)
def add_repo(payload: RepoCreate, db: Session = Depends(get_db),
             _session = Depends(require_role("admin"))):
    existing = db.query(Repo).filter(Repo.url == payload.url).first()
    if existing:
        # Repo already exists — just assign to project if requested
        if payload.project_id and existing.project_id != payload.project_id:
            existing.project_id = payload.project_id
            db.commit()
            db.refresh(existing)
        return existing
    repo = Repo(id=str(uuid.uuid4()), **payload.dict())
    db.add(repo); db.commit(); db.refresh(repo)
    return repo

class RepoUpdate(BaseModel):
    name: Optional[str] = None
    branch: Optional[str] = None
    provider: Optional[str] = None

@router.patch("/{repo_id}")
def update_repo(repo_id: str, payload: RepoUpdate, db: Session = Depends(get_db),
                _session = Depends(require_role("admin"))):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")
    for field, value in payload.dict(exclude_none=True).items():
        setattr(repo, field, value)
    db.commit()
    db.refresh(repo)
    return repo

@router.patch("/{repo_id}/project")
def assign_repo_project(repo_id: str, payload: dict,
                        db: Session = Depends(get_db),
                        _session=Depends(require_role("admin"))):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")
    repo.project_id = payload.get("project_id")
    db.commit()
    db.refresh(repo)
    return repo

@router.get("/{repo_id}")
def get_repo(repo_id: str, db: Session = Depends(get_db)):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo: raise HTTPException(404, "Repo not found")
    return repo

@router.delete("/{repo_id}", status_code=204)
def delete_repo(repo_id: str, db: Session = Depends(get_db),
                _session = Depends(require_role("admin"))):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")

    repo_name = repo.name
    db.delete(repo)
    db.commit()
    logger.info(f"Repo '{repo_name}' deleted — rebuilding CBOM")

    # Rebuild CBOM immediately so deleted repo's algorithms are removed
    try:
        from app.api.scans import rebuild_cbom
        rebuild_cbom(db)
    except Exception as e:
        # Non-fatal — CBOM will self-correct on next scan
        logger.warning(f"CBOM rebuild after delete failed: {e}")
