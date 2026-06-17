from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import uuid

from app.db.database import get_db
from app.models.models import Project, Repo
from app.api.auth import require_role

router = APIRouter()


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


@router.get("/")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at).all()
    result = []
    for p in projects:
        repos = db.query(Repo).filter(Repo.project_id == p.id).all()
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        top_risk = min((r.risk_level for r in repos), key=lambda x: risk_order.get(x, 4), default="UNKNOWN")
        last_scanned = max((r.last_scanned_at for r in repos if r.last_scanned_at), default=None)
        result.append({
            "id":           p.id,
            "name":         p.name,
            "description":  p.description,
            "created_at":   p.created_at,
            "repo_count":   len(repos),
            "risk_level":   top_risk,
            "last_scanned_at": last_scanned,
        })
    return result


@router.post("/", status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db),
                   _session=Depends(require_role("admin"))):
    existing = db.query(Project).filter(Project.name == payload.name).first()
    if existing:
        raise HTTPException(400, f"Project '{payload.name}' already exists")
    project = Project(id=str(uuid.uuid4()), name=payload.name, description=payload.description)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/{project_id}")
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.get("/{project_id}/repos")
def get_project_repos(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    return db.query(Repo).filter(Repo.project_id == project_id).all()


@router.patch("/{project_id}")
def update_project(project_id: str, payload: ProjectUpdate,
                   db: Session = Depends(get_db),
                   _session=Depends(require_role("admin"))):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: str, db: Session = Depends(get_db),
                   _session=Depends(require_role("admin"))):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    # Unlink repos (don't delete them)
    db.query(Repo).filter(Repo.project_id == project_id).update({"project_id": None})
    db.delete(project)
    db.commit()
