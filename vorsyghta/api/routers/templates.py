"""Simulation templates API router for Vorsyghta.

Lists and loads threat simulation templates from the filesystem,
including the ZestPayment payment-specific templates.

Endpoints:
    GET  /api/templates                — list all available templates
    GET  /api/templates/{category}     — list templates in a category
    GET  /api/templates/{category}/{name} — get a specific template
    POST /api/templates/load           — load a template into a scenario
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vorsyghta.security.rbac import CurrentUser, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/templates", tags=["Simulation Templates"])

# =============================================================================
# Configuration
# =============================================================================

_TEMPLATES_DIR = Path(os.getenv(
    "VORSYGHTA_TEMPLATES_DIR",
    str(Path(__file__).resolve().parents[3] / "templates"),
))


def _find_templates_dir() -> Path:
    """Locate the templates directory.

    Checks several candidate locations:
    1. VORSYGHTA_TEMPLATES_DIR env var
    2. /app/templates (Docker container)
    3. Repo root /templates
    """
    candidates = [
        _TEMPLATES_DIR,
        Path("/app/templates"),
        Path.cwd() / "templates",
        Path(__file__).resolve().parents[3] / "templates",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return _TEMPLATES_DIR


def _load_yaml_template(path: Path) -> Dict[str, Any]:
    """Load a YAML template file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def _extract_template_metadata(
    data: Dict[str, Any],
    path: Path,
    category: str,
) -> Dict[str, Any]:
    """Extract metadata from a template for listing."""
    meta = data.get("metadata", {})
    return {
        "name": meta.get("name", path.stem),
        "file": path.name,
        "category": category,
        "description": meta.get("description", ""),
        "version": meta.get("version", "1.0.0"),
        "tags": meta.get("tags", []),
        "threat_type": data.get("threat_type", "custom"),
        "difficulty_level": data.get("difficulty_level"),
        "estimated_duration": data.get("estimated_duration"),
        "references": meta.get("references", []),
        "path": str(path.relative_to(_find_templates_dir())),
    }


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/")
async def list_templates(
    current_user: CurrentUser = Depends(get_current_user),
):
    """List all available simulation templates, grouped by category."""
    templates_dir = _find_templates_dir()
    if not templates_dir.is_dir():
        return {"categories": {}, "total": 0}

    categories: Dict[str, List[Dict[str, Any]]] = {}
    total = 0

    for yaml_file in sorted(templates_dir.rglob("*.yaml")):
        # Skip non-template files (e.g., docker-compose, k8s manifests)
        if yaml_file.name in ("docker-compose.yml", "docker-compose.yaml"):
            continue
        if any(part.startswith(".") for part in yaml_file.parts):
            continue

        # Category is the subdirectory name, or "root" if at top level
        try:
            rel = yaml_file.relative_to(templates_dir)
            category = rel.parts[0] if len(rel.parts) > 1 else "root"
        except ValueError:
            category = "root"

        try:
            data = _load_yaml_template(yaml_file)
            if not isinstance(data, dict) or "metadata" not in data:
                continue
            meta = _extract_template_metadata(data, yaml_file, category)
            categories.setdefault(category, []).append(meta)
            total += 1
        except Exception as e:
            logger.warning(f"Failed to load template {yaml_file}: {e}")

    return {
        "categories": categories,
        "total": total,
    }


@router.get("/{category}")
async def list_templates_by_category(
    category: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List templates in a specific category (e.g., 'sanctioned_targets', 'root')."""
    templates_dir = _find_templates_dir()

    # "root" is a virtual category for templates at the top level
    if category == "root":
        category_dir = templates_dir
    else:
        category_dir = templates_dir / category

    if not category_dir.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template category '{category}' not found",
        )

    templates = []
    for yaml_file in sorted(category_dir.glob("*.yaml")):
        try:
            data = _load_yaml_template(yaml_file)
            if not isinstance(data, dict):
                continue
            meta = _extract_template_metadata(data, yaml_file, category)
            templates.append(meta)
        except Exception as e:
            logger.warning(f"Failed to load template {yaml_file}: {e}")

    return {
        "category": category,
        "total": len(templates),
        "templates": templates,
    }


@router.get("/{category}/{name}")
async def get_template(
    category: str,
    name: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get the full content of a specific template."""
    templates_dir = _find_templates_dir()

    # "root" is a virtual category for templates at the top level
    if category == "root":
        category_dir = templates_dir
    else:
        category_dir = templates_dir / category

    # Try exact name, then with .yaml extension
    candidates = [
        category_dir / name,
        category_dir / f"{name}.yaml",
        category_dir / f"{name}.yml",
    ]

    for path in candidates:
        if path.is_file():
            try:
                data = _load_yaml_template(path)
                return {
                    "category": category,
                    "file": path.name,
                    "content": data,
                }
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to load template: {e}",
                )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Template '{category}/{name}' not found",
    )


class LoadTemplateRequest(BaseModel):
    """Request to load a template into a ThreatScenario."""
    category: str = Field(..., description="Template category")
    name: str = Field(..., description="Template name (without .yaml)")


@router.post("/load")
async def load_template_to_scenario(
    request: LoadTemplateRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Load a template and convert it to a ThreatScenario structure.

    Returns the scenario data ready to be passed to the exercise runner
    or simulation endpoint.
    """
    templates_dir = _find_templates_dir()

    # "root" is a virtual category for templates at the top level
    if request.category == "root":
        category_dir = templates_dir
    else:
        category_dir = templates_dir / request.category

    candidates = [
        category_dir / request.name,
        category_dir / f"{request.name}.yaml",
    ]

    for path in candidates:
        if path.is_file():
            try:
                data = _load_yaml_template(path)
                meta = data.get("metadata", {})

                # Map template to ThreatScenario fields
                from vorsyghta.core.models import ThreatType

                threat_type_str = data.get("threat_type", "custom")
                try:
                    threat_type = ThreatType(threat_type_str)
                except ValueError:
                    threat_type = ThreatType.CUSTOM

                scenario = {
                    "name": meta.get("name", path.stem),
                    "threat_type": threat_type.value,
                    "description": meta.get("description", ""),
                    "severity": data.get("severity", "medium"),
                    "target_systems": data.get("target_profile", {}).get("target_systems", []),
                    "attack_vectors": data.get("attack_vectors", []),
                    "metadata": {
                        "template_file": str(path.relative_to(templates_dir)),
                        "tags": meta.get("tags", []),
                        "difficulty_level": data.get("difficulty_level"),
                        "estimated_duration": data.get("estimated_duration"),
                        "references": meta.get("references", []),
                        "compliance": data.get("compliance", {}),
                    },
                }

                return {
                    "scenario": scenario,
                    "template": _extract_template_metadata(data, path, request.category),
                }
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to load template: {e}",
                )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Template '{request.category}/{request.name}' not found",
    )
