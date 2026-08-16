"""Normalized client data models."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from vorsyghta.config.models import SeniorityLevel, TechnicalLevel


class Employee(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str = ""
    email: str = ""
    name: str = ""
    role: str = ""
    department: str = ""
    seniority: SeniorityLevel = SeniorityLevel.MID
    technical_level: TechnicalLevel = TechnicalLevel.MODERATE
    manager: Optional[str] = None
    phone: Optional[str] = None
    location: Optional[str] = None
    company_name: Optional[str] = None
    interests: List[str] = Field(default_factory=list)
    security_awareness_level: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str = ""
    name: str = ""
    asset_type: str = ""
    ip_address: Optional[str] = None
    os: Optional[str] = None
    services: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    node_id: str = ""
    name: str = ""
    node_type: str = ""
    properties: Dict[str, Any] = Field(default_factory=dict)


class NetworkLink(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str
    target_id: str
    link_type: str = "ethernet"
    properties: Dict[str, Any] = Field(default_factory=dict)


class NetworkTopology(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = ""
    nodes: List[NetworkNode] = Field(default_factory=list)
    links: List[NetworkLink] = Field(default_factory=list)
    subnets: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Document(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str = ""
    name: str = ""
    path: str = ""
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None
    content_preview: Optional[str] = None
    last_modified: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ClientProfile(BaseModel):
    tenant_id: str
    name: str = ""
    employees: List[Employee] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    network_topology: Optional[NetworkTopology] = None
    documents: List[Document] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    synced_at: Optional[datetime] = None

    def get_employee_by_email(self, email: str) -> Optional[Employee]:
        email_lower = email.lower()
        for employee in self.employees:
            if employee.email.lower() == email_lower:
                return employee
        return None

    def get_employees_by_department(self, department: str) -> List[Employee]:
        department_lower = department.lower()
        return [e for e in self.employees if department_lower in e.department.lower()]


class SyncResult(BaseModel):
    source_name: str
    tenant_id: str
    status: str
    employees_count: int = 0
    assets_count: int = 0
    documents_count: int = 0
    errors: List[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
