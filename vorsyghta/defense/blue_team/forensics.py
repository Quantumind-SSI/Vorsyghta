"""Digital Forensics Collection.

Forensic evidence collection, memory capture, disk imaging,
and timeline reconstruction for incident investigation.
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ForensicArtifact:
    """A piece of forensic evidence."""
    artifact_id: str
    artifact_type: str  # disk_image, memory_dump, log_capture, file_copy, registry_dump, network_capture
    source: str
    path: str
    size: int = 0
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    collected_at: str = ""
    collected_by: str = "vorsyghta"
    chain_of_custody: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ForensicTimelineEntry:
    """An entry in the forensic timeline."""
    timestamp: str
    event: str
    source: str
    details: str
    artifact_id: Optional[str] = None
    mitre_technique: Optional[str] = None


class ForensicsCollector:
    """Digital forensics collection and timeline reconstruction.

    Provides:
        - Evidence collection tracking with chain of custody
        - Disk image and memory dump metadata management
        - File hash calculation for integrity verification
        - Forensic timeline reconstruction from multiple sources
        - Evidence packaging for handoff

    Example:
        forensics = ForensicsCollector()
        artifact = forensics.collect_file("/var/log/auth.log", "web-server-01")
        timeline = forensics.build_timeline(log_entries)
    """

    def __init__(self, case_id: Optional[str] = None):
        self.case_id = case_id or f"CASE-{datetime.utcnow().strftime('%Y%m%d')}"
        self._artifacts: List[ForensicArtifact] = []
        self._timeline: List[ForensicTimelineEntry] = []
        self._artifact_counter = 0

    def collect_file(
        self,
        file_path: str,
        source: str,
        artifact_type: str = "file_copy",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ForensicArtifact:
        """Collect a file as forensic evidence."""
        self._artifact_counter += 1
        artifact_id = f"FA-{self.case_id}-{self._artifact_counter:04d}"

        size = 0
        hash_md5 = None
        hash_sha256 = None

        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            hash_md5, hash_sha256 = self._calculate_hashes(file_path)

        artifact = ForensicArtifact(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            source=source,
            path=file_path,
            size=size,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            collected_at=datetime.utcnow().isoformat(),
            metadata=metadata or {},
        )

        artifact.chain_of_custody.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "collected",
            "actor": "vorsyghta-forensics",
            "detail": f"File collected from {source}",
        })

        self._artifacts.append(artifact)
        return artifact

    def register_disk_image(
        self,
        image_path: str,
        source_host: str,
        image_type: str = "raw",
        size: int = 0,
        hash_sha256: Optional[str] = None,
    ) -> ForensicArtifact:
        """Register a disk image as evidence."""
        self._artifact_counter += 1
        artifact_id = f"FA-{self.case_id}-{self._artifact_counter:04d}"

        artifact = ForensicArtifact(
            artifact_id=artifact_id,
            artifact_type="disk_image",
            source=source_host,
            path=image_path,
            size=size,
            hash_sha256=hash_sha256,
            collected_at=datetime.utcnow().isoformat(),
            metadata={"image_type": image_type},
        )

        artifact.chain_of_custody.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "disk image created",
            "actor": "vorsyghta-forensics",
            "detail": f"Disk image of {source_host} ({image_type} format)",
        })

        self._artifacts.append(artifact)
        return artifact

    def register_memory_dump(
        self,
        dump_path: str,
        source_host: str,
        size: int = 0,
        hash_sha256: Optional[str] = None,
    ) -> ForensicArtifact:
        """Register a memory dump as evidence."""
        self._artifact_counter += 1
        artifact_id = f"FA-{self.case_id}-{self._artifact_counter:04d}"

        artifact = ForensicArtifact(
            artifact_id=artifact_id,
            artifact_type="memory_dump",
            source=source_host,
            path=dump_path,
            size=size,
            hash_sha256=hash_sha256,
            collected_at=datetime.utcnow().isoformat(),
            metadata={"dump_tool": "unknown"},
        )

        artifact.chain_of_custody.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "memory dump created",
            "actor": "vorsyghta-forensics",
            "detail": f"Memory dump of {source_host}",
        })

        self._artifacts.append(artifact)
        return artifact

    def register_network_capture(
        self,
        capture_path: str,
        source_host: str,
        duration: int = 0,
        size: int = 0,
    ) -> ForensicArtifact:
        """Register a network capture (PCAP) as evidence."""
        self._artifact_counter += 1
        artifact_id = f"FA-{self.case_id}-{self._artifact_counter:04d}"

        artifact = ForensicArtifact(
            artifact_id=artifact_id,
            artifact_type="network_capture",
            source=source_host,
            path=capture_path,
            size=size,
            collected_at=datetime.utcnow().isoformat(),
            metadata={"duration_seconds": duration, "format": "pcap"},
        )

        artifact.chain_of_custody.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "network capture created",
            "actor": "vorsyghta-forensics",
            "detail": f"Network capture on {source_host} for {duration}s",
        })

        self._artifacts.append(artifact)
        return artifact

    def add_timeline_entry(
        self,
        timestamp: str,
        event: str,
        source: str,
        details: str,
        artifact_id: Optional[str] = None,
        mitre_technique: Optional[str] = None,
    ) -> ForensicTimelineEntry:
        """Add an entry to the forensic timeline."""
        entry = ForensicTimelineEntry(
            timestamp=timestamp,
            event=event,
            source=source,
            details=details,
            artifact_id=artifact_id,
            mitre_technique=mitre_technique,
        )
        self._timeline.append(entry)
        return entry

    def build_timeline_from_logs(
        self,
        log_entries: List[Dict[str, Any]],
    ) -> List[ForensicTimelineEntry]:
        """Build a forensic timeline from log entries."""
        for entry in log_entries:
            self.add_timeline_entry(
                timestamp=entry.get("timestamp", datetime.utcnow().isoformat()),
                event=entry.get("event", "log_entry"),
                source=entry.get("source", "unknown"),
                details=entry.get("message", entry.get("details", str(entry))),
                mitre_technique=entry.get("mitre_technique"),
            )

        self._timeline.sort(key=lambda e: e.timestamp)
        return self._timeline

    def get_timeline(
        self,
        start: Optional[str] = None,
        end: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[ForensicTimelineEntry]:
        """Get filtered forensic timeline."""
        entries = self._timeline

        if start:
            entries = [e for e in entries if e.timestamp >= start]
        if end:
            entries = [e for e in entries if e.timestamp <= end]
        if source:
            entries = [e for e in entries if e.source == source]

        entries.sort(key=lambda e: e.timestamp)
        return entries

    def transfer_custody(
        self,
        artifact_id: str,
        to_actor: str,
        reason: str = "",
    ) -> bool:
        """Transfer chain of custody for an artifact."""
        artifact = next((a for a in self._artifacts if a.artifact_id == artifact_id), None)
        if not artifact:
            return False

        artifact.chain_of_custody.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "custody transfer",
            "actor": to_actor,
            "detail": reason or f"Custody transferred to {to_actor}",
        })
        return True

    def verify_integrity(self, artifact_id: str) -> Dict[str, Any]:
        """Verify the integrity of a collected artifact."""
        artifact = next((a for a in self._artifacts if a.artifact_id == artifact_id), None)
        if not artifact:
            return {"status": "error", "message": "Artifact not found"}

        if not os.path.exists(artifact.path):
            return {"status": "error", "message": "File not found at path"}

        current_md5, current_sha256 = self._calculate_hashes(artifact.path)

        md5_match = artifact.hash_md5 == current_md5 if artifact.hash_md5 else None
        sha256_match = artifact.hash_sha256 == current_sha256 if artifact.hash_sha256 else None

        return {
            "status": "ok" if md5_match and sha256_match else "mismatch",
            "artifact_id": artifact_id,
            "original_md5": artifact.hash_md5,
            "current_md5": current_md5,
            "md5_match": md5_match,
            "original_sha256": artifact.hash_sha256,
            "current_sha256": current_sha256,
            "sha256_match": sha256_match,
        }

    def _calculate_hashes(self, file_path: str) -> tuple:
        """Calculate MD5 and SHA256 hashes of a file."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation failed for {file_path}: {e}")
            return None, None

    def get_artifacts(self, artifact_type: Optional[str] = None) -> List[ForensicArtifact]:
        if artifact_type:
            return [a for a in self._artifacts if a.artifact_type == artifact_type]
        return list(self._artifacts)

    def get_artifact(self, artifact_id: str) -> Optional[ForensicArtifact]:
        return next((a for a in self._artifacts if a.artifact_id == artifact_id), None)

    def get_stats(self) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        total_size = 0

        for a in self._artifacts:
            type_counts[a.artifact_type] = type_counts.get(a.artifact_type, 0) + 1
            total_size += a.size

        return {
            "case_id": self.case_id,
            "total_artifacts": len(self._artifacts),
            "total_timeline_entries": len(self._timeline),
            "by_type": type_counts,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generate a forensic case report."""
        return {
            "case_id": self.case_id,
            "generated_at": datetime.utcnow().isoformat(),
            "artifacts": [
                {
                    "artifact_id": a.artifact_id,
                    "type": a.artifact_type,
                    "source": a.source,
                    "path": a.path,
                    "size": a.size,
                    "hash_md5": a.hash_md5,
                    "hash_sha256": a.hash_sha256,
                    "collected_at": a.collected_at,
                    "chain_of_custody": a.chain_of_custody,
                    "metadata": a.metadata,
                }
                for a in self._artifacts
            ],
            "timeline": [
                {
                    "timestamp": e.timestamp,
                    "event": e.event,
                    "source": e.source,
                    "details": e.details,
                    "artifact_id": e.artifact_id,
                    "mitre_technique": e.mitre_technique,
                }
                for e in self._timeline
            ],
            "stats": self.get_stats(),
        }
