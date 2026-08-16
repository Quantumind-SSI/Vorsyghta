"""Vorsyghta Attack Scenario-to-Flow Mapper.

Maps Vorsyghta YAML scenarios to Vorsyghta Attack flow parameters.
Translates MITRE ATT&CK techniques to Vorsyghta Attack task descriptions.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# MITRE ATT&CK technique to Vorsyghta Attack task description mapping
MITRE_TO_ATTACK_TASKS: Dict[str, Dict[str, str]] = {
    "T1595": {
        "task_name": "Network Scanning",
        "description": "Perform active network scanning to discover live hosts and open ports using nmap and masscan.",
        "agent_type": "executor",
    },
    "T1595.001": {
        "task_name": "IP Block Scanning",
        "description": "Scan the target network range for live hosts using nmap and masscan.",
        "agent_type": "executor",
    },
    "T1592": {
        "task_name": "Gather Target Host Information",
        "description": "Collect information about the target system including OS, software versions, and configurations.",
        "agent_type": "researcher",
    },
    "T1589": {
        "task_name": "Gather Target Identity Information",
        "description": "Collect email addresses, usernames, and credentials from OSINT sources.",
        "agent_type": "researcher",
    },
    "T1566": {
        "task_name": "Phishing for Initial Access",
        "description": "Craft and simulate phishing attacks to gain initial access to target systems.",
        "agent_type": "developer",
    },
    "T1566.001": {
        "task_name": "Spear-Phishing Attachment",
        "description": "Create and deliver spear-phishing attachments for initial access.",
        "agent_type": "developer",
    },
    "T1566.002": {
        "task_name": "Spear-Phishing Link",
        "description": "Create and deliver spear-phishing links for initial access.",
        "agent_type": "developer",
    },
    "T1190": {
        "task_name": "Exploit Public-Facing Application",
        "description": "Exploit vulnerabilities in public-facing web applications using sqlmap, nuclei, and manual techniques.",
        "agent_type": "executor",
    },
    "T1059": {
        "task_name": "Command and Scripting Interpreter",
        "description": "Execute commands and scripts on compromised systems for lateral movement and persistence.",
        "agent_type": "executor",
    },
    "T1059.004": {
        "task_name": "Unix Shell Execution",
        "description": "Execute Unix shell commands on compromised Linux systems.",
        "agent_type": "executor",
    },
    "T1110": {
        "task_name": "Brute Force Credentials",
        "description": "Use hydra and other tools to brute-force credentials on discovered services.",
        "agent_type": "executor",
    },
    "T1110.001": {
        "task_name": "Password Guessing",
        "description": "Attempt password guessing against discovered services using hydra.",
        "agent_type": "executor",
    },
    "T1212": {
        "task_name": "Exploitation for Credential Access",
        "description": "Exploit vulnerabilities to access credentials on target systems.",
        "agent_type": "executor",
    },
    "T1078": {
        "task_name": "Valid Accounts Usage",
        "description": "Use compromised credentials to access target systems and escalate privileges.",
        "agent_type": "executor",
    },
    "T1068": {
        "task_name": "Exploitation for Privilege Escalation",
        "description": "Exploit vulnerabilities to escalate privileges on compromised systems.",
        "agent_type": "executor",
    },
    "T1003": {
        "task_name": "Credential Dumping",
        "description": "Dump credentials from compromised systems using mimikatz and other tools.",
        "agent_type": "executor",
    },
    "T1087": {
        "task_name": "Account Discovery",
        "description": "Discover user and group accounts on target systems for lateral movement planning.",
        "agent_type": "researcher",
    },
    "T1046": {
        "task_name": "Network Service Discovery",
        "description": "Discover network services using nmap and other scanning tools.",
        "agent_type": "researcher",
    },
    "T1049": {
        "task_name": "System Network Connections",
        "description": "Monitor and discover network connections on compromised systems.",
        "agent_type": "researcher",
    },
    "T1057": {
        "task_name": "Process Discovery",
        "description": "Discover running processes on target systems for situational awareness.",
        "agent_type": "researcher",
    },
    "T1083": {
        "task_name": "File and Directory Discovery",
        "description": "Discover files and directories on target systems for data collection.",
        "agent_type": "researcher",
    },
    "T1005": {
        "task_name": "Data Collection from Local System",
        "description": "Collect sensitive data from compromised systems.",
        "agent_type": "executor",
    },
    "T1041": {
        "task_name": "Exfiltration Over C2 Channel",
        "description": "Exfiltrate collected data through established C2 channels.",
        "agent_type": "executor",
    },
    "T1071": {
        "task_name": "Application Layer Protocol C2",
        "description": "Establish command and control using application layer protocols.",
        "agent_type": "developer",
    },
}


class AttackMapper:
    """Maps Vorsyghta scenarios to Vorsyghta Attack flow parameters.

    Translates Vorsyghta's YAML scenario definitions into Vorsyghta Attack flow
    descriptions, task lists, and parameters that Vorsyghta Attack's multi-agent
    system can execute autonomously.

    Example:
        mapper = AttackMapper()
        flow_params = mapper.scenario_to_flow(
            scenario={
                "name": "Web App Pentest",
                "threat_type": "web_exploitation",
                "mitre_techniques": ["T1190", "T1110"],
                "target": {"url": "http://10.0.100.10"},
            },
            target_info={"ip": "10.0.100.10", "services": ["http"]},
        )
    """

    def __init__(self):
        self.mitre_mapping = MITRE_TO_ATTACK_TASKS

    def scenario_to_flow(
        self,
        scenario: Dict[str, Any],
        target_info: Dict[str, Any],
        payloads: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Convert a Vorsyghta scenario to Vorsyghta Attack flow parameters.

        Args:
            scenario: Vorsyghta scenario dict from YAML template
            target_info: Target environment information
            payloads: Optional LLM-generated threat content (phishing emails,
                pretext scripts, web pages, etc.) to arm Vorsyghta Attack agents with

        Returns:
            Dict with Vorsyghta Attack flow parameters:
                - name: Flow name
                - description: Flow description for Vorsyghta Attack agents
                - target: Target URL or IP
                - parameters: Additional parameters (includes payloads if provided)
        """
        scenario_name = scenario.get("name", "Unnamed Scenario")
        threat_type = scenario.get("threat_type", "penetration_test")
        mitre_techniques = scenario.get("mitre_techniques", [])
        difficulty = scenario.get("difficulty", 5)
        objectives = scenario.get("objectives", [])

        target_url = self._extract_target_url(scenario, target_info)

        description = self._build_flow_description(
            scenario_name, threat_type, mitre_techniques, objectives, difficulty, target_info
        )

        parameters = {
            "mitre_techniques": mitre_techniques,
            "difficulty": difficulty,
            "objectives": objectives,
            "target_info": target_info,
            "scenario_name": scenario_name,
            "threat_type": threat_type,
        }

        if "scope" in scenario:
            parameters["scope"] = scenario["scope"]
        if "exclusions" in scenario:
            parameters["exclusions"] = scenario["exclusions"]
        if "max_duration_minutes" in scenario:
            parameters["timeout_minutes"] = scenario["max_duration_minutes"]

        if payloads:
            parameters["payloads"] = payloads
            payload_summary = self._summarize_payloads(payloads)
            if payload_summary:
                description += f"\n\nCustom Payloads Available:\n{payload_summary}"

        return {
            "name": f"Vorsyghta: {scenario_name}",
            "description": description,
            "target": target_url,
            "parameters": parameters,
        }

    def _summarize_payloads(self, payloads: Dict[str, Any]) -> str:
        """Build a human-readable summary of available payloads for the flow description."""
        lines = []
        for content_type, items in payloads.items():
            if isinstance(items, list):
                lines.append(f"  {content_type}: {len(items)} variant(s)")
            elif isinstance(items, dict) and "content" in items:
                preview = items["content"][:100].replace("\n", " ")
                lines.append(f"  {content_type}: {preview}...")
            elif isinstance(items, str):
                preview = items[:100].replace("\n", " ")
                lines.append(f"  {content_type}: {preview}...")
        return "\n".join(lines) if lines else ""

    def _extract_target_url(
        self,
        scenario: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> str:
        """Extract the target URL from scenario or target info."""
        if "target" in scenario and isinstance(scenario["target"], dict):
            if "url" in scenario["target"]:
                return scenario["target"]["url"]
            if "ip" in scenario["target"]:
                ip = scenario["target"]["ip"]
                port = scenario["target"].get("port", 80)
                return f"http://{ip}:{port}"

        if "url" in target_info:
            return target_info["url"]
        if "ip" in target_info:
            ip = target_info["ip"]
            port = target_info.get("port", 80)
            return f"http://{ip}:{port}"

        return target_info.get("target", "unknown")

    def _build_flow_description(
        self,
        scenario_name: str,
        threat_type: str,
        mitre_techniques: List[str],
        objectives: List[str],
        difficulty: int,
        target_info: Dict[str, Any],
    ) -> str:
        """Build a natural language description for Vorsyghta Attack agents."""
        parts = [f"Scenario: {scenario_name}"]
        parts.append(f"Threat Type: {threat_type}")
        parts.append(f"Difficulty Level: {difficulty}/10")

        if mitre_techniques:
            technique_names = []
            for tech in mitre_techniques:
                mapping = self.mitre_mapping.get(tech)
                if mapping:
                    technique_names.append(f"{tech} ({mapping['task_name']})")
                else:
                    technique_names.append(tech)
            parts.append(f"MITRE ATT&CK Techniques: {', '.join(technique_names)}")

        if objectives:
            parts.append("Objectives:")
            for obj in objectives:
                parts.append(f"  - {obj}")

        if target_info:
            info_parts = []
            for key, value in target_info.items():
                if key not in ("credentials", "secrets"):
                    info_parts.append(f"  {key}: {value}")
            if info_parts:
                parts.append("Target Information:")
                parts.extend(info_parts)

        task_hints = self._generate_task_hints(mitre_techniques)
        if task_hints:
            parts.append("Suggested Attack Phases:")
            for hint in task_hints:
                parts.append(f"  - {hint}")

        return "\n".join(parts)

    def _generate_task_hints(self, mitre_techniques: List[str]) -> List[str]:
        """Generate task hints from MITRE techniques."""
        hints = []
        seen_phases = set()

        for tech in mitre_techniques:
            mapping = self.mitre_mapping.get(tech)
            if mapping:
                task_name = mapping["task_name"]
                agent = mapping["agent_type"]
                hint = f"[{agent}] {task_name} ({tech})"
                if hint not in seen_phases:
                    hints.append(hint)
                    seen_phases.add(hint)

        if not hints:
            hints.append("[researcher] Reconnaissance and information gathering")
            hints.append("[executor] Vulnerability scanning and exploitation")
            hints.append("[developer] Attack tool development and customization")

        return hints

    def flow_to_aar(
        self,
        flow_status: Dict[str, Any],
        report: Dict[str, Any],
        scenario: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Convert Vorsyghta Attack flow results to Vorsyghta After Action Review.

        Args:
            flow_status: Final flow status from Vorsyghta Attack
            report: Vulnerability report from Vorsyghta Attack
            scenario: Original Vorsyghta scenario

        Returns:
            AAR dict with structured after-action review data
        """
        aar = {
            "scenario_name": scenario.get("name", "Unknown"),
            "flow_id": flow_status.get("flow_id", ""),
            "flow_status": flow_status.get("status", "unknown"),
            "target": flow_status.get("target", ""),
            "executive_summary": report.get("executive_summary", ""),
            "vulnerabilities": report.get("vulnerabilities", []),
            "mitre_techniques_used": report.get("mitre_techniques", []),
            "recommendations": report.get("recommendations", []),
            "report_markdown": report.get("report_markdown", ""),
            "scenario_objectives": scenario.get("objectives", []),
            "objectives_met": self._assess_objectives(
                scenario.get("objectives", []),
                report.get("vulnerabilities", []),
            ),
        }

        return aar

    def _assess_objectives(
        self,
        objectives: List[str],
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        """Assess which objectives were met based on findings."""
        results = []
        vuln_text = " ".join(
            str(v.get("title", "")) + " " + str(v.get("description", ""))
            for v in vulnerabilities
        ).lower()

        for obj in objectives:
            obj_lower = obj.lower()
            keywords = obj_lower.split()
            matched = sum(1 for kw in keywords if kw in vuln_text)
            confidence = "high" if matched >= 2 else "medium" if matched >= 1 else "low"

            results.append({
                "objective": obj,
                "status": "likely_met" if confidence != "low" else "not_met",
                "confidence": confidence,
            })

        return results
