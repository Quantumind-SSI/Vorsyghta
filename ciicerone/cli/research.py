"""Research CLI — Zero-day vulnerability research commands.

Provides CLI commands for managing engagements, disclosures, and
running discovery campaigns.

Usage:
    ciicerone research engagement create --client "Acme" --name "Q4 Audit"
    ciicerone research engagement list
    ciicerone research engagement approve <id>
    ciicerone research engagement authorize <id> --target 10.0.100.10

    ciicerone research disclosure create --engagement <id> --vendor "Acme" ...
    ciicerone research disclosure notify-vendor <id>
    ciicerone research disclosure list
"""

import asyncio
import json
import logging
import sys
from typing import Optional

import click

logger = logging.getLogger(__name__)


# =========================================================================
# Research command group
# =========================================================================

@click.group()
def research():
    """Zero-day vulnerability research operations."""
    pass


# =========================================================================
# Engagement subcommands
# =========================================================================

@research.group()
def engagement():
    """Manage client engagements for zero-day research."""
    pass


@engagement.command(name="create")
@click.option("--client", "-c", required=True, help="Client organization name")
@click.option("--name", "-n", required=True, help="Engagement name")
@click.option("--target", "-t", multiple=True, help="Target IP/domain/URL (can specify multiple)")
@click.option("--start-date", "-s", help="Start date (ISO format)")
@click.option("--end-date", "-e", help="End date (ISO format)")
@click.option("--created-by", "-b", default="cli", help="User creating the engagement")
@click.option("--notes", help="Additional notes")
def engagement_create(client, name, target, start_date, end_date, created_by, notes):
    """Create a new client engagement."""
    from ciicerone.research.engagement import (
        EngagementManager, TargetEntry, TargetType,
    )

    manager = EngagementManager()

    targets = []
    for t in target:
        # Auto-detect target type
        target_type = TargetType.IP_ADDRESS
        if t.startswith("http://") or t.startswith("https://"):
            target_type = TargetType.URL
        elif "." in t and not t.replace(".", "").isdigit():
            target_type = TargetType.DOMAIN

        targets.append(TargetEntry(
            target_type=target_type,
            value=t,
            description=f"CLI-added target: {t}",
        ))

    engagement_obj = manager.create_engagement(
        client=client,
        engagement_name=name,
        targets=targets,
        start_date=start_date,
        end_date=end_date,
        created_by=created_by,
    )
    if notes:
        engagement_obj.notes = notes
        manager._save(engagement_obj)

    click.echo(f"Engagement created: {engagement_obj.id}")
    click.echo(f"  Client: {engagement_obj.client}")
    click.echo(f"  Name: {engagement_obj.engagement_name}")
    click.echo(f"  Status: {engagement_obj.status.value}")
    click.echo(f"  Targets: {len(engagement_obj.targets)}")
    if engagement_obj.start_date:
        click.echo(f"  Start: {engagement_obj.start_date}")
    if engagement_obj.end_date:
        click.echo(f"  End: {engagement_obj.end_date}")


@engagement.command(name="list")
@click.option("--status", "-s", help="Filter by status")
@click.option("--client", "-c", help="Filter by client name")
def engagement_list(status, client):
    """List all engagements."""
    from ciicerone.research.engagement import EngagementManager, EngagementStatus

    manager = EngagementManager()

    status_enum = None
    if status:
        try:
            status_enum = EngagementStatus(status)
        except ValueError:
            click.echo(f"Invalid status: {status}", err=True)
            sys.exit(1)

    engagements = manager.list_engagements(status=status_enum, client=client)

    if not engagements:
        click.echo("No engagements found.")
        return

    click.echo(f"{'ID':<14} {'Status':<18} {'Client':<20} {'Name':<30} {'Targets':<8} {'Findings':<10}")
    click.echo("-" * 100)
    for e in engagements:
        click.echo(
            f"{e.id:<14} {e.status.value:<18} {e.client[:20]:<20} "
            f"{e.engagement_name[:30]:<30} {len(e.targets):<8} "
            f"{e.findings_count}({e.critical_findings}c)"
        )


@engagement.command(name="show")
@click.argument("engagement_id")
def engagement_show(engagement_id):
    """Show details of a specific engagement."""
    from ciicerone.research.engagement import EngagementManager

    manager = EngagementManager()
    engagement_obj = manager.get_engagement(engagement_id)

    if not engagement_obj:
        click.echo(f"Engagement {engagement_id} not found.", err=True)
        sys.exit(1)

    click.echo(manager.export_engagement(engagement_id, format="markdown"))


@engagement.command(name="approve")
@click.argument("engagement_id")
def engagement_approve(engagement_id):
    """Approve an engagement (move from pending to active)."""
    from ciicerone.research.engagement import EngagementManager

    manager = EngagementManager()
    try:
        engagement_obj = manager.approve_engagement(engagement_id)
        click.echo(f"Engagement {engagement_id} approved and active.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@engagement.command(name="pause")
@click.argument("engagement_id")
def engagement_pause(engagement_id):
    """Pause an active engagement."""
    from ciicerone.research.engagement import EngagementManager

    manager = EngagementManager()
    try:
        manager.pause_engagement(engagement_id)
        click.echo(f"Engagement {engagement_id} paused.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@engagement.command(name="complete")
@click.argument("engagement_id")
def engagement_complete(engagement_id):
    """Mark an engagement as completed."""
    from ciicerone.research.engagement import EngagementManager

    manager = EngagementManager()
    try:
        manager.complete_engagement(engagement_id)
        click.echo(f"Engagement {engagement_id} completed.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@engagement.command(name="cancel")
@click.argument("engagement_id")
def engagement_cancel(engagement_id):
    """Cancel an engagement."""
    from ciicerone.research.engagement import EngagementManager

    manager = EngagementManager()
    try:
        manager.cancel_engagement(engagement_id)
        click.echo(f"Engagement {engagement_id} cancelled.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@engagement.command(name="authorize")
@click.argument("engagement_id")
@click.option("--target", "-t", required=True, help="Target to check")
@click.option("--method", "-m", help="Research method to check")
def engagement_authorize(engagement_id, target, method):
    """Check if a target is authorized for testing."""
    from ciicerone.research.engagement import EngagementManager, ResearchMethod

    manager = EngagementManager()

    method_enum = None
    if method:
        try:
            method_enum = ResearchMethod(method)
        except ValueError:
            click.echo(f"Invalid method: {method}", err=True)
            sys.exit(1)

    authorized, reason = manager.is_authorized(
        engagement_id=engagement_id,
        target_value=target,
        method=method_enum,
    )

    if authorized:
        click.echo(f"AUTHORIZED: {reason}")
    else:
        click.echo(f"NOT AUTHORIZED: {reason}")
        sys.exit(1)


@engagement.command(name="add-target")
@click.argument("engagement_id")
@click.option("--value", "-v", required=True, help="Target value (IP, domain, URL)")
@click.option("--type", "-t", default="ip_address", help="Target type")
@click.option("--description", "-d", default="", help="Description")
@click.option("--excluded", is_flag=True, help="Mark as excluded from scope")
def engagement_add_target(engagement_id, value, type, description, excluded):
    """Add a target to an engagement's scope."""
    from ciicerone.research.engagement import EngagementManager, TargetEntry, TargetType

    manager = EngagementManager()
    try:
        target_type = TargetType(type)
    except ValueError:
        click.echo(f"Invalid target type: {type}", err=True)
        sys.exit(1)

    try:
        manager.add_target(engagement_id, TargetEntry(
            target_type=target_type,
            value=value,
            description=description,
            excluded=excluded,
        ))
        click.echo(f"Target added to engagement {engagement_id}: {value}")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@engagement.command(name="export")
@click.argument("engagement_id")
@click.option("--format", "-f", default="json", type=click.Choice(["json", "markdown"]))
@click.option("--output", "-o", help="Output file path")
def engagement_export(engagement_id, format, output):
    """Export an engagement as JSON or markdown."""
    from ciicerone.research.engagement import EngagementManager

    manager = EngagementManager()
    content = manager.export_engagement(engagement_id, format=format)

    if output:
        with open(output, "w") as f:
            f.write(content)
        click.echo(f"Exported to {output}")
    else:
        click.echo(content)


# =========================================================================
# Disclosure subcommands
# =========================================================================

@research.group()
def disclosure():
    """Manage vulnerability disclosures."""
    pass


@disclosure.command(name="create")
@click.option("--engagement-id", "-e", required=True, help="Engagement ID")
@click.option("--finding-id", "-f", required=True, help="Finding ID")
@click.option("--vendor", "-v", required=True, help="Vendor name")
@click.option("--product", "-p", required=True, help="Product name")
@click.option("--title", "-t", required=True, help="Vulnerability title")
@click.option("--severity", "-s", default="medium", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--cvss", default=0.0, type=float, help="CVSS score")
@click.option("--cwe", default="", help="CWE ID")
@click.option("--description", "-d", default="", help="Vulnerability description")
@click.option("--embargo-days", default=None, type=int, help="Override embargo period")
@click.option("--vendor-email", default="", help="Vendor security email")
@click.option("--created-by", default="cli", help="User creating the disclosure")
def disclosure_create(engagement_id, finding_id, vendor, product, title, severity,
                      cvss, cwe, description, embargo_days, vendor_email, created_by):
    """Create a new vulnerability disclosure record."""
    from ciicerone.research.disclosure import DisclosureManager, VendorContact

    manager = DisclosureManager()

    vc = VendorContact(
        company=vendor,
        security_email=vendor_email,
    )

    disclosure_obj = manager.create_disclosure(
        engagement_id=engagement_id,
        finding_id=finding_id,
        vendor=vendor,
        product=product,
        title=title,
        severity=severity,
        cvss_score=cvss,
        cwe_id=cwe,
        description=description,
        vendor_contact=vc,
        embargo_days=embargo_days,
        created_by=created_by,
    )

    click.echo(f"Disclosure created: {disclosure_obj.id}")
    click.echo(f"  Vendor: {disclosure_obj.vendor} {disclosure_obj.product}")
    click.echo(f"  Severity: {disclosure_obj.severity}")
    click.echo(f"  Status: {disclosure_obj.status.value}")
    click.echo(f"  Embargo: {disclosure_obj.embargo_days} days (ends {disclosure_obj.embargo_end_date[:10]})")


@disclosure.command(name="list")
@click.option("--status", "-s", help="Filter by status")
@click.option("--vendor", "-v", help="Filter by vendor")
@click.option("--engagement-id", "-e", help="Filter by engagement ID")
def disclosure_list(status, vendor, engagement_id):
    """List all disclosures."""
    from ciicerone.research.disclosure import DisclosureManager, DisclosureStatus

    manager = DisclosureManager()

    status_enum = None
    if status:
        try:
            status_enum = DisclosureStatus(status)
        except ValueError:
            click.echo(f"Invalid status: {status}", err=True)
            sys.exit(1)

    disclosures = manager.list_disclosures(
        status=status_enum,
        vendor=vendor,
        engagement_id=engagement_id,
    )

    if not disclosures:
        click.echo("No disclosures found.")
        return

    click.echo(f"{'ID':<14} {'Status':<22} {'Vendor':<20} {'Product':<20} {'Severity':<10} {'CVE':<16} {'Embargo':<10}")
    click.echo("-" * 112)
    for d in disclosures:
        cve = d.cve_id or "pending"
        embargo = f"{d.days_until_disclosure()}d" if d.is_under_embargo() else ("expired" if d.embargo_end_date else "none")
        click.echo(
            f"{d.id:<14} {d.status.value:<22} {d.vendor[:20]:<20} "
            f"{d.product[:20]:<20} {d.severity:<10} {cve:<16} {embargo:<10}"
        )


@disclosure.command(name="show")
@click.argument("disclosure_id")
def disclosure_show(disclosure_id):
    """Show details of a specific disclosure."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    disclosure_obj = manager.get_disclosure(disclosure_id)

    if not disclosure_obj:
        click.echo(f"Disclosure {disclosure_id} not found.", err=True)
        sys.exit(1)

    click.echo(json.dumps(disclosure_obj.to_dict(), indent=2))


@disclosure.command(name="notify-vendor")
@click.argument("disclosure_id")
@click.option("--method", "-m", default="email", help="Notification method")
@click.option("--details", "-d", default="", help="Notification details")
def disclosure_notify_vendor(disclosure_id, method, details):
    """Record that the vendor has been notified."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    try:
        manager.notify_vendor(disclosure_id, notification_method=method, notification_details=details)
        click.echo(f"Vendor notified for disclosure {disclosure_id}.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="vendor-response")
@click.argument("disclosure_id")
@click.option("--response", "-r", required=True, help="Vendor response type")
@click.option("--details", "-d", default="", help="Response details")
@click.option("--tracking-id", "-t", default="", help="Vendor tracking ID")
def disclosure_vendor_response(disclosure_id, response, details, tracking_id):
    """Record a vendor's response."""
    from ciicerone.research.disclosure import DisclosureManager, VendorResponse

    manager = DisclosureManager()
    try:
        resp = VendorResponse(response)
    except ValueError:
        click.echo(f"Invalid response: {response}", err=True)
        sys.exit(1)

    try:
        manager.record_vendor_response(disclosure_id, response=resp, details=details, vendor_tracking_id=tracking_id)
        click.echo(f"Vendor response recorded for disclosure {disclosure_id}: {resp.value}")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="request-cve")
@click.argument("disclosure_id")
@click.option("--cna", default="MITRE", help="CVE Numbering Authority")
def disclosure_request_cve(disclosure_id, cna):
    """Request a CVE ID from a CNA."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    try:
        d = manager.request_cve(disclosure_id, cna=cna)
        click.echo(f"CVE requested from {cna}: {d.cve_request_id}")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="assign-cve")
@click.argument("disclosure_id")
@click.argument("cve_id")
def disclosure_assign_cve(disclosure_id, cve_id):
    """Record an assigned CVE ID."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    try:
        manager.assign_cve(disclosure_id, cve_id=cve_id)
        click.echo(f"CVE {cve_id} assigned to disclosure {disclosure_id}.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="extend-embargo")
@click.argument("disclosure_id")
@click.option("--days", "-d", required=True, type=int, help="Days to extend")
@click.option("--reason", "-r", default="", help="Reason for extension")
def disclosure_extend_embargo(disclosure_id, days, reason):
    """Grant an embargo extension."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    try:
        d = manager.grant_extension(disclosure_id, extension_days=days, reason=reason)
        click.echo(f"Embargo extended by {days} days. New end: {d.embargo_end_date[:10]}")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="publish")
@click.argument("disclosure_id")
@click.option("--force", is_flag=True, help="Force publication even if embargo active")
def disclosure_publish(disclosure_id, force):
    """Publish the vulnerability disclosure publicly."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    try:
        manager.publish(disclosure_id, force=force)
        click.echo(f"Disclosure {disclosure_id} published publicly.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="withdraw")
@click.argument("disclosure_id")
@click.option("--reason", "-r", default="", help="Reason for withdrawal")
def disclosure_withdraw(disclosure_id, reason):
    """Withdraw a disclosure."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    try:
        manager.withdraw(disclosure_id, reason=reason)
        click.echo(f"Disclosure {disclosure_id} withdrawn.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disclosure.command(name="export")
@click.argument("disclosure_id")
@click.option("--format", "-f", default="json",
              type=click.Choice(["json", "email", "report"]))
@click.option("--output", "-o", help="Output file path")
def disclosure_export(disclosure_id, format, output):
    """Export a disclosure as JSON, email template, or public report."""
    from ciicerone.research.disclosure import DisclosureManager

    manager = DisclosureManager()
    content = manager.export_disclosure(disclosure_id, format=format)

    if output:
        with open(output, "w") as f:
            f.write(content)
        click.echo(f"Exported to {output}")
    else:
        click.echo(content)


# =========================================================================
# VM provisioning subcommand
# =========================================================================

@research.command(name="provision-vm")
@click.option("--target-host", "-t", help="SSH host to provision (if running remotely)")
@click.option("--user", "-u", default="root", help="SSH username")
@click.option("--key", "-k", help="SSH private key path")
@click.option("--script-only", is_flag=True, help="Just output the script, don't run it")
def provision_vm(target_host, user, key, script_only):
    """Provision a zero-day research attacker VM with the full toolchain."""
    import os

    script_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "scripts", "provision_research_vm.sh"
    )
    script_path = os.path.abspath(script_path)

    if not os.path.exists(script_path):
        click.echo(f"Provisioning script not found: {script_path}", err=True)
        sys.exit(1)

    if script_only:
        with open(script_path) as f:
            click.echo(f.read())
        return

    if target_host:
        # Run remotely via SSH
        import subprocess
        click.echo(f"Provisioning research VM at {target_host}...")
        cmd = ["scp"]
        if key:
            cmd.extend(["-i", key])
        cmd.extend([script_path, f"{user}@{target_host}:/tmp/provision_research_vm.sh"])
        subprocess.run(cmd, check=True)

        cmd = ["ssh"]
        if key:
            cmd.extend(["-i", key])
        cmd.extend([f"{user}@{target_host}", "bash /tmp/provision_research_vm.sh"])
        subprocess.run(cmd, check=True)
    else:
        # Run locally
        click.echo("Provisioning research VM locally...")
        import subprocess
        subprocess.run(["bash", script_path], check=True)
