"""Create persistence layer tables for Phase 0/1

Revision ID: 003_persistence_layer
Revises: 002_create_snapshots_table
Create Date: 2026-07-07

Issue: P0-6 — No database persistence, no multi-tenant isolation
Author: Omolara Oladipupo (@laradipupo)

Creates all Phase 0/1 ORM-backed tables in the public schema:
    - tenants, users (auth/identity)
    - audit_events (tamper-evident audit trail)
    - simulation_results, simulation_stages (simulation engine)
    - attack_plans, attack_results, attack_steps (red team)
    - alerts, incidents (blue team)
    - threat_actors, threat_campaigns, malware_families,
      threat_indicators, threat_ttps, threat_reports (threat intel)
    - tool_usage, attack_sequences, attack_sequence_steps,
      attack_executions (tool tracking)

All tables carry tenant_id columns for multi-tenant isolation.
This migration replaces the Base.metadata.create_all() pilot shortcut
with a proper Alembic-managed schema.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_persistence_layer'
down_revision: Union[str, None] = '002_create_snapshots_table'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all Phase 0/1 persistence tables."""

    # -----------------------------------------------------------------------
    # Auth / Identity
    # -----------------------------------------------------------------------

    op.create_table(
        'tenants',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), nullable=False, unique=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index('ix_tenants_tenant_id', 'tenants', ['tenant_id'], unique=True)

    op.create_table(
        'users',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('user_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.tenant_id'], ),
    )
    op.create_index('ix_users_user_id', 'users', ['user_id'], unique=True)
    op.create_index('ix_users_tenant_id', 'users', ['tenant_id'])
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # -----------------------------------------------------------------------
    # Audit Trail
    # -----------------------------------------------------------------------

    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('event_id', sa.String(), nullable=False, unique=True),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('actor', sa.JSON(), nullable=False),
        sa.Column('target', sa.JSON(), nullable=False),
        sa.Column('context', sa.JSON(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('correlation_id', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('prev_hash', sa.String(64), nullable=True),
        sa.Column('event_hash', sa.String(64), nullable=True),
        sa.Column('tenant_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index('ix_audit_events_event_id', 'audit_events', ['event_id'], unique=True)
    op.create_index('ix_audit_events_event_type', 'audit_events', ['event_type'])
    op.create_index('ix_audit_events_timestamp', 'audit_events', ['timestamp'])
    op.create_index('ix_audit_events_tenant_id', 'audit_events', ['tenant_id'])

    # -----------------------------------------------------------------------
    # Simulation
    # -----------------------------------------------------------------------

    op.create_table(
        'simulation_results',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('result_id', sa.String(), nullable=False, unique=True),
        sa.Column('scenario_id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('start_time', sa.DateTime(), nullable=False),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('total_duration_seconds', sa.Float(), nullable=True),
        sa.Column('success_rate', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index('ix_simulation_results_result_id', 'simulation_results', ['result_id'], unique=True)
    op.create_index('ix_simulation_results_tenant_id', 'simulation_results', ['tenant_id'])

    op.create_table(
        'simulation_stages',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('stage_id', sa.String(), nullable=False, unique=True),
        sa.Column('result_id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('stage_name', sa.String(), nullable=False),
        sa.Column('technique_id', sa.String(), nullable=True),
        sa.Column('tactic', sa.String(), nullable=True),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.ForeignKeyConstraint(['result_id'], ['simulation_results.result_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_simulation_stages_stage_id', 'simulation_stages', ['stage_id'], unique=True)
    op.create_index('ix_simulation_stages_result_id', 'simulation_stages', ['result_id'])

    # -----------------------------------------------------------------------
    # Red Team
    # -----------------------------------------------------------------------

    op.create_table(
        'attack_plans',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('plan_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('exercise_id', sa.String(), nullable=True),
        sa.Column('scenario_name', sa.String(), nullable=False),
        sa.Column('threat_type', sa.String(), nullable=False),
        sa.Column('objective', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index('ix_attack_plans_plan_id', 'attack_plans', ['plan_id'], unique=True)
    op.create_index('ix_attack_plans_tenant_id', 'attack_plans', ['tenant_id'])

    op.create_table(
        'attack_results',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('result_id', sa.String(), nullable=False, unique=True),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('total_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('successful_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('start_time', sa.DateTime(), nullable=True),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.ForeignKeyConstraint(['plan_id'], ['attack_plans.plan_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_attack_results_result_id', 'attack_results', ['result_id'], unique=True)
    op.create_index('ix_attack_results_plan_id', 'attack_results', ['plan_id'])

    op.create_table(
        'attack_steps',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('step_id', sa.String(), nullable=False, unique=True),
        sa.Column('result_id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('step_name', sa.String(), nullable=False),
        sa.Column('technique_id', sa.String(), nullable=True),
        sa.Column('command', sa.Text(), nullable=True),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.ForeignKeyConstraint(['result_id'], ['attack_results.result_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_attack_steps_step_id', 'attack_steps', ['step_id'], unique=True)
    op.create_index('ix_attack_steps_result_id', 'attack_steps', ['result_id'])

    # -----------------------------------------------------------------------
    # Blue Team
    # -----------------------------------------------------------------------

    op.create_table(
        'alerts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('alert_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('exercise_id', sa.String(), nullable=True),
        sa.Column('source_module', sa.String(), nullable=False),
        sa.Column('technique_id', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('detected', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('stage_id', sa.String(), nullable=True),
        sa.Column('iocs', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index('ix_alerts_alert_id', 'alerts', ['alert_id'], unique=True)
    op.create_index('ix_alerts_tenant_id', 'alerts', ['tenant_id'])

    op.create_table(
        'incidents',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('incident_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('exercise_id', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='open'),
        sa.Column('mitre_techniques', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_incidents_incident_id', 'incidents', ['incident_id'], unique=True)
    op.create_index('ix_incidents_tenant_id', 'incidents', ['tenant_id'])

    # -----------------------------------------------------------------------
    # Threat Intelligence
    # -----------------------------------------------------------------------

    op.create_table(
        'threat_actors',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('actor_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('aliases', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('actor_type', sa.String(), nullable=False, server_default='apt'),
        sa.Column('target_industries', sa.Text(), nullable=True),
        sa.Column('target_regions', sa.Text(), nullable=True),
        sa.Column('target_countries', sa.Text(), nullable=True),
        sa.Column('sophistication_level', sa.Integer(), nullable=True),
        sa.Column('primary_motivation', sa.String(), nullable=True),
        sa.Column('secondary_motivations', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('confidence_level', sa.String(), nullable=False, server_default='medium'),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('collected_by', sa.String(), nullable=True),
        sa.Column('collection_method', sa.String(), nullable=True),
        sa.Column('shared_with_teams', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_threat_actors_actor_id', 'threat_actors', ['actor_id'], unique=True)
    op.create_index('ix_threat_actors_tenant_id', 'threat_actors', ['tenant_id'])

    op.create_table(
        'threat_campaigns',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('campaign_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('actor_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('campaign_status', sa.String(), nullable=False, server_default='active'),
        sa.Column('start_date', sa.DateTime(), nullable=True),
        sa.Column('end_date', sa.DateTime(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('target_organizations', sa.Text(), nullable=True),
        sa.Column('target_sectors', sa.Text(), nullable=True),
        sa.Column('target_geography', sa.Text(), nullable=True),
        sa.Column('mitre_techniques', sa.Text(), nullable=True),
        sa.Column('mitre_tactics', sa.Text(), nullable=True),
        sa.Column('impact_assessment', sa.Text(), nullable=True),
        sa.Column('estimated_impact_usd', sa.Float(), nullable=True),
        sa.Column('victims_count', sa.Integer(), nullable=True),
        sa.Column('confidence_level', sa.String(), nullable=False, server_default='medium'),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('collected_by', sa.String(), nullable=True),
        sa.Column('shared_with_teams', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['actor_id'], ['threat_actors.actor_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_threat_campaigns_campaign_id', 'threat_campaigns', ['campaign_id'], unique=True)
    op.create_index('ix_threat_campaigns_tenant_id', 'threat_campaigns', ['tenant_id'])
    op.create_index('ix_threat_campaigns_actor_id', 'threat_campaigns', ['actor_id'])

    op.create_table(
        'malware_families',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('malware_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('campaign_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('aliases', sa.Text(), nullable=True),
        sa.Column('family_type', sa.String(), nullable=False, server_default='malware'),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('platforms', sa.Text(), nullable=True),
        sa.Column('file_extensions', sa.Text(), nullable=True),
        sa.Column('file_hashes', sa.Text(), nullable=True),
        sa.Column('c2_infrastructure', sa.Text(), nullable=True),
        sa.Column('mitre_techniques', sa.Text(), nullable=True),
        sa.Column('yara_rules', sa.Text(), nullable=True),
        sa.Column('detection_signatures', sa.Text(), nullable=True),
        sa.Column('confidence_level', sa.String(), nullable=False, server_default='medium'),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('collected_by', sa.String(), nullable=True),
        sa.Column('shared_with_teams', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['campaign_id'], ['threat_campaigns.campaign_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_malware_families_malware_id', 'malware_families', ['malware_id'], unique=True)
    op.create_index('ix_malware_families_tenant_id', 'malware_families', ['tenant_id'])
    op.create_index('ix_malware_families_campaign_id', 'malware_families', ['campaign_id'])

    op.create_table(
        'threat_indicators',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('indicator_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('campaign_id', sa.String(), nullable=False),
        sa.Column('indicator_type', sa.String(), nullable=False),
        sa.Column('indicator_value', sa.Text(), nullable=False),
        sa.Column('indicator_hash', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('context', sa.Text(), nullable=True),
        sa.Column('indicator_state', sa.String(), nullable=False, server_default='active'),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('confidence_level', sa.String(), nullable=False, server_default='medium'),
        sa.Column('threat_score', sa.Integer(), nullable=True),
        sa.Column('false_positive_rate', sa.Float(), nullable=True),
        sa.Column('mitre_technique', sa.String(), nullable=True),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('collected_by', sa.String(), nullable=True),
        sa.Column('collection_method', sa.String(), nullable=True),
        sa.Column('shared_with_teams', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['campaign_id'], ['threat_campaigns.campaign_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_threat_indicators_indicator_id', 'threat_indicators', ['indicator_id'], unique=True)
    op.create_index('ix_threat_indicators_tenant_id', 'threat_indicators', ['tenant_id'])
    op.create_index('ix_threat_indicators_indicator_type', 'threat_indicators', ['indicator_type'])
    op.create_index('ix_threat_indicators_indicator_hash', 'threat_indicators', ['indicator_hash'])

    op.create_table(
        'threat_ttps',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('ttp_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('campaign_id', sa.String(), nullable=False),
        sa.Column('mitre_technique_id', sa.String(), nullable=True),
        sa.Column('mitre_tactic', sa.String(), nullable=True),
        sa.Column('mitre_subtechnique_id', sa.String(), nullable=True),
        sa.Column('ttp_name', sa.String(), nullable=False),
        sa.Column('ttp_category', sa.String(), nullable=False, server_default='technique'),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('observed_procedure', sa.Text(), nullable=True),
        sa.Column('detection_recommendations', sa.Text(), nullable=True),
        sa.Column('detection_data_sources', sa.Text(), nullable=True),
        sa.Column('sigma_rule', sa.Text(), nullable=True),
        sa.Column('splunk_query', sa.Text(), nullable=True),
        sa.Column('elastic_query', sa.Text(), nullable=True),
        sa.Column('sentinel_query', sa.Text(), nullable=True),
        sa.Column('mitigation_recommendations', sa.Text(), nullable=True),
        sa.Column('simulation_applicability', sa.String(), nullable=True),
        sa.Column('simulation_notes', sa.Text(), nullable=True),
        sa.Column('confidence_level', sa.String(), nullable=False, server_default='medium'),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('collected_by', sa.String(), nullable=True),
        sa.Column('shared_with_teams', sa.Text(), nullable=True),
        sa.Column('first_observed', sa.DateTime(), nullable=True),
        sa.Column('last_observed', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['campaign_id'], ['threat_campaigns.campaign_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_threat_ttps_ttp_id', 'threat_ttps', ['ttp_id'], unique=True)
    op.create_index('ix_threat_ttps_tenant_id', 'threat_ttps', ['tenant_id'])
    op.create_index('ix_threat_ttps_mitre_technique_id', 'threat_ttps', ['mitre_technique_id'])

    op.create_table(
        'threat_reports',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('report_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('actor_id', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('report_type', sa.String(), nullable=False, server_default='threat_assessment'),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('classification', sa.String(), nullable=False, server_default='TLP:AMBER'),
        sa.Column('severity', sa.String(), nullable=False, server_default='medium'),
        sa.Column('affected_industries', sa.Text(), nullable=True),
        sa.Column('affected_regions', sa.Text(), nullable=True),
        sa.Column('mitre_techniques', sa.Text(), nullable=True),
        sa.Column('recommendations', sa.Text(), nullable=True),
        sa.Column('remediation_steps', sa.Text(), nullable=True),
        sa.Column('confidence_level', sa.String(), nullable=False, server_default='medium'),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('authored_by', sa.String(), nullable=True),
        sa.Column('reviewed_by', sa.String(), nullable=True),
        sa.Column('report_status', sa.String(), nullable=False, server_default='draft'),
        sa.Column('shared_with_teams', sa.Text(), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['actor_id'], ['threat_actors.actor_id'], ondelete='SET NULL'),
    )
    op.create_index('ix_threat_reports_report_id', 'threat_reports', ['report_id'], unique=True)
    op.create_index('ix_threat_reports_tenant_id', 'threat_reports', ['tenant_id'])
    op.create_index('ix_threat_reports_actor_id', 'threat_reports', ['actor_id'])

    # -----------------------------------------------------------------------
    # Tool Tracking
    # -----------------------------------------------------------------------

    op.create_table(
        'attack_sequences',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('sequence_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('exercise_id', sa.String(), nullable=True),
        sa.Column('simulation_id', sa.String(), nullable=True),
        sa.Column('scenario_name', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('target_system', sa.String(), nullable=True),
        sa.Column('target_ip', sa.String(), nullable=True),
        sa.Column('target_url', sa.String(), nullable=True),
        sa.Column('attacker_vm', sa.String(), nullable=True),
        sa.Column('mitre_tactics', sa.Text(), nullable=True),
        sa.Column('mitre_techniques', sa.Text(), nullable=True),
        sa.Column('sequence_status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('total_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('completed_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('successful_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('start_time', sa.DateTime(), nullable=True),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('total_duration_seconds', sa.Float(), nullable=True),
        sa.Column('overall_success', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('result_summary', sa.Text(), nullable=True),
        sa.Column('key_findings', sa.Text(), nullable=True),
        sa.Column('initiated_by', sa.String(), nullable=True),
        sa.Column('initiated_by_source', sa.String(), nullable=False, server_default='api'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_attack_sequences_sequence_id', 'attack_sequences', ['sequence_id'], unique=True)
    op.create_index('ix_attack_sequences_tenant_id', 'attack_sequences', ['tenant_id'])
    op.create_index('ix_attack_sequences_exercise_id', 'attack_sequences', ['exercise_id'])
    op.create_index('ix_attack_sequences_simulation_id', 'attack_sequences', ['simulation_id'])

    op.create_table(
        'attack_sequence_steps',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('step_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('sequence_id', sa.String(), nullable=False),
        sa.Column('step_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('step_name', sa.String(), nullable=False),
        sa.Column('step_type', sa.String(), nullable=False, server_default='tool_execution'),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('mitre_technique_id', sa.String(), nullable=True),
        sa.Column('mitre_tactic', sa.String(), nullable=True),
        sa.Column('attack_phase', sa.String(), nullable=True),
        sa.Column('tool_name', sa.String(), nullable=True),
        sa.Column('command', sa.Text(), nullable=True),
        sa.Column('target', sa.String(), nullable=True),
        sa.Column('depends_on_steps', sa.Text(), nullable=True),
        sa.Column('condition', sa.Text(), nullable=True),
        sa.Column('step_status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('output_summary', sa.Text(), nullable=True),
        sa.Column('findings', sa.Text(), nullable=True),
        sa.Column('iocs_discovered', sa.Text(), nullable=True),
        sa.Column('start_time', sa.DateTime(), nullable=True),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['sequence_id'], ['attack_sequences.sequence_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_attack_sequence_steps_step_id', 'attack_sequence_steps', ['step_id'], unique=True)
    op.create_index('ix_attack_sequence_steps_tenant_id', 'attack_sequence_steps', ['tenant_id'])
    op.create_index('ix_attack_sequence_steps_sequence_id', 'attack_sequence_steps', ['sequence_id'])
    op.create_index('ix_attack_sequence_steps_mitre_technique_id', 'attack_sequence_steps', ['mitre_technique_id'])

    op.create_table(
        'attack_executions',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('execution_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('step_id', sa.String(), nullable=False),
        sa.Column('executor', sa.String(), nullable=False, server_default='tool_server'),
        sa.Column('executor_endpoint', sa.String(), nullable=True),
        sa.Column('input_command', sa.Text(), nullable=True),
        sa.Column('input_parameters', sa.Text(), nullable=True),
        sa.Column('raw_output', sa.Text(), nullable=True),
        sa.Column('parsed_output', sa.Text(), nullable=True),
        sa.Column('output_format', sa.String(), nullable=True),
        sa.Column('return_code', sa.Integer(), nullable=True),
        sa.Column('exit_status', sa.String(), nullable=True),
        sa.Column('error_details', sa.Text(), nullable=True),
        sa.Column('screenshots', sa.Text(), nullable=True),
        sa.Column('artifacts', sa.Text(), nullable=True),
        sa.Column('evidence_hash', sa.String(), nullable=True),
        sa.Column('impact_level', sa.String(), nullable=True),
        sa.Column('impact_description', sa.Text(), nullable=True),
        sa.Column('vulnerabilities_found', sa.Text(), nullable=True),
        sa.Column('execution_duration_seconds', sa.Float(), nullable=True),
        sa.Column('queued_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.ForeignKeyConstraint(['step_id'], ['attack_sequence_steps.step_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_attack_executions_execution_id', 'attack_executions', ['execution_id'], unique=True)
    op.create_index('ix_attack_executions_tenant_id', 'attack_executions', ['tenant_id'])
    op.create_index('ix_attack_executions_step_id', 'attack_executions', ['step_id'])

    op.create_table(
        'tool_usage',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('usage_id', sa.String(), nullable=False, unique=True),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('exercise_id', sa.String(), nullable=True),
        sa.Column('simulation_id', sa.String(), nullable=True),
        sa.Column('sequence_step_id', sa.String(), nullable=True),
        sa.Column('tool_name', sa.String(), nullable=False),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('args', sa.Text(), nullable=True),
        sa.Column('target', sa.String(), nullable=True),
        sa.Column('return_code', sa.Integer(), nullable=True),
        sa.Column('stdout', sa.Text(), nullable=True),
        sa.Column('stderr', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('timeout_seconds', sa.Integer(), nullable=True),
        sa.Column('timed_out', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('mitre_technique_id', sa.String(), nullable=True),
        sa.Column('attack_phase', sa.String(), nullable=True),
        sa.Column('invoked_by', sa.String(), nullable=True),
        sa.Column('invocation_source', sa.String(), nullable=False, server_default='api'),
        sa.Column('tool_server_url', sa.String(), nullable=True),
        sa.Column('output_size_bytes', sa.Integer(), nullable=True),
        sa.Column('metadata', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['sequence_step_id'], ['attack_sequence_steps.step_id'], ondelete='SET NULL'),
    )
    op.create_index('ix_tool_usage_usage_id', 'tool_usage', ['usage_id'], unique=True)
    op.create_index('ix_tool_usage_tenant_id', 'tool_usage', ['tenant_id'])
    op.create_index('ix_tool_usage_exercise_id', 'tool_usage', ['exercise_id'])
    op.create_index('ix_tool_usage_simulation_id', 'tool_usage', ['simulation_id'])
    op.create_index('ix_tool_usage_tool_name', 'tool_usage', ['tool_name'])
    op.create_index('ix_tool_usage_sequence_step_id', 'tool_usage', ['sequence_step_id'])


def downgrade() -> None:
    """Drop all Phase 0/1 persistence tables."""

    # Tool Tracking (drop in reverse dependency order)
    op.drop_table('tool_usage')
    op.drop_table('attack_executions')
    op.drop_table('attack_sequence_steps')
    op.drop_table('attack_sequences')

    # Threat Intelligence (reverse dependency order)
    op.drop_table('threat_reports')
    op.drop_table('threat_ttps')
    op.drop_table('threat_indicators')
    op.drop_table('malware_families')
    op.drop_table('threat_campaigns')
    op.drop_table('threat_actors')

    # Blue Team
    op.drop_table('incidents')
    op.drop_table('alerts')

    # Red Team
    op.drop_table('attack_steps')
    op.drop_table('attack_results')
    op.drop_table('attack_plans')

    # Simulation
    op.drop_table('simulation_stages')
    op.drop_table('simulation_results')

    # Audit
    op.drop_table('audit_events')

    # Auth
    op.drop_table('users')
    op.drop_table('tenants')
