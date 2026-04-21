#!/usr/bin/env python3
"""Generate a sample HTML report with fake data for demonstration purposes."""

import sys
import os
import random
from datetime import datetime, timedelta

# Add parent directory to path so we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_cis_assessment.core.models import (
    AssessmentResult, ComplianceSummary, ComplianceResult, ComplianceStatus,
    ControlScore, IGScore, CoverageMetrics, RemediationGuidance
)
from aws_cis_assessment.reporters.html_reporter import HTMLReporter
from aws_cis_assessment.reporters.json_reporter import JSONReporter

# Sample controls with realistic names
SAMPLE_CONTROLS = {
    "IG1": {
        "1.1": ("Establish and Maintain Detailed Enterprise Asset Inventory", [
            ("eip-attached", "AWS::EC2::EIP"),
            ("ec2-stopped-instance", "AWS::EC2::Instance"),
            ("ec2-instance-managed-by-systems-manager", "AWS::EC2::Instance"),
        ]),
        "3.3": ("Configure Data Access Control Lists", [
            ("s3-bucket-public-read-prohibited", "AWS::S3::Bucket"),
            ("iam-policy-no-statements-with-admin-access", "AWS::IAM::Policy"),
            ("ec2-instance-no-public-ip", "AWS::EC2::Instance"),
        ]),
        "3.11": ("Encrypt Sensitive Data at Rest", [
            ("ebs-encryption-by-default", "AWS::EC2::Volume"),
            ("rds-storage-encrypted", "AWS::RDS::DBInstance"),
            ("s3-default-encryption-kms", "AWS::S3::Bucket"),
        ]),
        "4.1": ("Establish and Maintain a Secure Configuration Process", [
            ("access-keys-rotated", "AWS::IAM::User"),
            ("secretsmanager-rotation-enabled-check", "AWS::SecretsManager::Secret"),
        ]),
        "8.2": ("Collect Audit Logs", [
            ("cloudtrail-enabled", "AWS::::Account"),
            ("vpc-flow-logs-enabled", "AWS::EC2::VPC"),
        ]),
        "11.2": ("Automated Backups", [
            ("db-instance-backup-enabled", "AWS::RDS::DBInstance"),
            ("dynamodb-pitr-enabled", "AWS::DynamoDB::Table"),
        ]),
    },
    "IG2": {
        "3.10": ("Encrypt Sensitive Data in Transit", [
            ("alb-http-to-https-redirection-check", "AWS::ElasticLoadBalancingV2::LoadBalancer"),
            ("elb-tls-https-listeners-only", "AWS::ElasticLoadBalancing::LoadBalancer"),
        ]),
        "5.2": ("Use Unique Passwords", [
            ("iam-password-policy", "AWS::::Account"),
            ("mfa-enabled-for-iam-console-access", "AWS::IAM::User"),
        ]),
    },
    "IG3": {
        "12.8": ("Establish and Maintain Dedicated Computing Resources", [
            ("vpc-sg-open-only-to-authorized-ports", "AWS::EC2::SecurityGroup"),
        ]),
        "13.1": ("Centralize Security Event Alerting", [
            ("restricted-incoming-traffic", "AWS::EC2::SecurityGroup"),
        ]),
    },
}

SAMPLE_RESOURCES = {
    "AWS::EC2::Instance": ["i-0a1b2c3d4e5f60001", "i-0a1b2c3d4e5f60002", "i-0a1b2c3d4e5f60003",
                           "i-0a1b2c3d4e5f60004", "i-0a1b2c3d4e5f60005"],
    "AWS::S3::Bucket": ["company-data-bucket", "logs-archive-bucket", "static-assets-bucket",
                         "backup-bucket-prod", "config-bucket"],
    "AWS::RDS::DBInstance": ["prod-database-1", "analytics-db", "staging-db"],
    "AWS::EC2::EIP": ["eipalloc-0a1b2c3d", "eipalloc-0e5f6a7b"],
    "AWS::IAM::Policy": ["AdminPolicy", "DeveloperPolicy", "ReadOnlyPolicy"],
    "AWS::IAM::User": ["admin-user", "developer-1", "ci-service-account", "analyst-user"],
    "AWS::EC2::Volume": ["vol-0a1b2c3d4e5f6001", "vol-0a1b2c3d4e5f6002", "vol-0a1b2c3d4e5f6003"],
    "AWS::EC2::VPC": ["vpc-0a1b2c3d", "vpc-0e5f6a7b"],
    "AWS::DynamoDB::Table": ["users-table", "sessions-table", "audit-log-table"],
    "AWS::SecretsManager::Secret": ["prod/database/password", "prod/api/key"],
    "AWS::ElasticLoadBalancingV2::LoadBalancer": ["app-lb-prod", "api-lb-prod"],
    "AWS::ElasticLoadBalancing::LoadBalancer": ["classic-lb-legacy"],
    "AWS::EC2::SecurityGroup": ["sg-web-servers", "sg-database", "sg-admin-access"],
}


def generate_findings(rule_name, resource_type, region, compliance_rate=0.7):
    """Generate fake compliance findings for a rule."""
    findings = []
    resources = SAMPLE_RESOURCES.get(resource_type, [f"resource-{i}" for i in range(3)])

    for resource_id in resources:
        is_compliant = random.random() < compliance_rate
        status = ComplianceStatus.COMPLIANT if is_compliant else ComplianceStatus.NON_COMPLIANT

        if is_compliant:
            reason = f"Resource {resource_id} meets {rule_name} requirements"
        else:
            reasons = [
                f"Resource {resource_id} does not meet {rule_name} requirements",
                f"{resource_id}: configuration does not comply with {rule_name}",
                f"Non-compliant: {resource_id} requires remediation for {rule_name}",
            ]
            reason = random.choice(reasons)

        findings.append(ComplianceResult(
            resource_id=resource_id,
            resource_type=resource_type,
            compliance_status=status,
            evaluation_reason=reason,
            config_rule_name=rule_name,
            region=region,
            timestamp=datetime.now(),
        ))
    return findings


def build_sample_data():
    """Build complete sample assessment data."""
    random.seed(42)  # Reproducible results
    region = "us-east-1"
    ig_scores = {}
    all_findings = []

    for ig_name, controls in SAMPLE_CONTROLS.items():
        control_scores = {}
        ig_compliant = 0

        for control_id, (title, rules) in controls.items():
            control_findings = []
            for rule_name, resource_type in rules:
                rate = random.uniform(0.5, 0.95)
                findings = generate_findings(rule_name, resource_type, region, rate)
                control_findings.extend(findings)
                all_findings.extend(findings)

            total = len(control_findings)
            compliant = sum(1 for f in control_findings if f.compliance_status == ComplianceStatus.COMPLIANT)
            pct = (compliant / total * 100) if total > 0 else 0

            control_scores[control_id] = ControlScore(
                control_id=control_id,
                title=title,
                implementation_group=ig_name,
                total_resources=total,
                compliant_resources=compliant,
                compliance_percentage=pct,
                config_rules_evaluated=[r[0] for r in rules],
                findings=control_findings,
            )
            if pct >= 80:
                ig_compliant += 1

        total_controls = len(control_scores)
        ig_pct = sum(cs.compliance_percentage for cs in control_scores.values()) / total_controls if total_controls else 0

        ig_scores[ig_name] = IGScore(
            implementation_group=ig_name,
            total_controls=total_controls,
            compliant_controls=ig_compliant,
            compliance_percentage=ig_pct,
            control_scores=control_scores,
        )

    total_resources = len(all_findings)
    total_compliant = sum(1 for f in all_findings if f.compliance_status == ComplianceStatus.COMPLIANT)
    overall = sum(ig.compliance_percentage for ig in ig_scores.values()) / len(ig_scores)

    assessment_result = AssessmentResult(
        account_id="123456789012",
        regions_assessed=[region],
        timestamp=datetime.now(),
        overall_score=overall,
        aws_config_score=total_compliant / total_resources * 100 if total_resources else 0,
        ig_scores=ig_scores,
        total_resources_evaluated=total_resources,
        assessment_duration=timedelta(minutes=12, seconds=34),
    )

    compliance_summary = ComplianceSummary(
        overall_compliance_percentage=overall,
        ig1_compliance_percentage=ig_scores.get("IG1", IGScore("IG1", 0, 0, 0)).compliance_percentage,
        ig2_compliance_percentage=ig_scores.get("IG2", IGScore("IG2", 0, 0, 0)).compliance_percentage,
        ig3_compliance_percentage=ig_scores.get("IG3", IGScore("IG3", 0, 0, 0)).compliance_percentage,
        top_risk_areas=["Data Access Control", "Encryption at Rest", "Network Security"],
        coverage_metrics={
            "IG1": CoverageMetrics("IG1", 56, 24, 42.9, 122),
            "IG2": CoverageMetrics("IG2", 74, 27, 36.5, 75),
            "IG3": CoverageMetrics("IG3", 153, 30, 19.6, 13),
        },
    )

    return assessment_result, compliance_summary


def main():
    base_dir = os.path.dirname(__file__)
    html_path = os.path.join(base_dir, "sample-report.html")
    json_path = os.path.join(base_dir, "sample-report.json")

    print("Generating sample reports with fake data...")
    assessment_result, compliance_summary = build_sample_data()

    reporter = HTMLReporter()
    html_content = reporter.generate_report(assessment_result, compliance_summary, html_path)

    json_reporter = JSONReporter()
    json_content = json_reporter.generate_report(assessment_result, compliance_summary, json_path)

    if html_content:
        print(f"✅ HTML report: {html_path}")
    else:
        print("❌ Failed to generate HTML report")

    if json_content:
        print(f"✅ JSON report: {json_path}")
    else:
        print("❌ Failed to generate JSON report")

    print("   Open the HTML file in your browser to preview the report.")


if __name__ == "__main__":
    main()
