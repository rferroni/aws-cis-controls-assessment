# HTML Report Generation Architecture — Reusable Reference

This document captures the complete architecture, patterns, and implementation details of the
AWS CIS Assessment Framework's HTML report generation system. It is designed to be used as a
reference for reproducing a similar self-contained, single-file HTML report generator in another
Python project.

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI (click)                              │
│  main.py → assess command → _generate_reports()                 │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Assessment Engine                             │
│  assessment_engine.py                                           │
│  - Collects data from AWS APIs (boto3)                          │
│  - Runs each control assessment class                           │
│  - Produces: AssessmentResult + ComplianceSummary               │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Scoring Engine                                │
│  scoring_engine.py                                              │
│  - Calculates per-control, per-IG, and overall scores           │
│  - Calculates coverage metrics from YAML configs                │
│  - Produces: ComplianceSummary with scores + remediation         │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Base Reporter                                  │
│  base_reporter.py → ReportGenerator (abstract base)             │
│  - _prepare_report_data(): transforms models → flat dicts       │
│  - _prepare_ig_data(), _prepare_control_data()                  │
│  - _prepare_finding_data(), _prepare_remediation_data()         │
│  - Deduplicates resources across IGs                            │
│  - Output: standardized report_data dict                        │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   HTML Reporter                                  │
│  html_reporter.py → HTMLReporter(ReportGenerator)               │
│  - _enhance_html_structure(): adds visual metadata              │
│  - _generate_html_content(): assembles full HTML document       │
│  - Produces: single self-contained .html file                   │
│    (all CSS + JS + data inline, no external dependencies)       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Principle: Single-File Output
The HTML report is a **completely self-contained single `.html` file**. All CSS, JavaScript,
and data are inlined. No external CDN links, no separate asset files. This means the report
can be emailed, uploaded to S3, or opened offline with zero dependencies.

---

## 2. Data Models (dataclasses)

All data flows through Python `@dataclass` objects defined in `core/models.py`.

### 2.1 Core Models

```python
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum

class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

class ImplementationGroup(Enum):
    IG1 = "IG1"
    IG2 = "IG2"
    IG3 = "IG3"

@dataclass
class ComplianceResult:
    """Individual resource evaluation result — the atomic unit of data."""
    resource_id: str          # e.g. "arn:aws:s3:::my-bucket"
    resource_type: str        # e.g. "AWS::S3::Bucket"
    compliance_status: ComplianceStatus
    evaluation_reason: str    # Human-readable explanation
    config_rule_name: str     # e.g. "s3-bucket-versioning-enabled"
    region: str               # e.g. "eu-west-1"
    timestamp: datetime = field(default_factory=datetime.now)
    remediation_guidance: Optional[str] = None

@dataclass
class ControlScore:
    """Aggregated score for one control (e.g. CIS Control 1.1)."""
    control_id: str
    title: str
    implementation_group: str
    total_resources: int
    compliant_resources: int
    compliance_percentage: float
    config_rules_evaluated: List[str] = field(default_factory=list)
    findings: List[ComplianceResult] = field(default_factory=list)

@dataclass
class IGScore:
    """Aggregated score for one Implementation Group (IG1/IG2/IG3)."""
    implementation_group: str
    total_controls: int
    compliant_controls: int
    compliance_percentage: float
    control_scores: Dict[str, ControlScore] = field(default_factory=dict)

@dataclass
class AssessmentResult:
    """Top-level assessment output — input to the reporter."""
    account_id: str
    regions_assessed: List[str]
    timestamp: datetime
    overall_score: float
    aws_config_score: float = 0.0
    ig_scores: Dict[str, IGScore] = field(default_factory=dict)
    total_resources_evaluated: int = 0
    assessment_duration: Optional[timedelta] = None

@dataclass
class CoverageMetrics:
    """How much of the framework is covered by implemented rules."""
    implementation_group: str
    total_safeguards: int
    covered_safeguards: int
    coverage_percentage: float
    implemented_rules: int

@dataclass
class ComplianceSummary:
    """Executive summary — second input to the reporter."""
    overall_compliance_percentage: float
    ig1_compliance_percentage: float
    ig2_compliance_percentage: float
    ig3_compliance_percentage: float
    top_risk_areas: List[str] = field(default_factory=list)
    remediation_priorities: List[RemediationGuidance] = field(default_factory=list)
    coverage_metrics: Dict[str, CoverageMetrics] = field(default_factory=dict)
```

### 2.2 Adapting for Another Project

Replace the domain-specific names but keep the hierarchy:
- `ComplianceResult` → your atomic evaluation result (e.g. `CheckResult`, `FindingResult`)
- `ControlScore` → your grouping unit (e.g. `CategoryScore`, `RuleGroupScore`)
- `IGScore` → your top-level grouping (e.g. `SeverityGroup`, `DomainScore`)
- `AssessmentResult` → your overall run result
- `ComplianceSummary` → your executive summary

---

## 3. Data Pipeline (Base Reporter)

The `ReportGenerator` base class transforms dataclass models into flat dictionaries
suitable for HTML rendering. This is the **data normalization layer**.

### 3.1 Entry Point

```python
class ReportGenerator:
    def _prepare_report_data(self, assessment_result, compliance_summary) -> dict:
        """Transform models into a standardized dict structure."""

        # Step 1: Deduplicate resources across groups
        unique_resources = {}
        for ig_name, ig_score in assessment_result.ig_scores.items():
            for control_id, control in ig_score.control_scores.items():
                for finding in control.findings:
                    key = (finding.resource_id, finding.resource_type,
                           finding.region, finding.config_rule_name)
                    unique_resources[key] = finding

        # Step 2: Count from deduplicated set
        total = len(unique_resources)
        compliant = sum(1 for f in unique_resources.values()
                        if f.compliance_status.value == 'COMPLIANT')

        # Step 3: Build standardized structure
        return {
            'metadata': { ... },           # account, regions, timestamp
            'executive_summary': { ... },  # percentages, counts, risk areas
            'implementation_groups': self._prepare_ig_data(ig_scores),
            'remediation_priorities': self._prepare_remediation_data(...),
            'detailed_findings': self._prepare_findings_data(ig_scores),
        }
```

### 3.2 Output Structure (report_data dict)

```python
{
    "metadata": {
        "account_id": "123456789012",
        "regions_assessed": ["eu-west-1", "us-east-1"],
        "report_generated_at": "2026-02-10T14:00:00",
        "assessment_duration": "0:05:23"
    },
    "executive_summary": {
        "overall_compliance_percentage": 41.2,
        "total_resources": 1786,
        "compliant_resources": 736,
        "non_compliant_resources": 1050,
        "top_risk_areas": ["Encryption at Rest", "Access Control"],
        "coverage_metrics": { ... }
    },
    "implementation_groups": {
        "IG1": {
            "compliance_percentage": 45.3,
            "total_controls": 24,
            "controls": {
                "1.1": {
                    "control_id": "1.1",
                    "title": "Establish Enterprise Asset Inventory",
                    "compliance_percentage": 80.0,
                    "config_rules_evaluated": ["ec2-instance-managed-by-ssm", ...],
                    "non_compliant_findings": [ ... ],
                    "compliant_findings": [ ... ]
                },
                ...
            }
        },
        "IG2": { ... },
        "IG3": { ... }
    },
    "remediation_priorities": [ ... ]
}
```

---

## 4. HTML Reporter — The Rendering Layer

### 4.1 Class Hierarchy

```python
class HTMLReporter(ReportGenerator):
    """Inherits data preparation, adds HTML-specific rendering."""

    def generate_report(self, assessment_result, compliance_summary, output_path=None):
        # 1. Prepare data (inherited from base)
        report_data = self._prepare_report_data(assessment_result, compliance_summary)

        # 2. Enhance with HTML-specific visual metadata
        html_data = self._enhance_html_structure(report_data)

        # 3. Generate HTML string
        html_content = self._generate_html_content(html_data)

        # 4. Optionally save to file
        if output_path:
            self._save_report_to_file(html_content, output_path)

        return html_content
```

### 4.2 Enhancement Layer (_enhance_html_structure)

This method adds visual metadata to the flat data dict:

```python
def _enhance_html_structure(self, report_data):
    html_data = {"report_format": "html", **report_data}

    # Add compliance grade (A/B/C/D/F)
    exec_summary = html_data["executive_summary"]
    exec_summary["compliance_grade"] = self._calculate_compliance_grade(pct)
    exec_summary["risk_level"] = self._calculate_risk_level(pct)
    exec_summary["status_color"] = self._get_status_color(pct)

    # Add chart data
    html_data["chart_data"] = self._prepare_chart_data(html_data)

    # Enhance each control with visual indicators
    for ig_name, ig_data in html_data["implementation_groups"].items():
        ig_data["status_color"] = self._get_status_color(ig_data["compliance_percentage"])
        for control_id, control_data in ig_data["controls"].items():
            control_data["status_color"] = self._get_status_color(...)
            control_data["severity_badge"] = self._get_severity_badge(...)
            # Enrich with display names, IG badges, tooltips
            self._enrich_control_metadata(control_data, control_id, ig_name, ...)

    # Build navigation structure
    html_data["navigation"] = self._build_navigation_structure(html_data)

    return html_data
```

### 4.3 HTML Generation (_generate_html_content)

The HTML document is assembled from method calls, NOT from template files:

```python
def _generate_html_content(self, html_data):
    html_head = self._generate_html_head(html_data)   # <head> with inline CSS
    html_body = self._generate_html_body(html_data)    # <body> with all sections
    return f"<!DOCTYPE html>\n<html lang=\"en\">\n{html_head}\n{html_body}\n</html>"

def _generate_html_body(self, html_data):
    header              = self._generate_header(html_data)
    navigation          = self._generate_navigation(html_data)
    executive_dashboard = self._generate_executive_dashboard(html_data)
    implementation_groups = self._generate_implementation_groups_section(html_data)
    controls_overview   = self._generate_controls_overview_section(html_data)
    resource_details    = self._generate_resource_details_section(html_data)
    footer              = self._generate_footer(html_data)

    return f"""<body>
    <div class="container">
        {header}
        {navigation}
        {executive_dashboard}
        {implementation_groups}
        {controls_overview}
        {resource_details}
        {footer}
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            initializeCharts();
            initializeInteractivity();
        }});
    </script>
</body>"""
```

### 4.4 HTML Head — Inline CSS

```python
def _generate_html_head(self, html_data):
    css = self._get_css_styles()       # Returns ~1100 lines of CSS as a string
    js = self._get_javascript_code(html_data)  # Returns ~500 lines of JS
    return f"""<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Controls Assessment Report - {html_data['metadata']['account_id']}</title>
    <style>{css}</style>
    <script>{js}</script>
</head>"""
```

Everything is inlined — no external `<link>` or `<script src>` tags.

---

## 5. Report Sections — Detailed Breakdown

Each section is a method that returns an HTML string built with Python f-strings.

### 5.1 Header

```python
def _generate_header(self, html_data):
    return f"""
    <div class="header" id="header">
        <h1>AWS CIS Controls Assessment Report</h1>
        <div class="subtitle">
            Account: {html_data['metadata']['account_id']} |
            Regions: {', '.join(html_data['metadata']['regions_assessed'])} |
            Generated: {html_data['metadata']['report_generated_at'][:10]}
        </div>
    </div>"""
```

### 5.2 Navigation Sidebar

Built dynamically from the sections present in the data:

```python
def _build_navigation_structure(self, html_data):
    nav_items = [
        {"id": "executive-dashboard", "label": "Executive Dashboard", "icon": "📊"},
        {"id": "implementation-groups", "label": "Implementation Groups", "icon": "🏗️"},
        {"id": "controls-overview", "label": "CIS Controls Overview", "icon": "📋"},
        {"id": "resource-details", "label": "Resource Details", "icon": "🔍"},
    ]
    return {"items": nav_items}
```

### 5.3 Executive Dashboard

Shows 4 summary cards + score comparison + coverage metrics:

```
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Overall Score    │ Resources        │ Compliant        │ Non-Compliant    │
│ 41.2%           │ 1,786            │ 736 (41.2%)      │ 1,050 (58.8%)    │
│ Grade: D        │ Across 2 regions │                  │                  │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

Pattern: each card is a `<div class="metric-card">` with a value, label, and sublabel.

### 5.4 Implementation Groups Section

For each IG (IG1, IG2, IG3), shows:
- IG header with compliance percentage and progress bar
- Grid of control cards, each showing:
  - Control ID + display name (with tooltip)
  - Compliance bar (color-coded: green >75%, yellow 50-75%, red <50%)
  - Resource counts (compliant / total)
  - IG badge showing which IGs the control belongs to

Controls are sorted numerically using a helper:

```python
def _sort_control_id(self, control_id: str) -> tuple:
    """Sort '1.1' before '1.5' before '2.2' etc."""
    parts = control_id.split('.')
    return tuple(int(p) if p.isdigit() else float('inf') for p in parts)
```

### 5.5 CIS Controls Overview Table

A comprehensive sortable/filterable table of all controls across all IGs:

```
┌────────┬─────────────────────┬────┬──────────────────────┬───────┬───────┬───────┬────────┐
│Ctrl ID │ Safeguard Name      │ IG │ Rules                │ Compl │ Non-C │ Total │ Comp % │
├────────┼─────────────────────┼────┼──────────────────────┼───────┼───────┼───────┼────────┤
│ 1.1    │ Enterprise Asset... │IG1 │ ec2-instance-managed │  45   │  12   │  57   │ 78.9%  │
│ 1.5    │ Account Inventory   │IG1 │ iam-user-unused...   │  3    │  2    │  5    │ 60.0%  │
└────────┴─────────────────────┴────┴──────────────────────┴───────┴───────┴───────┴────────┘
```

Features:
- Summary cards above the table (total controls, avg compliance, fully compliant, needs attention)
- Filter bar: IG dropdown, Rules dropdown (all unique rule names), text search
- Sortable columns (click header to sort asc/desc)
- Hover tooltips on Safeguard Name and Rules columns (for truncated text)
- Control ID is a clickable link that jumps to the Resource Details section
- Column widths: Control ID 5%, Safeguard Name 27%, IG 4%, Rules 30%, Compliant 7%, Non-Compliant 7%, Total 5%, Compliance 15%

Data is built by `_build_controls_overview_data()` which:
1. Iterates all IGs and their controls
2. Deduplicates controls that appear in multiple IGs (keeps lowest IG)
3. Looks up full CIS v8.1 safeguard names from a 153-entry dictionary
4. Collects all config rule names per control
5. Aggregates compliant/non-compliant/total counts

### 5.6 Resource Details Section

A filterable table of every individual resource evaluation:

```
┌──────────────────────┬──────────────────┬──────────┬────────────┬──────────────────────┐
│ Resource ID          │ Resource Type    │ Region   │ Status     │ Evaluation Details   │
├──────────────────────┼──────────────────┼──────────┼────────────┼──────────────────────┤
│ arn:aws:s3:::bucket  │ AWS::S3::Bucket  │ eu-west-1│ NON_COMPL  │ Versioning disabled  │
└──────────────────────┴──────────────────┴──────────┴────────────┴──────────────────────┘
```

Features:
- Filter bar: Status dropdown, Resource Type dropdown, Control dropdown, text search
- Hover tooltips on Resource ID and Resource Type columns
- CSV and JSON export buttons
- Pagination (shows count of visible/total)

### 5.7 Footer

```python
def _generate_footer(self, html_data):
    return f"""
    <div class="footer">
        <p>Generated by AWS CIS Controls Assessment Framework v{version}</p>
        <p>© {datetime.now().year} — Assessment Date: {timestamp}</p>
    </div>"""
```

---

## 6. CSS Design System

All CSS is returned by `_get_css_styles()` as a single string (~1100 lines).

### 6.1 Design Tokens

```css
/* Color palette */
--success: #27ae60;    /* Green — compliant */
--warning: #f39c12;    /* Yellow — partial */
--danger: #e74c3c;     /* Red — non-compliant */
--info: #3498db;       /* Blue — informational */
--primary: #667eea;    /* Purple gradient start */
--secondary: #764ba2;  /* Purple gradient end */

/* Typography */
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
line-height: 1.6;

/* Layout */
.container { max-width: 1200px; margin: 0 auto; }
```

### 6.2 Key CSS Patterns

```css
/* Metric cards — used in Executive Dashboard and Controls Overview */
.metric-card {
    background: white;
    border-radius: 10px;
    padding: 25px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    text-align: center;
    border-top: 4px solid var(--color);
}

/* Progress bars — used everywhere for compliance percentages */
.progress-bar {
    height: 8px;
    background-color: #e0e0e0;
    border-radius: 4px;
    overflow: hidden;
}
.progress-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s ease;
    /* Color set inline based on percentage */
}

/* Control cards — grid layout */
.control-card {
    background: white;
    border-radius: 8px;
    padding: 15px;
    border-left: 4px solid var(--status-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

/* Sortable table headers */
th.sortable { cursor: pointer; }
th.sortable:hover { background-color: #e8e8e8; }
th.sort-asc::after { content: " ▲"; }
th.sort-desc::after { content: " ▼"; }

/* Tooltip pattern (CSS-only via title attribute + span wrapper) */
td span[title] {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
td span[title]:hover {
    /* Browser shows native tooltip from title attribute */
}

/* Filter bar */
.filter-bar {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
    flex-wrap: wrap;
    align-items: center;
}
.filter-bar select, .filter-bar input {
    padding: 8px 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
}
```

### 6.3 Responsive Design

```css
@media (max-width: 768px) {
    .metric-cards { grid-template-columns: 1fr 1fr; }
    .nav-list { flex-direction: column; }
    .control-grid { grid-template-columns: 1fr; }
}
```

---

## 7. JavaScript Patterns

All JS is returned by `_get_javascript_code()` as a single string (~500 lines).
No external libraries — pure vanilla JS.

### 7.1 Initialization

```javascript
function initializeCharts() {
    // Set up any chart canvases (risk distribution pie chart)
}

function initializeInteractivity() {
    // Set up event listeners for filters, search, sort
    setupResourceDetailsFilters();
    setupControlsOverviewFilters();
}
```

### 7.2 Filtering Pattern

Every filterable section follows the same pattern:

```javascript
function filterResourceDetails() {
    var statusFilter = document.getElementById('statusFilter').value;
    var typeFilter = document.getElementById('typeFilter').value;
    var searchFilter = document.getElementById('searchFilter').value.toLowerCase();

    var rows = document.querySelectorAll('#resourceTable tbody tr');
    var visibleCount = 0;

    rows.forEach(function(row) {
        var status = row.getAttribute('data-status');
        var type = row.getAttribute('data-type');
        var text = row.textContent.toLowerCase();

        var show = true;
        if (statusFilter && status !== statusFilter) show = false;
        if (typeFilter && type !== typeFilter) show = false;
        if (searchFilter && text.indexOf(searchFilter) === -1) show = false;

        row.style.display = show ? '' : 'none';
        if (show) visibleCount++;
    });

    document.getElementById('visibleCount').textContent = visibleCount;
}
```

### 7.3 Sorting Pattern

```javascript
function sortControlsOverviewTable(columnIndex) {
    var table = document.getElementById('controlsOverviewTable');
    var tbody = table.querySelector('tbody');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    var header = table.querySelectorAll('th')[columnIndex];

    // Toggle sort direction
    var isAsc = header.classList.contains('sort-asc');
    table.querySelectorAll('th').forEach(function(th) {
        th.classList.remove('sort-asc', 'sort-desc');
    });
    header.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

    rows.sort(function(a, b) {
        var aVal = a.cells[columnIndex].getAttribute('data-sort-value')
                   || a.cells[columnIndex].textContent.trim();
        var bVal = b.cells[columnIndex].getAttribute('data-sort-value')
                   || b.cells[columnIndex].textContent.trim();

        // Numeric sort if both are numbers
        var aNum = parseFloat(aVal);
        var bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }
        return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
    });

    rows.forEach(function(row) { tbody.appendChild(row); });
}
```

### 7.4 CSV Export Pattern

```javascript
function exportToCSV() {
    var table = document.getElementById('resourceTable');
    var rows = table.querySelectorAll('tr:not([style*="display: none"])');
    var csv = '\uFEFF';  // UTF-8 BOM for Excel compatibility

    rows.forEach(function(row) {
        var cols = row.querySelectorAll('td, th');
        var rowData = [];
        cols.forEach(function(col) {
            var text = col.textContent.replace(/"/g, '""');
            rowData.push('"' + text + '"');
        });
        csv += rowData.join(',') + '\n';
    });

    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'report-export.csv';
    link.click();
}
```

---

## 8. HTML Generation Patterns (Python f-strings)

### 8.1 Metric Card Pattern

```python
def _generate_metric_card(self, value, label, sublabel="", color="#3498db"):
    return f"""
    <div class="metric-card" style="border-top-color: {color};">
        <div class="metric-value">{value}</div>
        <div class="metric-label">{label}</div>
        <div class="metric-sublabel">{sublabel}</div>
    </div>"""
```

### 8.2 Progress Bar Pattern

```python
def _generate_progress_bar(self, percentage, color):
    display_width = max(percentage, 5) if percentage > 0 else 0  # Min 5% for visibility
    return f"""
    <div class="progress-bar">
        <div class="progress-fill" style="width: {display_width}%; background-color: {color};"></div>
    </div>
    <span class="compliance-text">{percentage:.1f}%</span>"""
```

### 8.3 Table Row with Data Attributes Pattern

```python
# Data attributes on <tr> enable JS filtering without re-parsing text
row_html = f"""
<tr data-status="{status}" data-type="{resource_type}"
    data-control="{control_id}" data-rules="{rules_str}">
    <td><span title="{resource_id}">{truncated_id}</span></td>
    <td><span title="{resource_type}">{truncated_type}</span></td>
    <td>{region}</td>
    <td><span class="status-badge {status_class}">{status}</span></td>
    <td>{evaluation_reason}</td>
</tr>"""
```

### 8.4 Filter Bar Pattern

```python
filter_html = f"""
<div class="filter-bar">
    <select id="igFilter" onchange="filterControlsOverview()">
        <option value="">All IGs</option>
        <option value="IG1">IG1</option>
        <option value="IG2">IG2</option>
        <option value="IG3">IG3</option>
    </select>
    <select id="rulesFilter" onchange="filterControlsOverview()">
        <option value="">All Rules</option>
        {rule_options}  <!-- dynamically generated from data -->
    </select>
    <input type="text" id="coSearchFilter" placeholder="Search..."
           oninput="filterControlsOverview()">
</div>"""
```

---

## 9. Lookup Dictionaries

The report uses a hardcoded dictionary of 153 CIS v8.1 safeguard names for display:

```python
CIS_V8_SAFEGUARD_NAMES = {
    "1.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
    "1.2": "Address Unauthorized Assets",
    "1.3": "Utilize an Active Discovery Tool",
    "1.4": "Use Dynamic Host Configuration Protocol (DHCP) Logging",
    "1.5": "Use a Passive Asset Discovery Tool",
    # ... 153 entries total
}
```

Control titles are also loaded from YAML config files at runtime:

```python
def _load_control_titles(self) -> Dict[str, str]:
    """Load control titles from YAML config files."""
    if self._control_titles_cache:
        return self._control_titles_cache

    config_dir = Path(__file__).parent.parent / 'config' / 'rules'
    for yaml_file in config_dir.glob('cis_controls_ig*.yaml'):
        with open(yaml_file) as f:
            config = yaml.safe_load(f)
        for control_id, control_data in config.get('controls', {}).items():
            title = control_data.get('title', '')
            if title and not title.startswith('Control '):
                self._control_titles_cache[str(control_id)] = title

    return self._control_titles_cache
```

---

## 10. File Structure for Reproduction

To reproduce this pattern in another project:

```
your_project/
├── core/
│   ├── models.py              # Dataclasses (adapt from Section 2)
│   ├── assessment_engine.py   # Data collection (your domain logic)
│   └── scoring_engine.py      # Score calculation + summary generation
├── reporters/
│   ├── base_reporter.py       # Data normalization (adapt from Section 3)
│   ├── html_reporter.py       # HTML generation (adapt from Sections 4-8)
│   ├── csv_reporter.py        # Optional: CSV export
│   └── json_reporter.py       # Optional: JSON export
├── config/
│   └── rules/                 # YAML config files for your domain rules
└── cli/
    └── main.py                # CLI entry point (click)
```

### Minimal Reproduction Steps

1. Define your data models (dataclasses)
2. Create a base reporter that transforms models → flat dicts
3. Create an HTML reporter that:
   a. Inherits from base reporter
   b. Adds visual metadata (_enhance_html_structure)
   c. Generates HTML sections as f-strings
   d. Inlines all CSS and JS
4. Wire it up in your CLI

### Key Methods to Implement

| Method | Purpose | Lines (approx) |
|--------|---------|----------------|
| `_get_css_styles()` | All CSS as string | ~1100 |
| `_get_javascript_code()` | All JS as string | ~500 |
| `_generate_header()` | Report header | ~20 |
| `_generate_navigation()` | Sidebar nav | ~30 |
| `_generate_executive_dashboard()` | Summary cards | ~100 |
| `_generate_implementation_groups_section()` | Group cards | ~100 |
| `_generate_controls_overview_section()` | Sortable table | ~200 |
| `_generate_resource_details_section()` | Filterable table | ~200 |
| `_generate_footer()` | Footer | ~15 |

---

## 11. Lessons Learned / Tips

1. **f-strings over templates**: For a single-file report, Python f-strings are simpler than
   Jinja2 templates. You avoid template file management and get full Python logic inline.

2. **data- attributes on table rows**: Put all filterable values as `data-*` attributes on
   `<tr>` elements. This makes JS filtering fast (no text parsing needed).

3. **`data-sort-value` on `<td>`**: For columns where display text differs from sort value
   (e.g. "78.9%" displays but sorts as 78.9), use a `data-sort-value` attribute.

4. **Min-width progress bars**: When compliance is 0%, show a thin red bar (min 5% width)
   so the user can still see something. Pure 0-width bars are invisible.

5. **UTF-8 BOM for CSV**: Always prepend `\uFEFF` to CSV exports so Excel opens them correctly.

6. **Tooltip pattern**: Use `<span title="full text">truncated...</span>` inside `<td>`.
   Set `overflow: hidden; text-overflow: ellipsis; white-space: nowrap;` on the span.
   The browser's native tooltip shows the full text on hover.

7. **Deduplication**: When the same resource appears in multiple groups, deduplicate by
   a composite key (resource_id, resource_type, region, rule_name) before counting.

8. **Numeric sorting for IDs**: Control IDs like "1.1", "1.5", "2.2" need numeric sorting.
   Split on "." and convert each part to int for proper ordering.

9. **Color coding**: Use a simple threshold function:
   - ≥75%: green (#27ae60)
   - 50-74%: yellow (#f39c12)
   - <50%: red (#e74c3c)

10. **No external dependencies**: The entire report is one .html file. No CDN links, no
    separate CSS/JS files. This makes it portable, email-friendly, and works offline.
