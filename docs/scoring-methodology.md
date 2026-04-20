# Compliance Scoring Methodology

This document explains how compliance scores are calculated in the AWS CIS Controls Assessment Framework.

## Overview

The scoring system uses a **weighted, hierarchical approach** that calculates compliance at three levels:
1. **Control Level** - Individual CIS Control compliance
2. **Implementation Group Level** - IG1, IG2, IG3 compliance
3. **Overall Score** - Aggregate compliance across all IGs

## Scoring Hierarchy

```
Overall Score (0-100%)
├── IG1 Score (weight: 1.0)
│   ├── Control 1.1 (weight: 1.0)
│   ├── Control 3.3 (weight: 1.5)
│   └── ... (74 controls)
├── IG2 Score (weight: 1.5)
│   ├── Control 3.10 (weight: 1.4)
│   ├── Control 3.11 (weight: 1.4)
│   └── ... (58 additional controls)
└── IG3 Score (weight: 2.0)
    └── ... (13 additional controls)
```

## 1. Control-Level Scoring

### Basic Calculation

For each CIS Control, the compliance percentage is calculated as:

```
Control Compliance % = (Compliant Resources / Total Resources) × 100
```

**Example:**
- Control 3.3 (Data Access Control)
- Total Resources Evaluated: 50
- Compliant Resources: 40
- Non-Compliant Resources: 10
- **Control Compliance: 80%**

### Resource Status Classification

Resources are classified into these statuses:

| Status | Description | Counted in Score? |
|--------|-------------|-------------------|
| **COMPLIANT** | Resource meets requirements | ✅ Yes (numerator) |
| **NON_COMPLIANT** | Resource fails requirements | ✅ Yes (denominator only) |
| **NOT_APPLICABLE** | Rule doesn't apply to resource | ✅ Yes (excluded from both) |
| **ERROR** | Assessment error occurred | ❌ No (excluded from scoring) |

### Control Weighting

Controls are weighted based on their security criticality:

| Control ID | Weight | Rationale |
|------------|--------|-----------|
| 3.3 | 1.5 | Data Access Control - Critical |
| 3.10 | 1.4 | Encryption in Transit - Critical |
| 3.11 | 1.4 | Encryption at Rest - Critical |
| 5.2 | 1.3 | Password Management - Important |
| 12.8 | 1.3 | Network Segmentation - Important |
| 4.1 | 1.2 | Secure Configuration - Important |
| 3.14 | 1.2 | Sensitive Data Logging - Important |
| 13.1 | 1.2 | Network Monitoring - Important |
| 7.1 | 1.1 | Vulnerability Management - Important |
| 1.1 | 1.0 | Asset Inventory - Foundational |
| Others | 1.0 | Standard weight |

**Weighted Control Score:**
```
Weighted Control Score = Control Compliance % × Control Weight
```

## 2. Implementation Group (IG) Scoring

### IG Compliance Calculation

The IG score is a **weighted average** of all control scores within that IG:

```
IG Compliance % = Σ(Control Compliance % × Control Weight) / Σ(Control Weights)
```

**Example - IG1 with 3 controls:**
- Control 1.1: 90% × 1.0 = 90
- Control 3.3: 80% × 1.5 = 120
- Control 4.1: 75% × 1.2 = 90
- **Total Weighted Score: 300**
- **Total Weight: 3.7**
- **IG1 Compliance: 300 / 3.7 = 81.1%**

### Control Compliance Threshold

A control is considered "compliant" if it achieves **≥80% compliance**. This is used for the "compliant controls" count but doesn't affect the percentage calculation.

### IG Weighting

Implementation Groups have different weights reflecting their security maturity:

| IG | Weight | Description |
|----|--------|-------------|
| **IG1** | 1.0 | Essential Cyber Hygiene (baseline) |
| **IG2** | 1.5 | Enhanced Security (50% more weight) |
| **IG3** | 2.0 | Advanced Security (2x weight) |

## 3. Overall Compliance Score

The overall score is a **weighted average** across all assessed Implementation Groups:

```
Overall Score = Σ(IG Compliance % × IG Weight) / Σ(IG Weights)
```

### Scenario Examples

#### Scenario 1: All IGs Assessed
```
IG1: 85% × 1.0 = 85
IG2: 75% × 1.5 = 112.5
IG3: 60% × 2.0 = 120
Total: 317.5 / 4.5 = 70.6%
```

#### Scenario 2: Only IG1 Assessed
```
IG1: 85% × 1.0 = 85
Total: 85 / 1.0 = 85%
```

#### Scenario 3: IG1 + IG2 Assessed
```
IG1: 85% × 1.0 = 85
IG2: 75% × 1.5 = 112.5
Total: 197.5 / 2.5 = 79%
```

## Scoring Formula Summary

### Complete Formula

```
Overall Score = 
  Σ(IG in [IG1, IG2, IG3]) [
    IG_Weight(IG) × (
      Σ(Control in IG) [
        Control_Weight(Control) × (
          Count(Compliant Resources) / Count(Total Scorable Resources)
        )
      ] / Σ(Control_Weights in IG)
    )
  ] / Σ(IG_Weights)
```

### Simplified View

```
Overall = Weighted Average of IGs
  ├─ IG Score = Weighted Average of Controls
  │    └─ Control Score = Compliant / Total Resources
  └─ Weights applied at both levels
```

## Compliance Ratings

Scores are typically interpreted as:

| Score Range | Rating | Interpretation |
|-------------|--------|----------------|
| 90-100% | **Excellent** | Strong security posture |
| 80-89% | **Good** | Solid compliance, minor gaps |
| 70-79% | **Fair** | Moderate compliance, improvement needed |
| 60-69% | **Poor** | Significant gaps, action required |
| 0-59% | **Critical** | Major security risks, urgent action needed |

## Risk Area Identification

The scoring engine identifies top risk areas by:

1. **Sorting controls** by compliance percentage (lowest first)
2. **Filtering** controls with <80% compliance
3. **Selecting top 5** lowest-scoring controls
4. **Reporting** with control ID, title, and compliance percentage

**Example Risk Areas:**
```
1. Control 3.11 (Encryption at Rest): 45.2% compliant
2. Control 5.2 (Password Management): 52.8% compliant
3. Control 12.8 (Network Segmentation): 61.3% compliant
4. Control 3.10 (Encryption in Transit): 68.7% compliant
5. Control 13.1 (Network Monitoring): 72.4% compliant
```

## Remediation Prioritization

Remediation priorities are calculated using:

### Priority Calculation

```
Priority = f(Control Weight, Affected Resources, Rule Complexity)

HIGH:   Control Weight ≥ 1.4 OR Affected Resources ≥ 10
MEDIUM: Control Weight ≥ 1.2 OR Affected Resources ≥ 5
LOW:    All others
```

### Effort Estimation

```
Effort = f(Affected Resources, Rule Complexity)

Base Effort:
  - Low:    ≤5 resources
  - Medium: 6-20 resources
  - High:   >20 resources

Adjusted for complex rules:
  - IAM password policies
  - VPC security group rules
  - Multi-region CloudTrail
```

## Example: Complete Scoring Walkthrough

### Input Data
```
Assessment of IG1 with 3 controls:

Control 1.1 (Asset Inventory):
  - 100 resources evaluated
  - 90 compliant
  - 10 non-compliant
  - Weight: 1.0

Control 3.3 (Data Access Control):
  - 50 resources evaluated
  - 40 compliant
  - 10 non-compliant
  - Weight: 1.5

Control 4.1 (Secure Configuration):
  - 75 resources evaluated
  - 60 compliant
  - 15 non-compliant
  - Weight: 1.2
```

### Step 1: Calculate Control Scores
```
Control 1.1: 90/100 = 90%
Control 3.3: 40/50 = 80%
Control 4.1: 60/75 = 80%
```

### Step 2: Apply Control Weights
```
Control 1.1: 90% × 1.0 = 90
Control 3.3: 80% × 1.5 = 120
Control 4.1: 80% × 1.2 = 96
Total Weighted: 306
Total Weight: 3.7
```

### Step 3: Calculate IG1 Score
```
IG1 Score = 306 / 3.7 = 82.7%
```

### Step 4: Calculate Overall Score
```
(Only IG1 assessed)
Overall Score = 82.7% × 1.0 / 1.0 = 82.7%
```

### Result
```
Overall Compliance: 82.7% (Good)
IG1 Compliance: 82.7%
Compliant Controls: 2/3 (Controls 3.3 and 4.1 ≥80%)
Total Resources: 225
Compliant Resources: 190
```

## Customization

### Custom Control Weights

You can customize control weights when initializing the scoring engine:

```python
from aws_cis_assessment.core.scoring_engine import ScoringEngine

custom_weights = {
    '3.3': 2.0,  # Increase data access control importance
    '1.1': 0.5,  # Decrease asset inventory importance
}

scoring_engine = ScoringEngine(control_weights=custom_weights)
```

### Custom IG Weights

Similarly, you can adjust IG weights:

```python
custom_ig_weights = {
    'IG1': 1.0,
    'IG2': 1.2,  # Reduce IG2 weight
    'IG3': 1.5,  # Reduce IG3 weight
}

scoring_engine = ScoringEngine(ig_weights=custom_ig_weights)
```

## Scoring Best Practices

1. **Focus on weighted scores** - They reflect security priorities
2. **Track trends over time** - Compare scores across assessments
3. **Prioritize high-weight controls** - Maximum security impact
4. **Address ≥80% threshold** - Get controls to "compliant" status
5. **Review risk areas** - Focus remediation on lowest scores
6. **Consider resource counts** - High resource counts = higher impact

## Limitations

1. **No historical trending** - Current implementation doesn't track score changes over time
2. **Static weights** - Weights don't adapt to organizational priorities automatically
3. **Equal resource weighting** - All resources within a control are weighted equally
4. **No severity levels** - Non-compliance is binary (pass/fail)

## Future Enhancements

Potential improvements to the scoring system:

- **Historical trending** - Track compliance changes over time
- **Severity-based scoring** - Weight findings by severity (critical, high, medium, low)
- **Resource criticality** - Weight production resources higher than dev/test
- **Custom scoring profiles** - Industry-specific weight profiles (finance, healthcare, etc.)
- **Benchmark comparisons** - Compare scores against industry averages
- **Predictive scoring** - Estimate future compliance based on trends

---

**Last Updated**: January 26, 2026  
**Version**: 1.0.8
