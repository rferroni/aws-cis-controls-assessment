# HTML Report Improvements Documentation

## Overview

The HTML reporter has been enhanced with improved readability features and reduced redundancy. This document describes the new features, display formats, and customization options.

## New Features

### 1. Control Display Names

Controls now show both the control ID and the AWS Config rule name together, making it easier to understand what each control checks.

**Display Format:**
- Without title: `{control_id}: {config_rule_name}`
- With title: `{control_id}: {title} ({config_rule_name})`

**Examples:**
```
1.5: root-account-hardware-mfa-enabled
2.1: IAM Password Policy (iam-password-policy)
3.3: cloudtrail-enabled
```

**Truncation:**
- Display names longer than 50 characters are truncated with ellipsis
- Full name appears in a tooltip on hover
- CSS class `.control-display-name.truncated` is applied

### 2. Unique Controls Per Implementation Group

Each Implementation Group section now shows only the controls unique to that level, eliminating duplication.

**Behavior:**
- **IG1**: Shows all foundational controls
- **IG2**: Shows only controls unique to IG2 (not in IG1)
- **IG3**: Shows only controls unique to IG3 (not in IG1 or IG2)

**Visual Indicators:**
- An explanation box clarifies that IGs are cumulative
- Each section header shows the count of unique controls
- Scope descriptions explain what each IG includes

**Example:**
```
IG1 - Essential Cyber Hygiene
Showing 58 foundational controls essential for all organizations.

IG2 - Enhanced Security (includes IG1)
Showing 74 additional controls beyond IG1 for enhanced security.

IG3 - Advanced Security (includes IG1 + IG2)
Showing 24 advanced controls beyond IG1 and IG2 for comprehensive security.
```

### 3. IG Membership Badges

Controls display badges indicating which Implementation Groups include them.

**Badge Colors:**
- **IG1**: Blue (#3498db)
- **IG2**: Green (#27ae60)
- **IG3**: Purple (#9b59b6)

**Display Locations:**
- Implementation Groups section: Shows originating IG badge
- Detailed Findings section: Shows all IGs that include the control

**Example:**
```
Control: 1.5: root-account-hardware-mfa-enabled
Badges: [IG1] [IG2] [IG3]  (appears in all three IGs)

Control: 5.2: encryption-at-rest-enabled
Badges: [IG2] [IG3]  (appears only in IG2 and IG3)
```

### 4. Consolidated Detailed Findings

The Detailed Findings section now groups findings by control ID only, eliminating duplication across IGs.

**Changes:**
- Removed "IG1 Detailed Findings", "IG2 Detailed Findings", "IG3 Detailed Findings" subsections
- Each control appears once with all its findings
- IG membership badges show which IGs include each control
- Findings are sorted alphanumerically by control ID

**Benefits:**
- Easier to remediate issues (each resource listed once)
- Clearer understanding of which IGs are affected
- Reduced report length and improved readability

## CSS Classes for Custom Styling

### IG Badge Classes

```css
/* IG1 badge - Blue */
.ig-badge-1 {
    background-color: #3498db;
    color: white;
}

/* IG2 badge - Green */
.ig-badge-2 {
    background-color: #27ae60;
    color: white;
}

/* IG3 badge - Purple */
.ig-badge-3 {
    background-color: #9b59b6;
    color: white;
}

/* Default badge for unknown IGs */
.ig-badge-default {
    background-color: #95a5a6;
    color: white;
}
```

### Control Display Name Classes

```css
/* Control display name container */
.control-display-name {
    font-weight: 600;
    color: #2c3e50;
    margin-bottom: 5px;
    font-size: 0.95em;
}

/* Truncated display names with tooltip */
.control-display-name.truncated {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: help;
}
```

### IG Membership Badge Container

```css
/* Container for IG membership badges */
.ig-membership-badges {
    display: flex;
    gap: 5px;
    margin-top: 5px;
    margin-bottom: 10px;
}

/* Individual IG membership badge */
.ig-membership-badge {
    font-size: 0.7em;
    padding: 2px 6px;
    border-radius: 10px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
```

### IG Explanation and Scope

```css
/* Informational box explaining IG cumulative nature */
.ig-explanation {
    background-color: #e8f4fd;
    border-left: 4px solid #3498db;
    padding: 15px;
    margin-bottom: 30px;
    border-radius: 5px;
}

/* Scope description for each IG section */
.ig-scope {
    color: #666;
    font-size: 0.9em;
    margin-top: 5px;
}
```

## Customization Examples

### Change IG Badge Colors

To customize the IG badge colors, override the CSS classes:

```css
/* Custom color scheme */
.ig-badge-1 {
    background-color: #e74c3c;  /* Red for IG1 */
    color: white;
}

.ig-badge-2 {
    background-color: #f39c12;  /* Orange for IG2 */
    color: white;
}

.ig-badge-3 {
    background-color: #9b59b6;  /* Keep purple for IG3 */
    color: white;
}
```

### Adjust Truncation Threshold

The default truncation threshold is 50 characters. To change this, modify the `_enrich_control_metadata()` method:

```python
# In html_reporter.py
enriched['needs_truncation'] = len(enriched['display_name']) > 80  # Change to 80 characters
```

### Hide IG Badges

To hide IG badges in the report, add this CSS:

```css
.ig-membership-badges {
    display: none;
}
```

### Customize Control Card Layout

To adjust the control card layout:

```css
.control-card {
    border: 2px solid #3498db;  /* Thicker border */
    border-radius: 12px;         /* More rounded corners */
    padding: 25px;               /* More padding */
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);  /* Gradient background */
}
```

## Backward Compatibility

The improvements maintain full backward compatibility:

1. **Existing Data Structures**: Works with existing `AssessmentResult` data without modification
2. **Graceful Fallback**: If `config_rule_name` is missing, displays control ID only
3. **Preserved Sections**: All existing sections and functionality remain intact
4. **CSS Compatibility**: Existing CSS classes are preserved for custom styling
5. **JavaScript Functions**: All interactive features continue to work

## Migration Notes

No migration is required. The improvements work automatically with existing assessment data:

- Old reports: Show control IDs only (if config_rule_name was not available)
- New reports: Show formatted display names with rule names
- Mixed data: Gracefully handles both old and new data formats

## API Reference

### Key Methods

#### `_format_control_display_name(control_id, config_rule_name, title=None)`
Formats control display name combining ID, rule name, and optional title.

**Parameters:**
- `control_id` (str): Control identifier (e.g., "1.5")
- `config_rule_name` (str): AWS Config rule name
- `title` (str, optional): Human-readable title

**Returns:** Formatted display name string

#### `_get_ig_badge_class(ig_name)`
Returns CSS class for IG badge styling.

**Parameters:**
- `ig_name` (str): Implementation Group name (IG1, IG2, or IG3)

**Returns:** CSS class name string

#### `_enrich_control_metadata(control_data, control_id, ig_name, all_igs)`
Enriches control data with display metadata.

**Parameters:**
- `control_data` (dict): Existing control data
- `control_id` (str): Control identifier
- `ig_name` (str): Implementation Group name
- `all_igs` (dict): All implementation groups data

**Returns:** Enhanced control data dictionary

#### `_consolidate_findings_by_control(implementation_groups)`
Consolidates findings from all IGs, grouped by control ID only.

**Parameters:**
- `implementation_groups` (dict): Implementation groups data

**Returns:** Dictionary mapping control_id to consolidated findings

#### `_get_control_ig_membership(control_id, implementation_groups)`
Determines which IGs include a specific control.

**Parameters:**
- `control_id` (str): Control identifier
- `implementation_groups` (dict): All IG data

**Returns:** List of IG names

## Examples

### Example 1: Control Card Display

**Before:**
```
┌─────────────────────────┐
│ 1.5                     │
│ ━━━━━━━━━━━━━━━━━━━━━  │
│ 0% compliant            │
└─────────────────────────┘
```

**After:**
```
┌─────────────────────────────────────────────┐
│ 1.5: root-account-hardware-mfa-enabled      │
│ [IG1]                                       │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│ 0% compliant                                │
└─────────────────────────────────────────────┘
```

### Example 2: Detailed Findings Section

**Before:**
```
Detailed Findings

IG1 Detailed Findings
  Control 1.5
    - Resource: 175331854181
    - Status: NON_COMPLIANT

IG2 Detailed Findings
  Control 1.5
    - Resource: 175331854181
    - Status: NON_COMPLIANT

IG3 Detailed Findings
  Control 1.5
    - Resource: 175331854181
    - Status: NON_COMPLIANT
```

**After:**
```
Detailed Findings

1.5: root-account-hardware-mfa-enabled
Implementation Groups: [IG1] [IG2] [IG3]
  - Resource: 175331854181
  - Status: NON_COMPLIANT
```

### Example 3: Implementation Groups Section

**Before:**
```
IG1 - Essential Cyber Hygiene (58 controls)
  [Shows all 58 controls]

IG2 - Enhanced Security (132 controls)
  [Shows all 132 controls, including 58 from IG1]

IG3 - Advanced Security (156 controls)
  [Shows all 156 controls, including 132 from IG1+IG2]
```

**After:**
```
Implementation Groups
Note: IGs are cumulative. IG2 includes IG1, IG3 includes IG1+IG2.

IG1 - Essential Cyber Hygiene
Showing 58 foundational controls essential for all organizations.
  [Shows 58 IG1 controls]

IG2 - Enhanced Security (includes IG1)
Showing 74 additional controls beyond IG1 for enhanced security.
  [Shows only 74 controls unique to IG2]

IG3 - Advanced Security (includes IG1 + IG2)
Showing 24 advanced controls beyond IG1 and IG2 for comprehensive security.
  [Shows only 24 controls unique to IG3]
```

## Troubleshooting

### Issue: Control names not showing

**Cause:** `config_rule_name` field is missing in assessment data

**Solution:** The reporter gracefully falls back to showing control ID only. To fix, ensure your assessment includes config_rule_name in control data.

### Issue: IG badges not appearing

**Cause:** CSS classes may be overridden by custom styles

**Solution:** Check for conflicting CSS rules and ensure `.ig-membership-badge` classes are not hidden.

### Issue: Truncation not working

**Cause:** CSS for `.control-display-name.truncated` may be missing

**Solution:** Ensure the CSS styles are included in the report. Check browser developer tools for CSS conflicts.

## Support

For issues or questions about the HTML report improvements:

1. Check this documentation for examples and customization options
2. Review the docstrings in `html_reporter.py` for detailed API information
3. Examine the CSS classes in the generated HTML for styling customization
4. Refer to the requirements and design documents in `.kiro/specs/html-report-improvements/`
