# Data Assets Page - Quick Reference Guide

## 🎯 Quick Start

### Basic Search & Filter
1. **Search**: Type in "Search assets" box → searches names, schemas, tags
2. **Classification**: Select level → Public, Internal, Restricted, Confidential
3. **Compliance**: Choose tags → GDPR, HIPAA, PCI
4. **Click anywhere** outside filter panel to apply

### View Asset Details
1. Scroll to "🏷️ Asset Details & Tags"
2. Select asset from dropdown
3. Click "View Tags" or expand "Asset Metadata"

---

## 🔍 Filter Cheat Sheet

| Filter | Location | Purpose |
|--------|----------|---------|
| **Search assets** | Row 1 | Full-text search (DB, schema, table, tags) |
| **Classification Level** | Row 1 | Filter by sensitivity level |
| **Compliance Tag** | Row 1 | GDPR, HIPAA, PCI filtering |
| **Database** | Row 2 | Filter by specific database |
| **Schema** | Row 2 | Filter by schema name |
| **Table name** | Row 2 | Substring match on table names |
| **Owner** | Row 3 | Search by owner email |
| **Status** | Row 3 | Classified / Unclassified / Overdue |
| **Risk** | Row 3 | Low / Medium / High |
| **Min row count** | Advanced | Assets with ≥ N rows |
| **Min size (MB)** | Advanced | Assets with ≥ N MB |
| **Max cost ($)** | Advanced | Assets below cost threshold |
| **Min dependencies** | Advanced | Assets with ≥ N dependencies |
| **Business Unit** | Row 5 | Filter by business unit |
| **Business Domain** | Row 5 | Filter by domain |
| **Type** | Row 5 | TABLE or VIEW |
| **Lifecycle** | Row 6 | Active / Deprecated / Archived |
| **Data Category** | Row 6 | PII / PHI / Financial / Regulatory |

---

## 📊 Column Reference

### Main Asset Table Columns

| Column | Description |
|--------|-------------|
| **Dataset Name** | Full qualified name (DB.Schema.Table) |
| **Database** | Database name |
| **Schema** | Schema name |
| **Table Name** | Table name only |
| **Owner** | Assigned data owner (email) |
| **Classification** | Sensitivity level |
| **CIA Score** | Confidentiality-Integrity-Availability (0-3 each) |
| **C, I, A** | Individual CIA scores |
| **Tags** | Applied Snowflake tags |
| **Lifecycle** | Active / Deprecated / Archived |
| **Risk** | Overall risk level (Low/Medium/High) |
| **Status** | Classification status with SLA |
| **Type** | TABLE or VIEW |
| **Dependencies** | Count of upstream + downstream |
| **Estimated Monthly Cost ($)** | Storage cost estimate |
| **Last Updated** | Last modification date |
| **SLA** | Days until/past classification deadline |
| **QA Status** | Quality assurance review status |

---

## 🎬 Common Workflows

### Workflow 1: Classify New Assets
```
1. Filter: Status = "Unclassified ❌"
2. Review asset list
3. Select asset → View details
4. Expand "Asset Metadata" → review columns
5. Go to Classification page (use CTA button)
6. Apply classification with rationale
```

### Workflow 2: Bulk Classification
```
1. Apply filters to narrow down assets
2. Go to "Bulk Actions" tab
3. Select multiple assets
4. Choose classification + CIA scores
5. Enter rationale (required for Restricted/Confidential)
6. Click "Apply to Selected"
```

### Workflow 3: Find Related Assets
```
1. Navigate to asset in main table
2. Expand "🔗 Asset Relationships & Similar Assets"
3. Select asset from dropdown
4. View upstream/downstream dependencies
5. Review similar asset recommendations
```

### Workflow 4: Lifecycle Management
```
1. Select asset from details section
2. Expand "Ownership & Lifecycle"
3. Assign owner (if not set)
4. Select lifecycle action:
   - Mark Active
   - Mark Deprecated
   - Mark Archived
5. Click "Apply Lifecycle"
```

### Workflow 5: Export for Reporting
```
1. Apply desired filters
2. Go to "Export" tab
3. Choose format:
   - CSV (all columns)
   - Excel (formatted)
   - PDF (summary)
4. Click download button
```

### Workflow 6: Audit Overdue Assets
```
1. Filter: Status = "Overdue ⏰"
2. Sort by: "Creation Date" (oldest first)
3. Review list
4. For each asset:
   - Assign owner if missing
   - Apply classification
   - Document rationale
5. Export report for compliance
```

---

## 🔑 Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Refresh data | Click "🔄 Refresh now" button |
| Clear filters | Reload page (F5) |
| Navigate tabs | Click tab headers |
| Expand/collapse | Click section headers |

---

## 💡 Pro Tips

### Search Tips
- ✅ Use partial matches: "CUST" finds "CUSTOMER_DATA"
- ✅ Search is case-insensitive
- ✅ Enable column search for deep inspection (slower)
- ✅ Combine multiple filters for precision

### Performance Tips
- ⚡ Use pagination (25/50/100 per page)
- ⚡ Apply specific filters before column-level filters
- ⚡ Disable column search for large datasets
- ⚡ Use cache (5-min TTL) - avoid frequent refreshes

### Classification Tips
- 📋 Always provide rationale for Restricted/Confidential
- 📋 Assign owner before classifying
- 📋 Use bulk actions for similar assets
- 📋 Review similar assets for consistency

### Compliance Tips
- ✅ Tag PII assets with GDPR compliance
- ✅ Financial data requires at least Restricted
- ✅ SOX-relevant data must be Confidential
- ✅ Document decisions in rationale field

---

## 🚨 Troubleshooting

### "No assets found"
- Check database is selected (top of page)
- Verify you have read permissions
- Try clearing filters

### "Tags not applying"
- Requires ALTER or OWNERSHIP privileges
- Check with database administrator
- Verify tag exists in database

### "Dependencies not showing"
- Requires ACCOUNT_USAGE access
- Data may have 45-minute latency
- Some objects may not have dependencies

### "Slow loading"
- Reduce page size
- Disable column-level search
- Apply more specific filters
- Clear cache and refresh

### "Lifecycle not filtering"
- Lifecycle must be set on assets first
- Use "Ownership & Lifecycle" to set status
- Default is "Active" if not set

---

## 📈 KPI Card Meanings

| KPI | Calculation | Good Target |
|-----|-------------|-------------|
| **Total Assets** | Count of all tables/views | N/A (informational) |
| **Classified Coverage** | (Classified / Total) × 100% | ≥ 80% |
| **High Risk** | Count with Risk = "High" | Monitor closely |
| **Overdue (SLA)** | Count with Status = "Overdue" | 0 (classify within 5 days) |

---

## 🎨 Visual Indicators

| Icon/Badge | Meaning |
|------------|---------|
| ✅ | Classified (meets requirements) |
| ❌ | Unclassified (needs action) |
| ⏰ | Overdue (past SLA deadline) |
| 🔴 Red border | High risk / Confidential |
| 🟠 Orange border | Medium risk / Restricted |
| 🟡 Yellow border | Low risk / Internal |
| 🟢 Green border | Public |

---

## 📞 Need Help?

### In-App Help
- Hover over field labels for tooltips
- Expand "💡 What you're seeing" at bottom of page
- Check filter help icons (ⓘ)

### Documentation
- Full documentation: `docs/DATA_ASSETS_ENHANCEMENTS.md`
- Architecture: `docs/ARCHITECTURE.md`
- Compliance: `docs/COMPLIANCE.md`

### Support
- Contact: Data Governance Team
- Email: governance@company.com
- Slack: #data-governance

---

**Quick Reference Version**: 1.0  
**Last Updated**: 2025-10-01  
**Print-Friendly**: Yes
