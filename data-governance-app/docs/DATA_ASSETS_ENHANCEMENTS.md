# Data Assets Page - Enhanced Features Documentation

## Overview
The Data Assets page has been significantly enhanced with advanced inventory management, lifecycle tracking, relationship visualization, and comprehensive filtering capabilities while maintaining all existing functionality.

---

## 🆕 New Features Added

### 1. Asset Inventory & Management

#### **Full-Text Search**
- **Location**: Search and Filter section → "Search assets" input
- **Capabilities**:
  - Search across database, schema, table, and column names
  - Optional column-level search (checkbox: "Include column names in search")
  - Case-insensitive matching
  - Searches through tags as well

#### **Asset Classification**
- **Existing**: Sensitive / Confidential / Public / Internal / Restricted
- **Enhanced with**:
  - CIA Triad scoring (Confidentiality, Integrity, Availability: 0-3 scale)
  - Risk level calculation (Low/Medium/High) based on CIA scores
  - Policy-enforced validation for classification decisions

#### **Compliance Tags**
- **Location**: Search and Filter section → "Compliance Tag" multiselect
- **Options**: GDPR, HIPAA, PCI
- **Integration**: Tags are applied via Snowflake tag system and searchable

#### **Business Domain & Business Unit Mapping**
- **Location**: Search and Filter section → Business facets row
- **Features**:
  - Business Unit filter (multiselect)
  - Business Domain filter (multiselect)
  - Auto-derived from tags or schema names
  - Fallback to schema name when not explicitly tagged

---

### 2. Asset Lifecycle Management

#### **Lifecycle Status Tracking**
- **Location**: Search and Filter section → "Lifecycle" dropdown
- **States**:
  - **Active**: Currently in use (default)
  - **Deprecated**: Marked for future removal
  - **Archived**: No longer in active use
- **Storage**: Tracked in `DATA_GOVERNANCE.ASSET_LIFECYCLE` table

#### **Asset Registration Workflow**
- Assets are automatically discovered from `INFORMATION_SCHEMA`
- Tracked in `DATA_GOVERNANCE.ASSET_INVENTORY` table
- First discovery date recorded for SLA tracking

#### **Deprecation & Archival Tracking**
- **Location**: Asset Details → "Ownership & Lifecycle" expander
- **Actions**:
  - Mark Active
  - Mark Deprecated
  - Mark Archived
- **Audit Trail**: All lifecycle changes are logged with timestamps

#### **Ownership Assignment**
- **Location**: Asset Details → "Ownership & Lifecycle" expander
- **Features**:
  - Assign/update owner via email
  - Owner stored as Snowflake tag (`OWNER`)
  - Required for classification decisions (policy-enforced)
  - Filterable in main search

---

### 3. Basic Asset Information (Enhanced)

#### **Technical Metadata**
- **Row Count**: Displayed with comma formatting
- **Size**: Shown in MB with precise calculations
- **Type**: TABLE or VIEW distinction
- **Storage Location**: Full qualified name (Database.Schema.Table)

#### **Creation/Modification Dates**
- **Creation Date**: From `INFORMATION_SCHEMA.TABLES.CREATED`
- **Last Modified**: From `INFORMATION_SCHEMA.TABLES.LAST_ALTERED`
- **Sortable**: Available in "Sort by" dropdown

#### **Storage Cost Metrics**
- **Location**: Main asset table → "Estimated Monthly Cost ($)" column
- **Calculation**: Based on storage size with $23/TB-month rate
- **Formula**: `(Size_MB / 1024) * 0.023`
- **Filterable**: "Max monthly cost" in Advanced Filters

---

### 4. Asset Relationships

#### **Upstream/Downstream Lineage Visualization**
- **Location**: "🔗 Asset Relationships & Similar Assets" expander
- **Features**:
  - **Upstream Dependencies**: Tables/views this asset depends on
  - **Downstream Dependencies**: Objects that depend on this asset
  - Data sourced from `SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES`
  - Shows object name and type
  - Limited to 50 items per direction for performance

#### **Similar Asset Recommendations**
- **Algorithm**: Multi-factor similarity scoring
  - Same classification: +3 points
  - Same owner: +2 points
  - Same schema: +2 points
  - Same risk level: +1 point
- **Display**: Top 10 most similar assets with similarity scores
- **Use Cases**:
  - Find assets with similar governance requirements
  - Identify related datasets for bulk operations
  - Discover assets managed by same team

#### **Dependency Mapping**
- **Location**: Main asset table → "Dependencies" column
- **Calculation**: Total count of upstream + downstream dependencies
- **Filterable**: "Min dependencies" in Advanced Filters
- **Use Cases**:
  - Identify highly connected assets
  - Assess impact of changes
  - Prioritize critical infrastructure

---

## 🔍 Enhanced Filters

### Primary Filters (Always Visible)
1. **Search assets**: Full-text search with optional column inclusion
2. **Classification Level**: Public / Internal / Restricted / Confidential
3. **Compliance Tag**: GDPR, HIPAA, PCI (multiselect)

### Secondary Filters
4. **Database**: Filter by specific database
5. **Schema**: Filter by schema name
6. **Table name contains**: Substring match on table names

### Tertiary Filters
7. **Owner contains**: Search by owner email
8. **Status**: Classified ✅ / Unclassified ❌ / Overdue ⏰
9. **Risk**: Low / Medium / High

### Advanced Filters (New)
10. **Min row count**: Filter assets with at least N rows
11. **Min size (MB)**: Filter by minimum storage size
12. **Max monthly cost ($)**: Filter by cost threshold (0 = no limit)
13. **Min dependencies**: Filter assets with at least N dependencies

### Business Facets
14. **Business Unit**: Multiselect from discovered units
15. **Business Domain**: Multiselect from discovered domains
16. **Type**: TABLE or VIEW

### Lifecycle & Category
17. **Lifecycle**: Active / Deprecated / Archived
18. **Data Category**: PII / PHI / Financial / Regulatory

### Column-Level Filters (Multi-level)
19. **Column name contains**: Substring match on column names
20. **Column data type**: Filter by data types (STRING, NUMBER, DATE, etc.)
21. **Has masking policy**: Yes / No / Any
22. **Column category**: PII, PHI, PCI, Financial, Regulatory
23. **Minimum column count**: Require assets with at least N columns

---

## 📊 UI/UX Layout Recommendations

### Current Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ Page Header: Data Assets Inventory                      │
│ Connection Info: Role | Warehouse | Database            │
├─────────────────────────────────────────────────────────┤
│ 🔄 Refresh Button                                       │
├─────────────────────────────────────────────────────────┤
│ Tabs: [Inventory] [Discovery Feed] [Bulk Actions] [Export] │
└─────────────────────────────────────────────────────────┘

INVENTORY TAB:
┌─────────────────────────────────────────────────────────┐
│ KPI Cards (4 columns)                                   │
│ • Total Assets  • Coverage %  • High Risk  • Overdue    │
├─────────────────────────────────────────────────────────┤
│ 🔍 Search and Filter (Expandable - Default: Expanded)   │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Row 1: Search | Classification | Compliance Tags    │ │
│ │ Row 2: Database | Schema | Table Name              │ │
│ │ Row 3: Owner | Status | Risk                       │ │
│ │ Advanced Filters:                                   │ │
│ │ Row 4: Min Rows | Min Size | Max Cost | Min Deps   │ │
│ │ Row 5: Business Unit | Business Domain | Type       │ │
│ │ Row 6: Lifecycle | Data Category                    │ │
│ │ Column-Level Filters:                               │ │
│ │ Row 7: Column Name | Data Type | Masking            │ │
│ │ Row 8: Category | Min Column Count                  │ │
│ │ Row 9: Sort By | Page Size                          │ │
│ └─────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ 📊 Data Assets (N found) — Tables: X, Views: Y          │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Charts: Classification Distribution | Top Schemas   │ │
│ └─────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ Classification Summary (text)                           │
├─────────────────────────────────────────────────────────┤
│ Column-level Summary by Classification (expandable)     │
├─────────────────────────────────────────────────────────┤
│ Main Asset Table (paginated)                            │
│ • Columns selector (expandable)                         │
│ • Download current view (CSV)                           │
│ • Page N of M                                           │
├─────────────────────────────────────────────────────────┤
│ 🔗 Asset Relationships & Similar Assets (expandable)    │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Select asset dropdown                               │ │
│ │ ┌──────────────────────┬──────────────────────────┐ │ │
│ │ │ Upstream Dependencies│ Downstream Dependencies  │ │ │
│ │ └──────────────────────┴──────────────────────────┘ │ │
│ │ Similar Asset Recommendations (with scores)         │ │
│ └─────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ 🏷️ Asset Details & Tags                                │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Select asset dropdown                               │ │
│ │ • View Tags button                                  │ │
│ │ • Asset Metadata (expandable)                       │ │
│ │   - Column list with types, tags, categories        │ │
│ │   - AI Detection & Tagging (CTA to Classification)  │ │
│ │   - Column Masking Policies                         │ │
│ │   - Asset Relationships (lineage)                   │ │
│ │ • Manage Tags (CTA to Classification)               │ │
│ │ • Ownership & Lifecycle (expandable)                │ │
│ │   - Assign Owner | Lifecycle Actions                │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Filter Panel Best Practices
✅ **Implemented**:
- Collapsible expander to reduce visual clutter
- Logical grouping (Primary → Secondary → Advanced)
- Clear labels with help tooltips
- Multi-column layout for efficient space usage
- Progressive disclosure (advanced filters separate)

### Main Asset Table Best Practices
✅ **Implemented**:
- Customizable columns via multiselect
- Pagination for performance
- Sortable by multiple criteria
- Download capability
- Visual badges for status

### Relationships View Best Practices
✅ **Implemented**:
- Separate expandable section
- Side-by-side upstream/downstream view
- Clear counts and limits
- Similar assets with scoring algorithm
- Link to full lineage page

---

## 🔐 Audit & Compliance Readiness

### Audit Trail Features
1. **Classification Decisions**: Stored in `DATA_GOVERNANCE.CLASSIFICATION_DECISIONS`
   - Asset name, classification, CIA scores
   - Owner, rationale, checklist
   - Previous values for change tracking
   - Decided by (user) and timestamp

2. **Lifecycle Changes**: Stored in `DATA_GOVERNANCE.ASSET_LIFECYCLE`
   - Asset name, status (Active/Deprecated/Archived)
   - Timestamp of change

3. **Tag Applications**: Logged via `audit_service`
   - User ID, action, resource type/ID
   - Old and new values
   - Rationale and checklist

### Policy Enforcement
- **Decision Matrix Validation**: Enforces CIA-to-label consistency
- **Special Category Minimums**: PII ≥ Restricted, SOX ⇒ Confidential
- **Rationale Required**: For Restricted/Confidential classifications
- **Owner Required**: Before classification can be applied

### Compliance Reports
- **Export Options**: CSV, Excel, PDF summary
- **Column-level Summary**: Masked columns, PII/PHI/PCI counts
- **Status Tracking**: Classified vs Unclassified, Overdue SLA

---

## 🚀 Usage Examples

### Example 1: Find All PII Assets Requiring GDPR Compliance
1. Navigate to Data Assets → Inventory tab
2. Expand "🔍 Search and Filter"
3. Set:
   - **Compliance Tag**: Select "GDPR"
   - **Data Category**: Select "PII"
   - **Classification Level**: "Restricted" or "Confidential"
4. Review results in main table
5. Use "Bulk Actions" tab to apply consistent policies

### Example 2: Identify High-Cost, Low-Usage Assets for Archival
1. Set filters:
   - **Min size (MB)**: 10000 (10 GB)
   - **Max monthly cost ($)**: 1000
   - **Sort by**: "Last Modified"
2. Review assets not modified recently
3. Select assets for lifecycle change
4. Go to asset details → "Ownership & Lifecycle"
5. Mark as "Deprecated" or "Archived"

### Example 3: Discover Assets with High Dependencies
1. Set filters:
   - **Min dependencies**: 5
   - **Risk**: "High"
2. Review critical infrastructure assets
3. Use "🔗 Asset Relationships" to visualize impact
4. Document dependencies for change management

### Example 4: Audit Unclassified Assets Overdue for Review
1. Set filters:
   - **Status**: "Overdue ⏰"
2. Review assets exceeding 5-business-day SLA
3. Assign owners if missing
4. Apply classifications with rationale
5. Export report for compliance documentation

---

## 🔧 Technical Integration Notes

### Database Schema Requirements
The following tables are automatically created if they don't exist:

```sql
-- Classification decisions audit
{DATABASE}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
  - ID, ASSET_FULL_NAME, CLASSIFICATION
  - C, I, A (CIA scores)
  - OWNER, RATIONALE, CHECKLIST_JSON
  - DECIDED_BY, DECIDED_AT
  - PREV_* fields for change tracking

-- Asset lifecycle tracking
{DATABASE}.DATA_GOVERNANCE.ASSET_LIFECYCLE
  - ASSET_FULL_NAME, STATUS
  - UPDATED_AT

-- Asset inventory (discovery)
{DATABASE}.DATA_GOVERNANCE.ASSET_INVENTORY
  - FULL_NAME, CLASSIFIED, FIRST_DISCOVERED

-- QA reviews
{DATABASE}.DATA_GOVERNANCE.QA_REVIEWS
  - ASSET_FULL_NAME, STATUS
  - REQUESTED_AT, REVIEWED_AT
```

### Snowflake Permissions Required
- **Read**: `INFORMATION_SCHEMA.TABLES`, `INFORMATION_SCHEMA.VIEWS`, `INFORMATION_SCHEMA.COLUMNS`
- **Read**: `SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES`, `SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES`
- **Write**: Tag application requires `ALTER` or `OWNERSHIP` on objects
- **Write**: Governance schema requires `CREATE SCHEMA`, `CREATE TABLE` on database

### Performance Considerations
- **Caching**: 5-minute TTL on asset queries, 3-minute on column metadata
- **Limits**: 
  - Main query: 500 assets
  - Column queries: 300 assets max
  - Dependencies: 100 assets max
  - Lineage: 50 items per direction
- **Pagination**: 25/50/100 items per page

### API Integration Points
- `snowflake_connector`: All Snowflake queries
- `tagging_service`: Tag application and retrieval
- `ai_classification_service`: Sensitive column detection
- `policy_enforcement_service`: Auto-masking enforcement
- `audit_service`: Action logging
- `authz`: RBAC permission checks

---

## 📝 Migration Notes

### Existing Functionality Preserved
✅ All existing features remain intact:
- Original KPI cards
- Classification and tagging workflows
- Bulk actions
- Discovery feed
- Export capabilities
- AI classification integration
- Policy enforcement

### New Features Are Additive
✅ Enhancements are non-breaking:
- New filters are optional
- New columns can be hidden via column selector
- New sections are in expandable panels
- Existing queries unchanged (only extended)

### Backward Compatibility
✅ Works with existing data:
- Gracefully handles missing governance tables
- Falls back to heuristics when tags unavailable
- Defaults to "Active" lifecycle if not set
- Continues to work with existing tag schema

---

## 🎯 Future Enhancement Opportunities

### Potential Additions
1. **Asset Registration Workflow UI**: Form-based asset creation
2. **Bulk Lifecycle Operations**: Apply lifecycle changes to multiple assets
3. **Advanced Lineage Visualization**: Graph-based interactive lineage
4. **Asset Health Scores**: Composite metric (quality + compliance + usage)
5. **Automated Recommendations**: ML-based classification suggestions
6. **Integration with External Catalogs**: Alation, Collibra, etc.
7. **Asset Usage Analytics**: Query frequency, user access patterns
8. **Cost Optimization Recommendations**: Identify savings opportunities

### Monitoring & Alerts
- SLA breach notifications
- Unclassified asset alerts
- High-risk asset monitoring
- Compliance drift detection

---

## 📞 Support & Troubleshooting

### Common Issues

**Issue**: "No assets found"
- **Solution**: Verify database is set in session state or login
- **Check**: `INFORMATION_SCHEMA` access permissions

**Issue**: "Dependencies not showing"
- **Solution**: Requires `SNOWFLAKE.ACCOUNT_USAGE` access
- **Check**: Account usage views may have latency (up to 45 minutes)

**Issue**: "Tags not applying"
- **Solution**: Verify `ALTER` or `OWNERSHIP` privileges on target objects
- **Check**: Tag must exist in database (created automatically by service)

**Issue**: "Lifecycle filter not working"
- **Solution**: Lifecycle data stored in governance table; may need initial population
- **Check**: Apply lifecycle status to assets via "Ownership & Lifecycle" section

### Performance Tuning
- Reduce page size if loading slowly
- Disable column-level search for large datasets
- Use more specific filters to reduce result set
- Clear cache with "🔄 Refresh now" button if data seems stale

---

## 📚 Related Documentation
- [AI Classification](./AI_CLASSIFICATION.md)
- [Architecture Overview](./ARCHITECTURE.md)
- [Compliance Module](./COMPLIANCE.md)
- [Data Lineage](./DATA_LINEAGE.md)

---

**Last Updated**: 2025-10-01  
**Version**: 2.0 (Enhanced)  
**Maintained By**: Data Governance Team
