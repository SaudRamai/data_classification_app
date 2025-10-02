# ADMIN Role Access Configuration

## Summary
The ADMIN role has been configured to have full access to all pages in the Data Classification App.

## Changes Made

### 1. Authorization Service Update
**File:** `src/services/authorization_service.py`

Added `"ADMIN"` to the `ADMIN_ROLES` set:

```python
ADMIN_ROLES = {
    "ADMIN", "CDO_ROLE", "ROLE_CDO_ADMIN", "ACCOUNTADMIN", 
    "SECURITY_ADMIN", "SYSADMIN", "DATA_GOV_COMMITTEE_ROLE"
}
```

## How It Works

The authorization system uses a hierarchical permission model where ADMIN role inherits all privileges:

### Access Control Methods
- **`is_admin()`** - Returns True for ADMIN role
- **`is_owner()`** - Returns True for owners OR admins
- **`is_custodian()`** - Returns True for custodians OR admins  
- **`is_specialist()`** - Returns True for specialists OR admins
- **`is_consumer()`** - Returns True for consumers OR elevated roles (including admins)
- **`can_access_classification()`** - Grants access if admin
- **`can_see_admin_actions()`** - Grants access if admin
- **`can_classify()`** - Grants access if admin
- **`can_approve_tags()`** - Grants access if admin

## Pages and Their Access Requirements

| Page | File | Access Requirement | ADMIN Access |
|------|------|-------------------|--------------|
| **Dashboard** | `1_Dashboard.py` | No RBAC guard (open to all authenticated) | ✅ Full Access |
| **Data Assets** | `2_Data_Assets.py` | `is_consumer()` | ✅ Full Access |
| **Classification** | `3_Classification.py` | `can_access_classification()` | ✅ Full Access |
| **Compliance** | `4_Compliance.py` | `is_consumer()` | ✅ Full Access |
| **Data Quality** | `5_Data_Quality.py` | No RBAC guard | ✅ Full Access |
| **Data Lineage** | `6_Data_Lineage.py` | No RBAC guard | ✅ Full Access |
| **Administration** | `10_Administration.py` | `is_custodian()` OR `is_admin()` | ✅ Full Access |
| **Policy Guidance** | `12_Policy_Guidance.py` | No RBAC guard | ✅ Full Access |
| **AI Classification** | `13_AI_Classification.py` | `can_classify()` | ✅ Full Access |

## Quick Links (app.py)

The main app page uses a simple lowercase role matching for quick links:
- Dashboard: Available to all
- Data Assets: `can_data` (includes admins via string matching)
- Classification: `can_classify` (includes admins)  
- Compliance: `can_compliance` (includes admins)
- Data Discovery: `can_discovery` (includes admins)
- Administration: `can_admin` (matches "admin" in role name)

The quick links use `_has_any()` which checks if the role name contains certain keywords (case-insensitive), and ADMIN role will match the "admin" keyword.

## Usage

### Assigning ADMIN Role in Snowflake
```sql
-- Grant ADMIN role to a user
GRANT ROLE ADMIN TO USER your_username;

-- Set ADMIN as default role
ALTER USER your_username SET DEFAULT_ROLE = ADMIN;

-- Verify role assignment
SHOW GRANTS TO USER your_username;
```

### Logging In with ADMIN Role
1. Navigate to the Data Classification App
2. Login with your Snowflake credentials
3. The app will automatically detect your ADMIN role
4. You will have full access to all pages and features

## Testing
To verify ADMIN access:
1. Login as a user with ADMIN role
2. Check that all navigation links appear on the home page
3. Visit each page to confirm no permission errors
4. Verify you can perform all actions (classify, approve, administer, etc.)

## Notes
- The ADMIN role is case-insensitive (converted to uppercase internally)
- ADMIN users bypass all permission checks in the application
- This includes both page-level access and action-level permissions
- Object-level permissions (table ALTER/OWNERSHIP) are still checked via Snowflake privileges
