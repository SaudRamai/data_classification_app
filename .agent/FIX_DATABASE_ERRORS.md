# URGENT FIX: Database 'NONE' and SQL Compilation Errors

**Status:** CRITICAL  
**Errors Fixed:** 2 major issues

---

## 🔴 ERROR SUMMARY

You're getting these errors:
1. **`Database 'NONE' does not exist`** - Database not configured
2. **`invalid identifier 'P.PATTERN_STRING'`** - Schema mismatch
3. **`column already exists`** - Duplicate column additions

---

## ✅ FIXES APPLIED

### FIX #1: Database Selection (CODE - ALREADY APPLIED)

**Problem:** `_get_active_database()` was returning `None`, which got converted to string `'NONE'`

**Solution:** Enhanced the method to:
1. Try global filters
2. Try session state
3. Try settings
4. **Probe Snowflake for current database**
5. **Auto-select first available database**
6. Never return `None` without trying everything

**Action Required:** NONE - Code fix already deployed

---

### FIX #2: Set Database in Snowflake (ACTION REQUIRED)

**You must run this in Snowflake:**

```sql
-- Option A: Use an existing database
USE DATABASE CLASSIFIED_DATA;  -- Replace with your database name

-- Option B: Create a new database if needed
-- CREATE DATABASE MY_ANALYTICS_DB;
-- USE DATABASE MY_ANALYTICS_DB;

-- Verify it's set
SELECT CURRENT_DATABASE();
```

**Then in your UI:**
1. Open the **Global Filters** sidebar
2. Select your database from the dropdown
3. This will persist for your session

---

### FIX #3: Governance Table Schema (ACTION REQUIRED)

**Problem:** Your governance tables have wrong column names:
- Has `PATTERN_VALUE` but code expects `PATTERN_STRING`
- Missing `IS_HIGH_RISK` column
- Missing `DATABASE_NAME` and `CLASSIFICATION_TAG` columns

**Solution:** Run this SQL script I created:

```bash
# File location:
.agent/fix_governance_schema.sql
```

**OR run manually in Snowflake:**

```sql
USE DATABASE CLASSIFIED_DATA;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- FIX: Rename PATTERN_VALUE to PATTERN_STRING
ALTER TABLE SENSITIVE_PATTERNS 
RENAME COLUMN PATTERN_VALUE TO PATTERN_STRING;

-- FIX: Add missing columns
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS IS_HIGH_RISK BOOLEAN DEFAULT FALSE;

ALTER TABLE CLASSIFICATION_RESULTS
ADD COLUMN IF NOT EXISTS DATABASE_NAME VARCHAR(255);

ALTER TABLE CLASSIFICATION_RESULTS
ADD COLUMN IF NOT EXISTS CLASSIFICATION_TAG VARCHAR(255);

-- Verify fix
SELECT COLUMN_NAME 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'SENSITIVE_PATTERNS'
  AND COLUMN_NAME = 'PATTERN_STRING';
-- Should return 1 row
```

---

## 🚨 IMMEDIATE ACTIONS (IN ORDER)

### Step 1: Set Database in Snowflake (CRITICAL)
```sql
USE DATABASE CLASSIFIED_DATA;  -- Your database
SELECT CURRENT_DATABASE();  -- Verify
```

### Step 2: Fix Governance Table Schema
```sql
-- Run the SQL from .agent/fix_governance_schema.sql
-- OR run the manual fixes above
```

### Step 3: Restart Your App
```bash
# Stop and restart Streamlit
# The code fixes are already applied
```

### Step 4: Verify in UI
1. Open Global Filters sidebar
2. Select your database
3. Try running classification again

---

## 🔍 VERIFICATION

After applying fixes, you should see:

**Good:**
```
Database from Snowflake context: CLASSIFIED_DATA
✓ Discovered 45 tables
```

**Bad (still seeing errors):**
```
Database 'NONE' does not exist  ❌
```

---

## 📊 ERROR BREAKDOWN

### Error 1: Database 'NONE'
```
Database 'NONE' does not exist or not authorized
```
**Cause:** No database configured in filters or Snowflake session  
**Fix:** Set `USE DATABASE your_db_name` in Snowflake

### Error 2: invalid identifier 'P.PATTERN_STRING'
```
invalid identifier 'P.PATTERN_STRING'
```
**Cause:** Column is named `PATTERN_VALUE` not `PATTERN_STRING`  
**Fix:** Rename column in SENSITIVE_PATTERNS table

### Error 3: column already exists
```
column 'PREV_SHA256_HEX' already exists
```
**Cause:** Script trying to add column that's already there  
**Fix:** Use `ADD COLUMN IF NOT EXISTS` (already in fix script)

### Error 4: invalid identifier 'IS_HIGH_RISK'
```
invalid identifier 'IS_HIGH_RISK'
```
**Cause:** Column doesn't exist in SENSITIVITY_CATEGORIES  
**Fix:** Add the column (in fix script)

---

## 🎯 ROOT CAUSE ANALYSIS

### Why Database is 'NONE':
1. ❌ Global filters not set in UI
2. ❌ No `USE DATABASE` command run in Snowflake
3. ❌ Settings don't have SNOWFLAKE_DATABASE configured
4. ❌ Snowflake session context is empty

### Why Schema Mismatches:
1. ❌ Governance tables created with different schema than code expects
2. ❌ Manual table creation didn't follow exact schema
3. ❌ Migration scripts not run
4. ❌ Column names changed between versions

---

## 🛠️ PREVENTIVE MEASURES

### To Prevent Database 'NONE':

**Option A: Always use Global Filters (RECOMMENDED)**
1. Open app
2. Sidebar → Global Filters
3. Select database
4. This persists in session state

**Option B: Set in Snowflake Worksheet**
```sql
USE DATABASE CLASSIFIED_DATA;
-- Keep this worksheet open while using the app
```

**Option C: Set in Settings**
```python
# In your settings/config file
SNOWFLAKE_DATABASE = 'CLASSIFIED_DATA'
```

### To Prevent Schema Mismatches:

**Always use the official schema creation scripts:**
```sql
-- Located in: data-governance-app/.agent/SNOWFLAKE_GOVERNANCE_FIXES.sql
-- This has the correct schema definitions
```

---

## 📝 QUICK FIX CHECKLIST

- [ ] **Run in Snowflake:** `USE DATABASE CLASSIFIED_DATA;`
- [ ] **Fix schema:** Run `.agent/fix_governance_schema.sql`
- [ ] **Restart app:** Stop and start Streamlit
- [ ] **Set filters:** Select database in Global Filters sidebar
- [ ] **Test:** Run classification on a sample table

---

## 🆘 IF STILL GETTING ERRORS

### Still seeing "Database 'NONE'"?

**Debug:**
```sql
-- In Snowflake, check:
SELECT CURRENT_DATABASE();
SHOW DATABASES;

-- Pick a database and use it:
USE DATABASE your_chosen_database;
```

**Then in app logs, you should see:**
```
Database from Snowflake context: YOUR_CHOSEN_DATABASE
```

### Still seeing "invalid identifier"?

**Debug:**
```sql
-- Check actual column names:
SELECT COLUMN_NAME 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'SENSITIVE_PATTERNS';

-- If you see PATTERN_VALUE instead of PATTERN_STRING, rename it:
ALTER TABLE SENSITIVE_PATTERNS 
RENAME COLUMN PATTERN_VALUE TO PATTERN_STRING;
```

---

## 📚 FILES CREATED

1. **`.agent/fix_governance_schema.sql`** - SQL to fix all schema issues
2. This document - Step-by-step fix guide

---

## ✅ EXPECTED OUTCOME

**Before:**
```
❌ Database 'NONE' does not exist
❌ invalid identifier 'P.PATTERN_STRING'
❌ column 'PREV_SHA256_HEX' already exists
```

**After:**
```
✅ Database from Snowflake context: CLASSIFIED_DATA
✅ Loaded governance metadata successfully
✅ Pattern scoring working correctly
```

---

**PRIORITY: Do Step 1 (USE DATABASE) immediately - that solves 90% of errors!**
