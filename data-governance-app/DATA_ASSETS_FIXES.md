# Data Assets Page Fixes

## Issues Fixed

### 1. Database 'NONE' Error ❌ → ✅
**Problem:** `settings.SNOWFLAKE_DATABASE` was `None`, causing SQL compilation errors when querying `INFORMATION_SCHEMA`.

**Solution:** Added comprehensive database fallback logic throughout the file:
- Check `st.session_state.get('sf_database')` first (user session)
- Fall back to `settings.SNOWFLAKE_DATABASE` (environment config)
- Query `CURRENT_DATABASE()` from Snowflake if both are None
- Skip operations gracefully if no database is available

**Locations Fixed:**
- `_ensure_wh_quick()` - Database initialization
- `_ensure_decisions_table()` - Audit table creation
- `_persist_decision()` - Decision persistence
- `get_real_data_assets()` - Main data fetching function
- `compute_policy_fields()` - Status computation
- `_get_inventory_map()` - Inventory queries
- `_get_qa_status_map()` - QA status queries
- `_fetch_columns_for_assets()` - Column metadata (2 locations)
- Asset metadata expander - Column details
- Masking policy queries
- Lifecycle management

### 2. st.selectbox Index Error ❌ → ✅
**Problem:** `st.selectbox(..., index=0 if names else None)` caused error when `names` list was empty.

**Solution:** Conditional rendering of selectbox:
```python
if names:
    sel_asset = st.selectbox("Select asset", options=sorted(names), index=0, key="ai_assets_select")
else:
    st.info("No assets available. Please ensure you have tables or views in your database.")
    sel_asset = None
```

**Location:** Line 532-536 in AI Actions expander

### 3. Empty Data Handling ❌ → ✅
**Problem:** Page would fail or show confusing errors when no assets were found.

**Solution:** Added early exit with helpful message:
```python
if assets_df.empty:
    st.info("📊 No data assets found in the current database. Please ensure:\n\n"
            "1. You have selected a valid database in your session\n"
            "2. The database contains tables or views\n"
            "3. You have the necessary permissions to query INFORMATION_SCHEMA")
    st.stop()
```

**Location:** Line 682-687 in Inventory tab

## Testing Recommendations

1. **Test with no database set:**
   - Clear session state database
   - Verify graceful error messages appear

2. **Test with empty database:**
   - Connect to database with no tables/views
   - Verify helpful info message displays

3. **Test with valid database:**
   - Connect to database with tables
   - Verify all features work normally

4. **Test AI Actions:**
   - With assets: verify selectbox works
   - Without assets: verify info message shows

## Files Modified

- `src/pages/2_Data_Assets.py` - All fixes applied

## Summary

✅ All database references now have proper fallback logic  
✅ No more "Database 'NONE' does not exist" errors  
✅ No more st.selectbox index errors  
✅ Graceful handling of empty data scenarios  
✅ Clear, actionable error messages for users
