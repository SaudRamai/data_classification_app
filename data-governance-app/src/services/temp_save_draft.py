
    def _save_classification_results(self, db: str, results: List[Dict[str, Any]]) -> None:
        """
        Save classification results to CLASSIFICATION_AI_RESULTS table.
        Uses MERGE to update existing records or insert new ones.
        """
        if not results:
            return

        gov_db = self._get_governance_database(db)
        if not gov_db:
            logger.error("Cannot save results: No governance database configured")
            return

        logger.info(f"Saving {len(results)} classification results to {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS")

        # Prepare batch data
        values_list = []
        
        # Get category IDs map if not already loaded
        cat_ids = getattr(self, '_category_ids', {})
        
        for r in results:
            try:
                asset = r.get('asset', {})
                schema = str(asset.get('schema', '')).strip()
                table = str(asset.get('table', '')).strip()
                
                # Handle column results if present (from table classification)
                # If the result is a table-level result, it might contain column_results?
                # Actually _classify_assets_local returns table-level results, but we need column-level granularity for the table.
                # Wait, the UI shows column-level data. 
                # _classify_table_governance_driven returns a dict with 'category' (table level).
                # But it also calculates column results internally.
                # We need to capture those column results!
                
                # RE-READ: _classify_table_governance_driven returns a single dict for the TABLE.
                # But the UI expects COLUMN level rows.
                # The current implementation of _classify_table_governance_driven DOES NOT return column details in the main result dict!
                # It returns: {'asset': ..., 'category': ..., 'confidence': ..., 'detected_categories': ...}
                
                # This is a problem. The previous pipeline returned a list of column results.
                # The new one returns table results.
                # BUT, _classify_table_governance_driven calculates column_results internally.
                # We need to expose them.
                
                pass 
            except Exception:
                continue
                
        # ... (implementation paused to fix return value)
