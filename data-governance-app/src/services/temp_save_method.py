    def _save_classification_results(self, db: str, results: List[Dict[str, Any]]) -> None:
        """
        Save classification results to CLASSIFICATION_AI_RESULTS table.
        """
        if not results:
            return

        gov_db = self._get_governance_database(db)
        if not gov_db:
            logger.error("Cannot save results: No governance database configured")
            return

        # Flatten results to get all sensitive columns
        all_columns = []
        for table_res in results:
            cols = table_res.get('column_results', [])
            if cols:
                all_columns.extend(cols)
        
        if not all_columns:
            logger.info("No sensitive columns to save.")
            return

        logger.info(f"Saving {len(all_columns)} sensitive column results to Snowflake...")
        
        # Get category IDs map
        cat_ids = getattr(self, '_category_ids', {})
        
        # Batch processing
        batch_size = 50
        total_saved = 0
        
        for i in range(0, len(all_columns), batch_size):
            batch = all_columns[i:i+batch_size]
            
            # Build VALUES string
            values = []
            params = {}
            
            for idx, col in enumerate(batch):
                p_idx = i + idx
                schema = col.get('schema', '')
                table = col.get('table', '')
                column = col.get('column', '')
                category = col.get('category', 'Unknown')
                confidence = float(col.get('confidence', 0.0))
                details = col.get('details', '')
                
                cat_id = cat_ids.get(category)
                
                # Param keys
                k_s = f"s{p_idx}"
                k_t = f"t{p_idx}"
                k_c = f"c{p_idx}"
                k_cat = f"cat{p_idx}"
                k_conf = f"conf{p_idx}"
                k_det = f"det{p_idx}"
                k_cid = f"cid{p_idx}"
                
                values.append(f"(%({k_s})s, %({k_t})s, %({k_c})s, %({k_cat})s, %({k_conf})s, %({k_det})s, %({k_cid})s)")
                
                params[k_s] = schema
                params[k_t] = table
                params[k_c] = column
                params[k_cat] = category
                params[k_conf] = confidence
                params[k_det] = details
                params[k_cid] = cat_id
            
            if not values:
                continue
                
            values_str = ", ".join(values)
            
            query = f"""
            MERGE INTO {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS AS target
            USING (SELECT * FROM VALUES {values_str}) AS source(SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, AI_CATEGORY, FINAL_CONFIDENCE, DETAILS, SENSITIVITY_CATEGORY_ID)
            ON target.SCHEMA_NAME = source.SCHEMA_NAME 
               AND target.TABLE_NAME = source.TABLE_NAME 
               AND target.COLUMN_NAME = source.COLUMN_NAME
            WHEN MATCHED THEN
                UPDATE SET 
                    target.AI_CATEGORY = source.AI_CATEGORY,
                    target.FINAL_CONFIDENCE = source.FINAL_CONFIDENCE,
                    target.DETAILS = source.DETAILS,
                    target.SENSITIVITY_CATEGORY_ID = source.SENSITIVITY_CATEGORY_ID,
                    target.UPDATED_AT = CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN
                INSERT (SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, AI_CATEGORY, FINAL_CONFIDENCE, DETAILS, SENSITIVITY_CATEGORY_ID, CREATED_AT, UPDATED_AT)
                VALUES (source.SCHEMA_NAME, source.TABLE_NAME, source.COLUMN_NAME, source.AI_CATEGORY, source.FINAL_CONFIDENCE, source.DETAILS, source.SENSITIVITY_CATEGORY_ID, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())
            """
            
            try:
                snowflake_connector.execute_query(query, params)
                total_saved += len(batch)
            except Exception as e:
                logger.error(f"Failed to save batch {i//batch_size}: {e}")
                
        logger.info(f"Successfully saved {total_saved} column results.")
