    def _convert_results_to_dataframe(self, results: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert in-memory classification results to DataFrame matching DB schema."""
        data = []
        for r in results:
            # Handle table-level results that contain column_results
            cols = r.get('column_results', [])
            if cols:
                for col in cols:
                    try:
                        # Map fields to match _fetch_classification_history output
                        category = col.get('category', 'Unknown')
                        policy_group = col.get('policy_group')
                        
                        # Derive compliance name if missing
                        if not policy_group:
                            policy_group = self._map_category_to_policy_group(category) or 'None'
                            
                        # Get sensitivity name (same as category for now, or map if needed)
                        sensitivity = category # In DB fetch it joins with SENSITIVITY_CATEGORIES.CATEGORY_NAME
                        
                        # Construct rationale from details if available, else empty
                        rationale = ""
                        if col.get('detected_categories'):
                             rationale = f"Detected: {', '.join([d['category'] for d in col['detected_categories']])}"
                        
                        row = {
                            'Schema': str(col.get('schema', '')).strip() or 'Unknown',
                            'Table': str(col.get('table', '')).strip() or 'Unknown',
                            'Column': str(col.get('column_name', '')).strip() or 'Unknown',
                            'Category': category,
                            'Confidence': float(col.get('confidence', 0.0)),
                            'Sensitivity': sensitivity,
                            'Compliance': policy_group,
                            'Rationale': rationale
                        }
                        data.append(row)
                    except Exception as e:
                        logger.warning(f"Error converting result row: {e}")
                        continue
            else:
                # Fallback for table-only results (shouldn't happen with new logic but safe to handle)
                pass
                
        if not data:
            return pd.DataFrame()
            
        return pd.DataFrame(data)
