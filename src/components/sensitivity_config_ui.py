import streamlit as st
import pandas as pd
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from src.connectors.snowflake_connector import snowflake_connector

def get_sensitivity_categories() -> List[Dict[str, Any]]:
    """Fetch all active sensitivity categories from the database."""
    try:
        query = """
            SELECT CATEGORY_ID, CATEGORY_NAME, DESCRIPTION, 
                   CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
                   DETECTION_THRESHOLD
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
            WHERE IS_ACTIVE = TRUE
            ORDER BY CATEGORY_NAME
        """
        return snowflake_connector.execute_query(query) or []
    except Exception as e:
        st.error(f"Error fetching sensitivity categories: {str(e)}")
        return []

def get_sensitive_keywords() -> List[Dict[str, Any]]:
    """Fetch all sensitive keywords with their categories."""
    try:
        query = """
            SELECT 
                k.KEYWORD_ID,
                k.KEYWORD_STRING,
                k.MATCH_TYPE,
                k.SENSITIVITY_WEIGHT,
                k.IS_ACTIVE,
                k.CREATED_AT,
                k.UPDATED_AT,
                c.CATEGORY_NAME
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k
            JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c
                ON k.CATEGORY_ID = c.CATEGORY_ID
            ORDER BY c.CATEGORY_NAME, k.KEYWORD_STRING
        """
        return snowflake_connector.execute_query(query) or []
    except Exception as e:
        st.error(f"Error fetching sensitive keywords: {str(e)}")
        return []

def get_sensitive_patterns() -> List[Dict[str, Any]]:
    """Fetch all sensitive patterns with their categories."""
    try:
        query = """
            SELECT 
                p.PATTERN_ID,
                p.PATTERN_NAME,
                p.PATTERN_STRING,
                p.DESCRIPTION,
                p.SENSITIVITY_WEIGHT,
                p.IS_ACTIVE,
                p.CREATED_AT,
                p.UPDATED_AT,
                c.CATEGORY_NAME
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS p
            JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c
                ON p.CATEGORY_ID = c.CATEGORY_ID
            ORDER BY c.CATEGORY_NAME, p.PATTERN_NAME
        """
        return snowflake_connector.execute_query(query) or []
    except Exception as e:
        st.error(f"Error fetching sensitive patterns: {str(e)}")
        return []

from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service

def save_keyword(keyword_data: Dict[str, Any], is_new: bool = True) -> bool:
    """Save a keyword to the database using the centralized service."""
    try:
        # Extract fields from the dictionary
        keyword = keyword_data.get("keyword_string") or keyword_data.get("KEYWORD_STRING")
        category = keyword_data.get("category_name") or keyword_data.get("CATEGORY_NAME")
        match_type = keyword_data.get("match_type") or keyword_data.get("MATCH_TYPE", "CONTAINS")
        weight = float(keyword_data.get("sensitivity_weight") or keyword_data.get("SENSITIVITY_WEIGHT", 0.8))
        
        # Use the service to upsert (handles sync with classification results)
        return ai_classification_pipeline_service.upsert_sensitive_keyword(
            keyword=keyword,
            category_name=category,
            match_type=match_type,
            sensitivity_weight=weight
        )
    except Exception as e:
        st.error(f"Error saving keyword: {str(e)}")
        return False

def save_pattern(pattern_data: Dict[str, Any], is_new: bool = True) -> bool:
    """Save a pattern to the database."""
    try:
        if is_new:
            query = """
                INSERT INTO DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS (
                    PATTERN_ID, CATEGORY_ID, PATTERN_NAME, PATTERN_STRING, 
                    DESCRIPTION, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_AT, VERSION_NUMBER
                )
                SELECT 
                    %(pattern_id)s,
                    (SELECT CATEGORY_ID FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES 
                     WHERE CATEGORY_NAME = %(category_name)s LIMIT 1),
                    %(pattern_name)s,
                    %(pattern_string)s,
                    %(description)s,
                    %(sensitivity_weight)s,
                    %(is_active)s,
                    CURRENT_TIMESTAMP(),
                    1
            """
        else:
            query = """
                UPDATE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS
                SET 
                    CATEGORY_ID = (SELECT CATEGORY_ID FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES 
                                  WHERE CATEGORY_NAME = %(category_name)s LIMIT 1),
                    PATTERN_NAME = %(pattern_name)s,
                    PATTERN_STRING = %(pattern_string)s,
                    DESCRIPTION = %(description)s,
                    SENSITIVITY_WEIGHT = %(sensitivity_weight)s,
                    IS_ACTIVE = %(is_active)s,
                    UPDATED_AT = CURRENT_TIMESTAMP(),
                    VERSION_NUMBER = VERSION_NUMBER + 1
                WHERE PATTERN_ID = %(pattern_id)s
            """
        
        snowflake_connector.execute_query(query, pattern_data)
        return True
    except Exception as e:
        st.error(f"Error saving pattern: {str(e)}")
        return False

def delete_keyword(keyword: str, category: str) -> bool:
    """Delete a keyword using the centralized service."""
    try:
        return ai_classification_pipeline_service.delete_sensitive_keyword(keyword, category)
    except Exception as e:
        st.error(f"Error deleting keyword: {str(e)}")
        return False

def delete_pattern(pattern_id: str) -> bool:
    """Delete a pattern from the database."""
    try:
        query = """
            DELETE FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS
            WHERE PATTERN_ID = %(pattern_id)s
        """
        snowflake_connector.execute_query(query, {"pattern_id": pattern_id})
        return True
    except Exception as e:
        st.error(f"Error deleting pattern: {str(e)}")
        return False

def render_keyword_form(keyword_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Render a form for adding/editing a keyword."""
    is_edit = keyword_data is not None
    categories = get_sensitivity_categories()
    category_names = [c["CATEGORY_NAME"] for c in categories]
    
    if is_edit:
        st.subheader("Edit Keyword")
        category_name = next(
            (c["CATEGORY_NAME"] for c in categories 
             if c["CATEGORY_ID"] == keyword_data.get("CATEGORY_ID")),
            category_names[0] if category_names else ""
        )
    else:
        st.subheader("Add New Keyword")
        category_name = category_names[0] if category_names else ""
        keyword_data = {
            "KEYWORD_STRING": "",
            "MATCH_TYPE": "CONTAINS",
            "SENSITIVITY_WEIGHT": 0.5,
            "IS_ACTIVE": True
        }
    
    with st.form(f"keyword_form_{keyword_data.get('KEYWORD_ID', 'new')}"):
        col1, col2 = st.columns(2)
        
        with col1:
            keyword_string = st.text_input(
                "Keyword",
                value=keyword_data.get("KEYWORD_STRING", ""),
                help="The keyword to match against column names"
            )
            
            match_type = st.selectbox(
                "Match Type",
                ["EXACT", "CONTAINS", "STARTS_WITH", "ENDS_WITH"],
                index=["EXACT", "CONTAINS", "STARTS_WITH", "ENDS_WITH"].index(
                    keyword_data.get("MATCH_TYPE", "CONTAINS")
                )
            )
        
        with col2:
            category = st.selectbox(
                "Category",
                category_names,
                index=category_names.index(category_name) if category_name in category_names else 0
            )
            
            sensitivity_weight = st.number_input(
                "Sensitivity Weight",
                min_value=0.0,
                max_value=10.0,
                step=0.1,
                value=float(keyword_data.get("SENSITIVITY_WEIGHT", 0.5)),
                help="Weight for this keyword in sensitivity scoring (0.0 - 10.0)"
            )
            
            is_active = st.checkbox("Active", value=keyword_data.get("IS_ACTIVE", True))
        
        submitted = st.form_submit_button("Save")
        
        if submitted:
            if not keyword_string:
                st.error("Keyword is required")
                return None
                
            return {
                "keyword_id": keyword_data.get("KEYWORD_ID", str(uuid.uuid4())),
                "keyword_string": keyword_string,
                "match_type": match_type,
                "category_name": category,
                "sensitivity_weight": float(sensitivity_weight),
                "is_active": is_active
            }
    
    return None

def render_pattern_form(pattern_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Render a form for adding/editing a pattern."""
    is_edit = pattern_data is not None
    categories = get_sensitivity_categories()
    category_names = [c["CATEGORY_NAME"] for c in categories]
    
    if is_edit:
        st.subheader("Edit Pattern")
        category_name = next(
            (c["CATEGORY_NAME"] for c in categories 
             if c["CATEGORY_ID"] == pattern_data.get("CATEGORY_ID")),
            category_names[0] if category_names else ""
        )
    else:
        st.subheader("Add New Pattern")
        category_name = category_names[0] if category_names else ""
        pattern_data = {
            "PATTERN_NAME": "",
            "PATTERN_STRING": "",
            "DESCRIPTION": "",
            "SENSITIVITY_WEIGHT": 0.5,
            "IS_ACTIVE": True
        }
    
    with st.form(f"pattern_form_{pattern_data.get('PATTERN_ID', 'new')}"):
        pattern_name = st.text_input(
            "Pattern Name",
            value=pattern_data.get("PATTERN_NAME", ""),
            help="A descriptive name for this pattern"
        )
        
        pattern_string = st.text_area(
            "Regular Expression Pattern",
            value=pattern_data.get("PATTERN_STRING", ""),
            help="Regular expression pattern to match against column names"
        )
        
        description = st.text_area(
            "Description",
            value=pattern_data.get("DESCRIPTION", ""),
            help="Description of what this pattern matches"
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            category = st.selectbox(
                "Category",
                category_names,
                index=category_names.index(category_name) if category_name in category_names else 0
            )
        
        with col2:
            sensitivity_weight = st.number_input(
                "Sensitivity Weight",
                min_value=0.0,
                max_value=10.0,
                step=0.1,
                value=float(pattern_data.get("SENSITIVITY_WEIGHT", 0.5)),
                help="Weight for this pattern in sensitivity scoring (0.0 - 10.0)"
            )
            
            is_active = st.checkbox("Active", value=pattern_data.get("IS_ACTIVE", True))
        
        submitted = st.form_submit_button("Save")
        
        if submitted:
            if not pattern_name:
                st.error("Pattern name is required")
                return None
                
            if not pattern_string:
                st.error("Pattern string is required")
                return None
                
            return {
                "pattern_id": pattern_data.get("PATTERN_ID", str(uuid.uuid4())),
                "pattern_name": pattern_name,
                "pattern_string": pattern_string,
                "description": description,
                "category_name": category,
                "sensitivity_weight": float(sensitivity_weight),
                "is_active": is_active
            }
    
    return None

def render_keywords_tab():
    """Render the keywords management tab."""
    st.header("Sensitive Keywords")
    
    # Add new keyword
    with st.expander("Add New Keyword", expanded=False):
        keyword_data = render_keyword_form()
        if keyword_data:
            if save_keyword(keyword_data, is_new=True):
                st.success("Keyword saved successfully!")
                st.rerun()
    
    # List all keywords
    keywords = get_sensitive_keywords()
    
    if not keywords:
        st.info("No keywords found. Add a keyword to get started.")
        return
    
    # Convert to DataFrame for display
    df = pd.DataFrame([{
        "Keyword": k["KEYWORD_STRING"],
        "Match Type": k["MATCH_TYPE"],
        "Category": k["CATEGORY_NAME"],
        "Weight": k["SENSITIVITY_WEIGHT"],
        "Active": "✅" if k["IS_ACTIVE"] else "❌",
        "Last Updated": k["UPDATED_AT"] or k["CREATED_AT"],
        "_id": k["KEYWORD_ID"]
    } for k in keywords])
    
    # Display the table with edit/delete actions
    st.data_editor(
        df.drop(columns=["_id"]),
        hide_index=True,
        use_container_width=True,
        key="keywords_table"
    )
    
    # Handle row selection for edit/delete
    selected_rows = st.session_state.get("keywords_table", {}).get("selected_rows", [])
    
    if selected_rows:
        selected_row = selected_rows[0]
        keyword_id = df.iloc[selected_row]["_id"]
        keyword_data = next((k for k in keywords if k["KEYWORD_ID"] == keyword_id), None)
        
        if keyword_data:
            col1, col2 = st.columns([1, 1])
            
            with col1:
                if st.button("Edit Keyword"):
                    st.session_state["editing_keyword"] = keyword_data
            
            with col2:
                if st.button("Delete Keyword", type="primary"):
                    if delete_keyword(keyword_data["KEYWORD_STRING"], keyword_data["CATEGORY_NAME"]):
                        st.success("Keyword deleted successfully!")
                        st.rerun()
    
    # Handle editing
    if "editing_keyword" in st.session_state:
        st.markdown("---")
        keyword_data = st.session_state["editing_keyword"]
        updated_data = render_keyword_form(keyword_data)
        
        if updated_data:
            if save_keyword(updated_data, is_new=False):
                del st.session_state["editing_keyword"]
                st.success("Keyword updated successfully!")
                st.rerun()
        
        if st.button("Cancel"):
            del st.session_state["editing_keyword"]
            st.rerun()

def render_patterns_tab():
    """Render the patterns management tab."""
    st.header("Sensitive Patterns")
    
    # Add new pattern
    with st.expander("Add New Pattern", expanded=False):
        pattern_data = render_pattern_form()
        if pattern_data:
            if save_pattern(pattern_data, is_new=True):
                st.success("Pattern saved successfully!")
                st.rerun()
    
    # List all patterns
    patterns = get_sensitive_patterns()
    
    if not patterns:
        st.info("No patterns found. Add a pattern to get started.")
        return
    
    # Convert to DataFrame for display
    df = pd.DataFrame([{
        "Name": p["PATTERN_NAME"],
        "Pattern": p["PATTERN_STRING"],
        "Category": p["CATEGORY_NAME"],
        "Weight": p["SENSITIVITY_WEIGHT"],
        "Active": "✅" if p["IS_ACTIVE"] else "❌",
        "Last Updated": p["UPDATED_AT"] or p["CREATED_AT"],
        "_id": p["PATTERN_ID"]
    } for p in patterns])
    
    # Display the table with edit/delete actions
    st.data_editor(
        df.drop(columns=["_id"]),
        hide_index=True,
        use_container_width=True,
        key="patterns_table"
    )
    
    # Handle row selection for edit/delete
    selected_rows = st.session_state.get("patterns_table", {}).get("selected_rows", [])
    
    if selected_rows:
        selected_row = selected_rows[0]
        pattern_id = df.iloc[selected_row]["_id"]
        pattern_data = next((p for p in patterns if p["PATTERN_ID"] == pattern_id), None)
        
        if pattern_data:
            col1, col2 = st.columns([1, 1])
            
            with col1:
                if st.button("Edit Pattern"):
                    st.session_state["editing_pattern"] = pattern_data
            
            with col2:
                if st.button("Delete Pattern", type="primary"):
                    if delete_pattern(pattern_id):
                        st.success("Pattern deleted successfully!")
                        st.rerun()
    
    # Handle editing
    if "editing_pattern" in st.session_state:
        st.markdown("---")
        pattern_data = st.session_state["editing_pattern"]
        updated_data = render_pattern_form(pattern_data)
        
        if updated_data:
            if save_pattern(updated_data, is_new=False):
                del st.session_state["editing_pattern"]
                st.success("Pattern updated successfully!")
                st.rerun()
        
        if st.button("Cancel"):
            del st.session_state["editing_pattern"]
            st.rerun()

def render_sensitivity_config_ui():
    """Main function to render the sensitivity configuration UI."""
    st.title("Sensitivity Configuration")
    
    tab1, tab2 = st.tabs(["Keywords", "Patterns"])
    
    with tab1:
        render_keywords_tab()
    
    with tab2:
        render_patterns_tab()
