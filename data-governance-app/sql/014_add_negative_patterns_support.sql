-- Add IS_NEGATIVE column to SENSITIVE_PATTERNS table
ALTER TABLE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS 
ADD COLUMN IF NOT EXISTS IS_NEGATIVE BOOLEAN DEFAULT FALSE;

-- Add comment for the new column
COMMENT ON COLUMN DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS.IS_NEGATIVE IS 
'When TRUE, this pattern is used to reduce false positives by matching non-sensitive data';

-- Insert negative patterns for PII category
INSERT INTO DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS (
    PATTERN_ID, 
    CATEGORY_ID, 
    PATTERN_NAME, 
    PATTERN_STRING, 
    DESCRIPTION, 
    SENSITIVITY_WEIGHT,
    IS_NEGATIVE,
    IS_ACTIVE
) 
SELECT 
    UUID_STRING(),
    'PII',
    'Negative Pattern - ' || TO_CHAR(ROW_NUMBER() OVER ()),
    pattern,
    'Negative pattern to reduce false positives for PII detection',
    0.5,
    TRUE,
    TRUE
FROM (
    SELECT 'PRODUCT' as pattern UNION ALL
    SELECT 'SKU' UNION ALL
    SELECT 'ITEM' UNION ALL
    SELECT 'MATERIAL' UNION ALL
    SELECT 'PART' UNION ALL
    SELECT 'ARTICLE' UNION ALL
    SELECT 'CATALOG' UNION ALL
    SELECT 'INVENTORY' UNION ALL
    SELECT 'STOCK' UNION ALL
    SELECT 'BATCH' UNION ALL
    SELECT 'ORDER' UNION ALL
    SELECT 'ORDER_LINE' UNION ALL
    SELECT 'LINE' UNION ALL
    SELECT 'TXN' UNION ALL
    SELECT 'TRANSACTION' UNION ALL
    SELECT 'REF' UNION ALL
    SELECT 'REFERENCE' UNION ALL
    SELECT 'SERIAL' UNION ALL
    SELECT 'SERIAL_NO' UNION ALL
    SELECT 'BARCODE' UNION ALL
    SELECT 'CURRENCY' UNION ALL
    SELECT 'FX' UNION ALL
    SELECT 'FOREX' UNION ALL
    SELECT 'EXCHANGE' UNION ALL
    SELECT 'RATE' UNION ALL
    SELECT 'PRICE' UNION ALL
    SELECT 'UNIT_PRICE' UNION ALL
    SELECT 'LIST_PRICE' UNION ALL
    SELECT 'AMOUNT_DUE' UNION ALL
    SELECT 'TAX_RATE' UNION ALL
    SELECT 'CATEGORY' UNION ALL
    SELECT 'SUBCATEGORY' UNION ALL
    SELECT 'TYPE' UNION ALL
    SELECT 'FLAG' UNION ALL
    SELECT 'STATUS' UNION ALL
    SELECT 'STATE' UNION ALL
    SELECT 'CODE' UNION ALL
    SELECT 'PRODUCT_CODE' UNION ALL
    SELECT 'ITEM_CODE' UNION ALL
    SELECT 'COLOR_CODE' UNION ALL
    SELECT 'ERROR_CODE'
) patterns
WHERE NOT EXISTS (
    SELECT 1 
    FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS 
    WHERE IS_NEGATIVE = TRUE 
    AND CATEGORY_ID = 'PII'
);

-- Insert negative patterns for Financial category
INSERT INTO DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS (
    PATTERN_ID, 
    CATEGORY_ID, 
    PATTERN_NAME, 
    PATTERN_STRING, 
    DESCRIPTION, 
    SENSITIVITY_WEIGHT,
    IS_NEGATIVE,
    IS_ACTIVE
) 
SELECT 
    UUID_STRING(),
    'FINANCIAL',
    'Negative Pattern - ' || TO_CHAR(ROW_NUMBER() OVER ()),
    pattern,
    'Negative pattern to reduce false positives for Financial data detection',
    0.5,
    TRUE,
    TRUE
FROM (
    SELECT 'CURRENCY' as pattern UNION ALL
    SELECT 'FX' UNION ALL
    SELECT 'EXCHANGE' UNION ALL
    SELECT 'RATE' UNION ALL
    SELECT 'SPOT' UNION ALL
    SELECT 'FORWARD' UNION ALL
    SELECT 'INDEX' UNION ALL
    SELECT 'PRICE_INDEX' UNION ALL
    SELECT 'BENCHMARK' UNION ALL
    SELECT 'QUANTITY' UNION ALL
    SELECT 'UNIT_PRICE' UNION ALL
    SELECT 'DISCOUNT' UNION ALL
    SELECT 'MARKUP' UNION ALL
    SELECT 'MARGIN' UNION ALL
    SELECT 'TAX_RATE' UNION ALL
    SELECT 'VAT_RATE'
) patterns
WHERE NOT EXISTS (
    SELECT 1 
    FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS 
    WHERE IS_NEGATIVE = TRUE 
    AND CATEGORY_ID = 'FINANCIAL'
);

-- Update the load_sensitivity_config function to include negative patterns
CREATE OR REPLACE PROCEDURE DATA_CLASSIFICATION_GOVERNANCE.LOAD_SENSITIVITY_CONFIG()
RETURNS VARIANT
LANGUAGE JAVASCRIPT
AS
$$
    // Existing implementation remains the same
    // ...
    
    // Add negative patterns to the config
    var negPatternsQuery = `
        SELECT 
            CATEGORY_ID as category,
            PATTERN_STRING as pattern,
            PATTERN_NAME as name,
            SENSITIVITY_WEIGHT as weight
        FROM ${schema_fqn}.SENSITIVE_PATTERNS
        WHERE IS_NEGATIVE = TRUE
        AND IS_ACTIVE = TRUE
        ORDER BY SENSITIVITY_WEIGHT DESC
    `;
    
    var negPatterns = [];
    try {
        var stmt = snowflake.createStatement({sqlText: negPatternsQuery});
        var rs = stmt.execute();
        while (rs.next()) {
            negPatterns.push({
                category: rs.getColumnValue(1),
                pattern: rs.getColumnValue(2),
                name: rs.getColumnValue(3),
                weight: rs.getColumnValue(4)
            });
        }
    } catch (err) {
        // Log error but don't fail
        snowflake.execute({
            sqlText: `
                INSERT INTO DATA_CLASSIFICATION_GOVERNANCE.AUDIT_LOG 
                (TIMESTAMP, ACTION, DETAILS)
                VALUES (
                    CURRENT_TIMESTAMP(),
                    'ERROR_LOADING_NEGATIVE_PATTERNS',
                    PARSE_JSON('{"error": ' + TO_JSON(ERROR_MESSAGE()) + '}')
                )
            `
        });
    }
    
    // Add negative patterns to the config
    var negativePatterns = {};
    for (var i = 0; i < negPatterns.length; i++) {
        var item = negPatterns[i];
        if (!negativePatterns[item.category]) {
            negativePatterns[item.category] = {
                name_tokens: [],
                value_regex: []
            };
        }
        
        // Simple heuristic: if pattern is all uppercase with underscores, treat as name token
        if (/^[A-Z0-9_]+$/.test(item.pattern)) {
            negativePatterns[item.category].name_tokens.push(item.pattern);
        } else {
            negativePatterns[item.category].value_regex.push(item.pattern);
        }
    }
    
    // Add to config
    config.negative_patterns = negativePatterns;
    
    // Rest of the existing implementation
    // ...
    
    return config;
$$;
