-- Create LABEL_COLOR_MAPPING table for visual classification label mapping
-- This table maps classification labels to colors and metadata for UI display

CREATE OR REPLACE TABLE LABEL_COLOR_MAPPING (
    LABEL_ID STRING PRIMARY KEY,
    CLASSIFICATION_LABEL STRING NOT NULL,
    COLOR_NAME STRING NOT NULL,
    HEX_CODE STRING NOT NULL,
    EMOJI STRING,
    DESCRIPTION STRING,
    DISPLAY_ORDER INTEGER DEFAULT 1,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    CREATED_BY STRING DEFAULT CURRENT_USER(),
    VERSION_NUMBER INTEGER DEFAULT 1
);

-- Seed data for standard classification labels
INSERT INTO LABEL_COLOR_MAPPING (
    LABEL_ID,
    CLASSIFICATION_LABEL,
    COLOR_NAME,
    HEX_CODE,
    EMOJI,
    DESCRIPTION,
    DISPLAY_ORDER
) VALUES
    ('PUBLIC', 'Public', 'Green', '#22c55e', '🟩', 'Public data, no restriction', 1),
    ('INTERNAL', 'Internal', 'Yellow', '#eab308', '🟨', 'Internal-only business data', 2),
    ('RESTRICTED', 'Restricted', 'Orange', '#f97316', '🟧', 'Sensitive; moderate risk', 3),
    ('CONFIDENTIAL', 'Confidential', 'Red', '#ef4444', '🟥', 'Highly sensitive / regulated', 4);
