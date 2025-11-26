#!/usr/bin/env python3
"""
Script to update confidence thresholds and add boosting logic
"""

# Read the file
with open('data-governance-app/src/services/ai_classification_pipeline_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Update thresholds from 50% to 60%
content = content.replace('confidence >= 0.50', 'confidence >= 0.60')
content = content.replace('confidence < 0.50', 'confidence < 0.60')
content = content.replace('< 50%', '< 60%')

# 2. Add boosting logic after "confidence = float(combined.get(best_cat, 0.0))"
# Find the location and insert boosting code
old_code = """                        best_cat = max(combined, key=combined.get)
                        confidence = float(combined.get(best_cat, 0.0))
                        
                    # Multi-signal check (optional logging)"""

new_code = """                        best_cat = max(combined, key=combined.get)
                        confidence = float(combined.get(best_cat, 0.0))
                        
                        # CONFIDENCE BOOSTING: Increase confidence when strong signals are present
                        s_score = float(sem.get(best_cat, 0.0))
                        k_score = float(kw.get(best_cat, 0.0))
                        p_score = float(pt.get(best_cat, 0.0))
                        g_score = float(gov_sem.get(best_cat, 0.0))
                        
                        # Count strong signals (>= 0.4)
                        strong_signals = sum([
                            s_score >= 0.4,
                            k_score >= 0.4,
                            p_score >= 0.4,
                            g_score >= 0.4
                        ])
                        
                        # Boost confidence based on signal strength
                        if strong_signals >= 3:
                            confidence = min(0.99, confidence * 1.25)
                            logger.info(f"    BOOSTED (3+ signals): {col_name} {confidence:.1%}")
                        elif strong_signals >= 2:
                            confidence = min(0.95, confidence * 1.15)
                            logger.info(f"    BOOSTED (2 signals): {col_name} {confidence:.1%}")
                        elif strong_signals >= 1 and confidence >= 0.5:
                            confidence = min(0.90, confidence * 1.10)
                        
                        # Additional boost for very strong individual signals
                        if s_score >= 0.7 or k_score >= 0.7 or p_score >= 0.7:
                            confidence = min(0.99, confidence * 1.10)
                            logger.info(f"    BOOSTED (strong signal): {col_name} {confidence:.1%}")
                        
                    # Multi-signal check (optional logging)"""

content = content.replace(old_code, new_code)

# Write back
with open('data-governance-app/src/services/ai_classification_pipeline_service.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Successfully updated confidence thresholds to 60% and added boosting logic")
