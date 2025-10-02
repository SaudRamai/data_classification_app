# Data Assets Page - UI/UX Design Guide

## 🎨 Visual Design System

### Color Palette

#### Classification Colors
```css
Public:        #2ECC71 (Green)   - Low sensitivity
Internal:      #F1C40F (Yellow)  - Medium sensitivity
Restricted:    #E67E22 (Orange)  - High sensitivity
Confidential:  #E74C3C (Red)     - Critical sensitivity
```

#### Status Colors
```css
Active:        #2ECC71 (Green)
Deprecated:    #E67E22 (Orange)
Archived:      #95A5A6 (Gray)
```

#### Accent Colors
```css
Info:          #3498db (Blue)
Success:       #2ED4C6 (Teal)
Warning:       #F1C40F (Yellow)
Error:         #E74C3C (Red)
```

---

## 📐 Layout Structure

### Page Hierarchy
```
┌─────────────────────────────────────────────────────────────┐
│ 🗂️ Data Assets Inventory                                    │
│ Comprehensive asset management with lifecycle tracking...   │
├─────────────────────────────────────────────────────────────┤
│ 🔄 Refresh Button                                           │
├─────────────────────────────────────────────────────────────┤
│ Tabs: [Inventory] [Discovery Feed] [Bulk Actions] [Export] │
└─────────────────────────────────────────────────────────────┘
```

### Inventory Tab Layout
```
┌─────────────────────────────────────────────────────────────┐
│ 📊 Asset Overview (Section Header)                          │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│ │📦 Total │ │✅ Cover │ │⚠️ High  │ │⏰ Over  │           │
│ │ Assets  │ │  age    │ │  Risk   │ │  due    │           │
│ │  1,234  │ │   85%   │ │   45    │ │   12    │           │
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
├─────────────────────────────────────────────────────────────┤
│ 🔍 Search & Filter Assets (Section Header)                  │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Filter Panel (Expandable)                               │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ 🎯 Primary Filters                                  │ │ │
│ │ │ [Search] [Classification] [Compliance]              │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ ⚡ Advanced Filters                                  │ │ │
│ │ │ [Min Rows] [Min Size] [Max Cost] [Min Deps]        │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ 🏢 Business Context                                  │ │ │
│ │ │ [Business Unit] [Domain] [Type]                     │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ 🔄 Lifecycle & Data Categories                       │ │ │
│ │ │ [Lifecycle] [Category]                              │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ 📋 Column-Level Filters (Advanced)                   │ │ │
│ │ │ [Column Name] [Data Type] [Masking] [Category]     │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ 📊 Asset Inventory Results (Section Header)                 │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Found 234 assets (180 tables, 54 views) │ Page 1/10    │ │
│ └─────────────────────────────────────────────────────────┘ │
│ ┌──────────────────┬──────────────────┐                    │
│ │ Classification   │ Top Schemas      │                    │
│ │ Distribution     │ by Asset Count   │                    │
│ └──────────────────┴──────────────────┘                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Main Asset Table (Paginated, Sortable, Filterable)     │ │
│ │ [Columns Selector] [Download CSV]                       │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ 🔗 Asset Relationships & Discovery (Section Header)         │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Relationship Visualization (Expandable)                 │ │
│ │ ┌──────────────────────┬──────────────────────┐         │ │
│ │ │ Upstream             │ Downstream           │         │ │
│ │ │ Dependencies         │ Dependencies         │         │ │
│ │ └──────────────────────┴──────────────────────┘         │ │
│ │ Similar Asset Recommendations (AI-scored)               │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ 🏷️ Asset Details & Management (Section Header)             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ [Select Asset Dropdown]                                 │ │
│ │ • View Tags                                             │ │
│ │ • Asset Metadata (Expandable)                           │ │
│ │ • Ownership & Lifecycle (Expandable)                    │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Component Design Patterns

### 1. KPI Cards
**Design**: Gradient background with hover effect
```html
<div class='kpi-card kpi-{classification}'>
    <div>📦 Title</div>
    <div style='font-size: 32px'>Value</div>
    <div style='font-size: 12px'>Description</div>
</div>
```

**Features**:
- Left border color-coded by classification
- Hover animation (lift + shadow)
- Icon + title + value + description
- Responsive 4-column grid

### 2. Section Headers
**Design**: Bold with bottom border
```html
<div class='section-header'>🔍 Section Title</div>
```

**Features**:
- Icon prefix for visual recognition
- 18px font, 600 weight
- Bottom border for separation
- Consistent spacing (20px top, 10px bottom)

### 3. Filter Sections
**Design**: Grouped cards with subtle background
```html
<div class='filter-section'>
    <strong>🎯 Filter Group Name</strong>
    [Filter Controls]
</div>
```

**Features**:
- Light background (rgba(255,255,255,0.03))
- Rounded corners (8px)
- Padding (15px)
- Subtle border
- Icon prefix for category

### 4. Info Boxes
**Design**: Blue gradient with left accent
```html
<div class='info-box'>
    <strong>💡 Title</strong><br>
    Description text
</div>
```

**Features**:
- Blue gradient background
- Left accent border (4px solid #3498db)
- Rounded corners
- Used for contextual help

### 5. Relationship Cards
**Design**: Subtle background with left accent
```html
<div class='relationship-card'>
    <div>Title</div>
    <div>Description</div>
</div>
```

**Features**:
- Light background
- Blue left border
- Used for related content grouping

---

## 📱 Responsive Design

### Breakpoints
```css
Desktop:  > 1200px  (4-column KPIs, 3-column filters)
Tablet:   768-1200px (2-column KPIs, 2-column filters)
Mobile:   < 768px   (1-column stacked)
```

### Column Layouts
- **KPI Cards**: 4 columns (desktop) → 2 columns (tablet) → 1 column (mobile)
- **Filters**: 3 columns → 2 columns → 1 column
- **Charts**: Side-by-side → Stacked
- **Relationships**: 2 columns → 1 column

---

## 🎨 Typography

### Font Hierarchy
```css
Page Title:       32px, 700 weight
Section Header:   18px, 600 weight
Card Title:       14px, 600 weight
KPI Value:        32px, 700 weight
Body Text:        14px, 400 weight
Caption:          12px, 400 weight
```

### Font Family
- Primary: System font stack (optimized for readability)
- Monospace: For code/data values

---

## 🔄 Interactive States

### Hover Effects
```css
KPI Cards:
  - translateY(-2px)
  - box-shadow: 0 6px 12px rgba(0,0,0,0.15)

Buttons:
  - Opacity: 0.9
  - Cursor: pointer

Links:
  - Underline
  - Color: #3498db
```

### Focus States
- Blue outline (2px solid #3498db)
- Visible keyboard navigation
- WCAG 2.1 AA compliant

### Loading States
- Spinner with "Loading..." text
- Skeleton screens for tables
- Progress indicators for long operations

---

## 🎭 Visual Indicators

### Status Badges
```html
✅ Classified
❌ Unclassified
⏰ Overdue
```

**Styling**:
- Rounded pill shape (border-radius: 999px)
- Colored background with border
- Icon + text
- 11px font, 600 weight

### Risk Indicators
```
Low:     Green dot
Medium:  Yellow dot
High:    Red dot
```

### Lifecycle Status
```
Active:      Green text
Deprecated:  Orange text
Archived:    Gray text
```

---

## 📊 Data Visualization

### Chart Types

#### 1. Classification Distribution (Pie Chart)
- **Library**: Altair
- **Theme**: Dark mode
- **Colors**: Classification color palette
- **Tooltip**: Classification + Count
- **Interactive**: Hover highlights

#### 2. Top Schemas (Bar Chart)
- **Library**: Altair
- **Orientation**: Horizontal
- **Sort**: Descending by count
- **Limit**: Top 10
- **Tooltip**: Schema + Count

#### 3. Relationship Graph (Future)
- **Library**: NetworkX / D3.js
- **Layout**: Force-directed
- **Nodes**: Assets (color by classification)
- **Edges**: Dependencies (directional arrows)

---

## 🔍 Search & Filter UX

### Search Behavior
1. **Instant feedback**: Results update as you type
2. **Placeholder text**: "DB, schema, table, column or tags"
3. **Clear button**: X icon to reset search
4. **Column search toggle**: Checkbox for deep search

### Filter Organization
1. **Progressive disclosure**: Grouped in expandable sections
2. **Visual grouping**: Color-coded sections with icons
3. **Smart defaults**: Most common filters at top
4. **Clear all**: Button to reset all filters

### Filter Feedback
- **Result count**: "Found X assets" updates live
- **Applied filters**: Visible chips/tags
- **No results**: Helpful message with suggestions

---

## 📋 Table Design

### Features
- **Sticky header**: Stays visible while scrolling
- **Sortable columns**: Click header to sort
- **Resizable columns**: Drag column borders
- **Column selector**: Show/hide columns
- **Row hover**: Highlight on hover
- **Zebra striping**: Alternate row colors
- **Pagination**: 25/50/100 per page

### Column Types
- **Text**: Left-aligned
- **Numbers**: Right-aligned with comma formatting
- **Dates**: ISO format with relative time
- **Status**: Badges with icons
- **Actions**: Icon buttons

---

## 🎯 Accessibility (WCAG 2.1 AA)

### Color Contrast
- **Text on background**: 4.5:1 minimum
- **Large text**: 3:1 minimum
- **Icons**: 3:1 minimum

### Keyboard Navigation
- **Tab order**: Logical flow
- **Focus indicators**: Visible outlines
- **Skip links**: Jump to main content
- **Escape key**: Close modals/expanders

### Screen Readers
- **ARIA labels**: Descriptive labels for all controls
- **ARIA live regions**: Announce dynamic updates
- **Alt text**: Descriptive text for icons
- **Semantic HTML**: Proper heading hierarchy

---

## 🚀 Performance Optimization

### Loading Strategy
1. **Critical content first**: KPIs and search
2. **Lazy load**: Charts and relationships
3. **Pagination**: Limit table rows
4. **Caching**: 5-minute TTL on queries

### Visual Feedback
- **Skeleton screens**: Show structure while loading
- **Progress bars**: For long operations
- **Spinners**: For quick operations
- **Success/error toasts**: Confirm actions

---

## 💡 User Experience Principles

### 1. Progressive Disclosure
- Start with overview (KPIs)
- Expand for details (filters, relationships)
- Drill down for specifics (asset details)

### 2. Consistency
- Same patterns across all tabs
- Consistent terminology
- Predictable behavior

### 3. Feedback
- Immediate response to actions
- Clear success/error messages
- Visual confirmation of state changes

### 4. Efficiency
- Keyboard shortcuts
- Bulk operations
- Smart defaults
- Quick filters

### 5. Forgiveness
- Undo/redo where possible
- Confirmation for destructive actions
- Auto-save drafts
- Clear error recovery

---

## 🎨 Icon System

### Icon Library
Using Unicode emojis for cross-platform consistency:

```
📦 Assets/Inventory
🔍 Search
🎯 Target/Primary
⚡ Advanced/Fast
🏢 Business
🔄 Lifecycle/Refresh
📋 List/Details
🔗 Relationships/Links
🏷️ Tags/Labels
⚙️ Settings/Operations
📥 Export/Download
📊 Charts/Analytics
✅ Success/Approved
❌ Error/Denied
⏰ Time/Deadline
⚠️ Warning/Risk
💡 Info/Help
```

---

## 📐 Spacing System

### Scale (8px base unit)
```
xs:   4px   (0.5x)
sm:   8px   (1x)
md:   16px  (2x)
lg:   24px  (3x)
xl:   32px  (4x)
2xl:  48px  (6x)
```

### Component Spacing
- **Card padding**: 20px (2.5x)
- **Section margin**: 20px top, 10px bottom
- **Filter section margin**: 15px bottom
- **Column gap**: 16px (2x)
- **Row gap**: 8px (1x)

---

## 🎬 Animation Guidelines

### Timing
```css
Fast:    150ms  (hover, focus)
Medium:  300ms  (expand, collapse)
Slow:    500ms  (page transitions)
```

### Easing
```css
Standard:  ease-in-out
Enter:     ease-out
Exit:      ease-in
```

### Principles
- **Subtle**: Don't distract from content
- **Purposeful**: Communicate state changes
- **Performant**: Use transform/opacity only
- **Respectful**: Honor prefers-reduced-motion

---

## 📱 Mobile Considerations

### Touch Targets
- **Minimum size**: 44x44px
- **Spacing**: 8px between targets
- **Feedback**: Visual response on tap

### Mobile-Specific
- **Swipe gestures**: Navigate between tabs
- **Pull to refresh**: Update data
- **Bottom navigation**: Easy thumb access
- **Collapsible sections**: Save screen space

---

## 🎯 Call-to-Action Hierarchy

### Primary Actions
- **Style**: Solid background, high contrast
- **Examples**: "Apply to Selected", "Download CSV"
- **Color**: Blue (#3498db)

### Secondary Actions
- **Style**: Outlined, medium contrast
- **Examples**: "View Tags", "Apply Owner"
- **Color**: Gray outline

### Tertiary Actions
- **Style**: Text only, low contrast
- **Examples**: "Cancel", "Clear filters"
- **Color**: Gray text

---

## 📚 Best Practices Summary

### Do's ✅
- Use consistent spacing and colors
- Provide clear feedback for all actions
- Group related controls together
- Use icons to enhance recognition
- Make important actions prominent
- Test with real data and edge cases
- Optimize for performance
- Follow accessibility guidelines

### Don'ts ❌
- Don't use color alone to convey information
- Don't hide critical information in tooltips
- Don't use jargon without explanation
- Don't make users memorize information
- Don't disable controls without explanation
- Don't use tiny touch targets on mobile
- Don't animate excessively
- Don't ignore loading states

---

**Last Updated**: 2025-10-01  
**Version**: 2.0  
**Design System**: Material Design inspired, Dark theme optimized
