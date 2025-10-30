# DATA CLASSIFICATION POLICY

## DOCUMENT HEADER
- Document Classification: Internal  
- Version: 1.0  
- Effective Date: 2025-09-24  
- Document Owner: Chief Data Officer  
- Approval Authority: Chief Executive Officer  
- Next Review Date: 2026-09-24

## DOCUMENT CONTROLS
### Document Details
- Document ID: AVD-DWH-DCLS-001  
- Version: V1.0  
- Classification: Internal  
- Document Type: Corporate Policy  
- Business Unit: Data Governance

**Abstract**  
This document establishes The data classification framework for all data stored, processed, and managed within Snowflake data warehouse environments. The policy defines classification levels, criteria, and procedures to ensure appropriate protection of organizational data assets.

### Revision History
| Version | Author(s) | Revision Description | Date |
|---|---|---|---|
| 1.0 | Data Governance Team | Initial Policy Creation | 2025-09-24 |

## TABLE OF CONTENTS
1. Introduction  
2. Purpose and Scope  
3. Key Definitions  
4. Data Classification Principles  
5. Classification Framework  
6. Classification Procedures  
7. Roles and Responsibilities  
8. Policy Compliance  
9. Appendices

---

## 1. INTRODUCTION
### 1.1 Business Context
The organization recognizes data as one of its most valuable business assets. As our organization increasingly relies on data-driven decision making through our Snowflake data warehouse platform, it becomes critical to establish a systematic approach to data classification that ensures appropriate protection while enabling business objectives.

### 1.2 Risk Context
Without proper data classification, The organization faces several significant risks including inappropriate handling of sensitive business information, regulatory compliance failures, security vulnerabilities, and operational inefficiencies. This policy addresses these risks by establishing clear classification criteria and procedures.

### 1.3 Policy Foundation
This policy provides the foundational framework for data classification within the organization's Snowflake environment, serving as the basis for subsequent data protection, access control, and governance policies.

## 2. PURPOSE AND SCOPE
### 2.1 Purpose
This policy establishes the official data classification framework for Snowflake data warehouse environments. The primary purposes are to:
- Define consistent classification criteria and procedures for categorizing data based on sensitivity and business value
- Establish standardized classification labels and their meanings
- Provide guidance for data owners and users on proper classification procedures
- Create foundation for risk-based data protection and governance
- Support regulatory compliance and audit requirements

### 2.2 Scope
#### 2.2.1 Organizational Scope
This policy applies to:
- All employees, contractors, consultants, and temporary staff
- Third-party vendors and partners accessing the organization's data systems
- All business units and subsidiaries using Snowflake environments

#### 2.2.2 Technical Scope
This policy covers:
- All data stored in the organization's Snowflake data warehouse environments
- Data imported from source systems into Snowflake
- Derived data, analytics, and reports generated from Snowflake data
- Metadata and configuration data within Snowflake systems

#### 2.2.3 Exclusions
This policy does not cover:
- Data stored in systems other than Snowflake (covered by separate policies)
- Specific technical security controls (covered by separate security policies)
- Data access management procedures (covered by separate access control policies)

## 3. KEY DEFINITIONS
### 3.1 Core Data Concepts
- Data: Raw facts, figures, or information in its unprocessed form stored within Avendra's Snowflake environment.
- Information: Data that has been processed, organized, or structured to provide meaning and context for business purposes.
- Data Asset: Any data collection, database, table, or information resource within Snowflake that provides business value to Avendra.
- Data Classification: The systematic process of categorizing data based on its confidentiality, integrity, and availability requirements.

### 3.2 Classification Terminology
- Confidentiality Level: The degree of protection required to prevent unauthorized disclosure of data.
- Integrity Level: The degree of protection required to prevent unauthorized modification or corruption of data.
- Availability Level: The degree of protection required to ensure data remains accessible when needed.
- Business Impact: The potential consequences to Avendra's operations, finances, or reputation if data is compromised.

### 3.3 Organizational Roles
- Data Owner: Business executive or manager responsible for specific data assets, including classification decisions.
- Data Custodian: Technical professional responsible for implementing data classification within Snowflake systems.
- Data Consumer: Individual who accesses or uses classified data in accordance with their business role.
- Data Classification Specialist: Trained professional who assists in data classification activities.

## 4. DATA CLASSIFICATION PRINCIPLES
### 4.1 Foundational Principles
- Business-Driven Classification: Data classification must be driven by business requirements and the value of data to the organization's operations. Business stakeholders, not technical teams, must lead classification decisions based on their understanding of data usage and importance.
- Risk-Based Approach: Classification levels must reflect the potential risk and business impact of data compromise. Higher sensitivity data requires higher classification levels and more stringent protection measures.
- Proportionate Protection: The level of data protection must be proportionate to the classification level. Over-classification creates unnecessary operational burden, while under-classification creates unacceptable risk.
- Lifecycle Awareness: Data classification may change throughout the data lifecycle as business value, sensitivity, or regulatory requirements evolve. Regular review and reclassification procedures must be established.

### 4.2 Implementation Principles
- Consistency: Classification decisions must be consistent across similar data types and business contexts to ensure uniform protection and avoid confusion.
- Clarity: Classification criteria must be clear and unambiguous to enable consistent decision-making by data owners and users.
- Practicality: Classification procedures must be practical and efficient to encourage compliance while minimizing operational disruption.
- Auditability: All classification decisions must be documented and auditable to support compliance requirements and governance activities.

## 5. CLASSIFICATION FRAMEWORK
### 5.1 Classification Methodology
Avendra employs a risk-based classification system that evaluates three core security attributes: Confidentiality (C), Integrity (I), and Availability (A). Each attribute is rated from 0 (lowest impact) to 3 (highest impact).

### 5.2 Security Attribute Levels
#### 5.2.1 Confidentiality (C) Levels
- C0 - Public: Information intended for public release or already publicly available. No business harm from unauthorized disclosure. Examples: Press releases, published reports, marketing materials
- C1 - Internal: Information intended for internal Avendra use only. Minor business impact from unauthorized disclosure. Examples: Internal policies, organizational charts, general business correspondence
- C2 - Restricted: Information requiring protection with significant impact if disclosed. Moderate to significant business harm from unauthorized disclosure. Examples: Customer lists, financial analysis, strategic plans, employee data
- C3 - Confidential: Information requiring highest protection with severe impact if disclosed. Major business, financial, or regulatory consequences from unauthorized disclosure. Examples: Trade secrets, personally identifiable information, financial reporting data

#### 5.2.2 Integrity (I) Levels
- I0 - Low Integrity: Data accuracy not critical to business operations. Minimal impact from data corruption or modification. Examples: Draft documents, temporary files
- I1 - Standard Integrity: Some business reliance on data accuracy. Moderate operational impact from data corruption. Examples: Reference information, historical data
- I2 - High Integrity: Significant business reliance on data accuracy. Material impact on operations from data corruption. Examples: Customer records, financial transactions
- I3 - Critical Integrity: Critical business dependence on data accuracy. Severe operational or regulatory impact from data corruption. Examples: Financial reporting data, regulatory submissions

#### 5.2.3 Availability (A) Levels
- A0 - Low Availability: Data access not time-critical for business operations. Minimal impact from temporary unavailability. Examples: Archived records, historical reference data
- A1 - Standard Availability: Some business dependence on data availability. Moderate operational impact from temporary unavailability. Examples: Training materials, administrative data
- A2 - High Availability: Significant business dependence on data availability. Material operational impact from unavailability. Examples: Customer service data, operational dashboards
- A3 - Critical Availability: Critical business dependence on continuous data availability. Severe operational impact from unavailability. Examples: Real-time transaction data, emergency response systems

### 5.3 Overall Risk Classification
The combination of Confidentiality, Integrity, and Availability ratings determines the overall risk classification:
- Low Risk: C0-C1, I0-I1, A0-A1 with no high-impact combinations — Minimal business risk requiring basic protection
- Medium Risk: C2, I2, or A2 ratings, or specific combinations of lower ratings — Moderate business risk requiring enhanced protection
- High Risk: C3, I3, or A3 ratings, or high-impact combinations — Significant business risk requiring comprehensive protection

### 5.4 Classification Labels
#### 5.4.1 Primary Labels
- Public — Green (C0)
- Internal — Yellow (C1)
- Restricted — Orange (C2)
- Confidential — Red (C3)

#### 5.4.2 Snowflake Tagging Implementation
Data classification in Snowflake shall be implemented using standardized tags for `data_classification`, `confidentiality_level`, `integrity_level`, and `availability_level` with appropriate allowed values for each category.

### 5.5 Special Classification Categories
- Personal Data (PII): Restricted (C2) minimum; sensitive personal data Confidential (C3)
- Financial Data: Restricted (C2) minimum; SOX-relevant data Confidential (C3)
- Regulatory Data: Classified according to the most restrictive applicable regulation

## 6. CLASSIFICATION PROCEDURES
### 6.1 Initial Classification Process
- Timing: All new data assets must be classified within 5 business days of being created or imported into Snowflake environments.
- Steps:
  1. Data Discovery: Identify and inventory the data asset
  2. Business Context Assessment: Understand data usage, purpose, and business value
  3. Risk Assessment: Evaluate potential impact of confidentiality, integrity, or availability compromise
  4. Classification Assignment: Apply appropriate classification level based on risk assessment
  5. Label Application: Apply classification tags within Snowflake environment
  6. Documentation: Record classification decision and rationale

### 6.2 Classification Decision Process
- Primary Assessment Questions
  - Confidentiality: Impact of unauthorized disclosure? Regulatory protection requirements? Contains personal, financial, or proprietary info? Competitive harm?
  - Integrity: Impact of corruption or modification? Criticality of accuracy? Regulatory requirements? Decision impact of inaccuracies?
  - Availability: Impact of unavailability? Time sensitivity? SLAs? Process disruption?
- Matrix Application
  1. Rate C, I, A (0–3)
  2. Determine overall risk from highest rating and combinations
  3. Assign classification label
  4. Document rationale

### 6.3 Reclassification Procedures
- Triggers: Usage changes, regulations, discovered errors, security incidents, process changes
- Process: Trigger identification → Impact assessment → Stakeholder consultation → Update classification → Document → Communicate

### 6.4 Quality Assurance
- Reviews: Peer (complex), Management (high-sensitivity), Technical (implementation)
- Consistency Checks: Cross-type consistency, proper criteria application, label/tag accuracy, documentation completeness

## 7. ROLES AND RESPONSIBILITIES
### 7.1 Governance Roles
- Chief Data Officer (CDO): Accountable for policy and program, dispute resolution, policy approvals, executive reporting
- Data Governance Committee: Policy/procedure review, dispute resolution, standards guidance, program monitoring

### 7.2 Business Roles
- Data Owners: Make initial decisions, provide context, approve reclassifications, ensure alignment, review annually
- Data Classification Specialists: Assist with criteria, methodology expertise, QA reviews, records maintenance, training

### 7.3 Technical Roles
- Data Custodians: Apply tags/labels, implement controls, monitor compliance, maintain metadata/docs, report issues
- Snowflake Administrators: Configure tagging, automate classification tools, generate reports, support audits, maintain system docs

### 7.4 End User Roles
- Data Consumers: Understand levels, handle appropriately, report issues, complete training, comply with handling requirements

## 8. POLICY COMPLIANCE
### 8.1 Compliance Requirements
- Mandatory: Classify all data, document rationale, apply approved tags, conduct regular reviews, complete training
- Monitoring: Monthly coverage/accuracy, quarterly decision/review checks, annual comprehensive audit, ongoing automated monitoring

### 8.2 Non-Compliance Consequences
- Violations: Retraining, management counseling, access restriction, disciplinary action for repeated/serious violations
- Exceptions: Require justification, risk assessment, mitigation plan, approvals, documentation, periodic review

### 8.3 Policy Maintenance
- Regular Review: Annual or upon significant business/regulatory/technology/audit changes
- Updates: Impact assessment, stakeholder consultation, committee review, executive approval (significant), communication/training, implementation plan

## 9. APPENDICES
### Appendix A: Classification Examples
- Published Financial Statements — Public (C0) — Already publicly available
- Internal Budget Reports — Restricted (C2) — Competitive sensitivity
- Customer Contact Information — Restricted (C2) — Privacy protection
- Employee Social Security Numbers — Confidential (C3) — High sensitivity PII
- Marketing Campaign Data — Internal (C1) — Internal business use
- Vendor Contract Terms — Restricted (C2) — Commercial sensitivity
- System Configuration Data — Internal (C1) — Operational information
- Financial Audit Reports — Confidential (C3) — Regulatory sensitivity
- Customer Survey Responses — Restricted (C2) — Privacy and competitive concerns
- Public Press Releases — Public (C0) — Intended for public distribution

### Appendix A.2: Decision Examples
- Customer Transaction History — C2, I3, A2 → Overall: Restricted. Rationale: Sensitive customer information with high integrity requirements
- Employee Training Materials — C1, I1, A1 → Overall: Internal. Rationale: No special sensitivity

### Appendix B: Quick Reference
- Decision Tree: Public? If yes → Public (C0). Else contains personal/proprietary/confidential? If yes → Severe harm? If yes → Confidential (C3) else Restricted (C2). Then assess I and A.
- Checklist:
  - Before: Understand purpose; identify stakeholders; consider regulations; assess C/I/A impact; review similar data; document rationale
  - After: Apply tags; document decision; communicate; schedule review; ensure handling procedures are followed

---

Document Owner: Chief Data Officer  
Approved By: Chief Executive Officer
