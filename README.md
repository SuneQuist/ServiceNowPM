# Patch & Mitigation Assessment — ServiceNow

**Patch & Mitigation Assessment** is a custom ServiceNow application developed to support IT operations and security teams with vulnerability assessment, remediation prioritization, technical troubleshooting, and evidence-based decision-making.

The application integrates vulnerability intelligence with the **SSVC 2.0 Deployer decision tree** and generates actionable mitigation and patching guidance directly from ServiceNow Incident records.

### Access Application

Use the "Access Patch Risk" button under an Incident.
<img width="2555" height="41" alt="image" src="https://github.com/user-attachments/assets/79d091e0-52a8-4ccc-a259-713722fcec9d" />


## Application Overview

![Patch & Mitigation Assessment dashboard](https://github.com/user-attachments/assets/9d9d9268-789f-4864-adaa-97b84b237dce)

The application provides a centralized dashboard for reviewing vulnerability context, assessment status, external intelligence, and recommended responses.

## Vulnerability Intelligence

![Vulnerability intelligence overview](https://github.com/user-attachments/assets/c2b58489-0375-4ab3-9296-3e49311c08fd)

The application retrieves and presents information from three external security intelligence sources:

- **NVD (National Vulnerability Database):** CVE descriptions, CVSS scores, and severity.
- **CISA KEV:** Known exploited vulnerabilities and relevant exploitation evidence.
- **FIRST EPSS:** Probability estimates for exploitation in the next 30 days.

External intelligence supports analyst decisions without automatically treating CVSS or EPSS scores as definitive SSVC evidence.

## SSVC Risk Assessment

![SSVC assessment interface](https://github.com/user-attachments/assets/30551dbb-90d3-415f-81f7-452b637e350c)

![SSVC assessment details](https://github.com/user-attachments/assets/746a54d6-d367-4a46-a337-662ac064d9e1)

The application implements the **SSVC 2.0 Deployer decision tree**, evaluating:

- Exploitation status and system exposure.
- Exploit utility, derived from automatability and value density.
- Human impact, derived from safety and mission impact.
- Vulnerability applicability.

Based on these factors, the application determines an appropriate response: **Immediate, Out-of-Cycle, Scheduled, or Defer**.

The decision logic supports partial assessments when the available evidence produces an unambiguous outcome, while explicitly identifying unresolved information when it could change the result.

SSVC prioritization is maintained separately from ServiceNow Incident Impact, Urgency, and Priority.

## Dynamic Action Plans

![Mitigation and patching action plans](https://github.com/user-attachments/assets/93604b72-4d8a-4c86-9444-f436f929bbdf)

The application generates structured mitigation and patching guidance based on the calculated SSVC decision and available remediation information.

Action plans include recommended steps, responsible roles, operational explanations, and considerations for authorization, testing, rollback, and verification.

The guidance adapts to patch availability and supports situations where a vendor fix is unavailable or a system is no longer supported.

## Technical Investigation and Evidence

![Technical investigation workspace](https://github.com/user-attachments/assets/30204734-547d-4188-82af-338a6bd5e607)

A dedicated investigation workspace allows administrators to research recurring incidents, software regressions, update failures, and vulnerability-related issues.

It supports searches of accessible ServiceNow Knowledge articles, links to vendor documentation, technical communities, and recent public web results.

Administrators can also record supporting URLs, comments, investigation notes, and other relevant evidence.

*Native ServiceNow AI/Now Assist is a potential future integration and is not currently required for the investigation workflow.*

## Assessment History and Traceability

![Assessment history](https://github.com/user-attachments/assets/ebca22ef-7e7e-44eb-bc61-a9330a1fac9a)

Assessment revisions preserve the context behind previous decisions, supporting documentation, and changes in vulnerability prioritization over time.

This provides a traceable record of how an Incident was assessed and why particular mitigation or patching actions were recommended.

## Technology Stack

| Technology | Purpose |
|---|---|
| ServiceNow Scoped Application | Application platform and Incident integration |
| JavaScript | Assessment logic and interactive functionality |
| Script Includes | Server-side SSVC calculation and action-plan generation |
| Jelly, HTML and CSS | Custom application interface |
| GlideRecordSecure | Permission-aware ServiceNow record access |
| NVD API | CVE and CVSS intelligence |
| CISA KEV | Known exploitation intelligence |
| FIRST EPSS | Exploitation probability context |

## Project Goal

The purpose of this project is to bridge the gap between **security intelligence and practical IT operations**.

Instead of relying exclusively on vulnerability severity scores, the application combines technical evidence, organizational context, structured prioritization, and documented investigation findings to support informed remediation decisions.

The project demonstrates experience with ServiceNow development, API integration, JavaScript, security assessment methodologies, workflow design, and technical problem-solving.

---

**Project status:** Functional prototype developed in a ServiceNow Personal Developer Instance (PDI). Production use would require additional testing, security review, and integration validation.
