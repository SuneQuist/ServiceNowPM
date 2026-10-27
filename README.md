# ServiceNowPM
ServiecNow Patching &amp; Mitigation Scoped App

<img width="1172" height="759" alt="image" src="https://github.com/user-attachments/assets/a5a9500f-3e05-480f-a835-e1b40b02b8ba" />
<img width="1123" height="840" alt="image" src="https://github.com/user-attachments/assets/c7f48c46-e50a-4af2-b249-c4c6d5e1435e" />

===========================================================================

NIST SP 1800-31B

===========================================================================
https://www.nccoe.nist.gov/publication/1800-31/VolB/index.html#approach

For CIO \& CISO, incl. IT personnel.
Covers Asset identification and assessment, and how you should handle and prioritize including co-op between different departments in an org.

**Scenarios**

Scenario 0: Asset Identification and assessment

Scenario 1: Routing patching

Scenario 2: Routing patching with cloud delivery model

Scenario 3: Emergency patching

Scenario 4: Emergency mitigation (and backout if needed)

Scenario 5: Isolation of unpatchable assets

Scenario 6: Patch management system security (or other system with administrative privileged access)

**Risk Assessment**

https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf

"Risk is a measure of the extent to which an entity is threatened by a potential circumstance or event, and typically a function of: (i) the adverse impacts that would arise if the circumstance or event occurs; and (ii) the likelihood of occurrence."

"Risk assessment is the process of identifying, estimating, and prioritizing risks to organizational operations (including mission, functions, image, reputation), organizational assets, individuals, other organizations, and the Nation, resulting from the operation of an information system. Part of risk management incorporates threat and vulnerability analyses, and considers mitigations provided by security controls planned or in place"

Example and implementations of A and B from NIST SP 1800-31
https://www.nccoe.nist.gov/publication/1800-31/VolC/index.html

Vuln. Assessment: https://www.nccoe.nist.gov/publication/1800-31/\_images/image1.png

===========================================================================

Stakeholder-Specific Vulnerability Categorization (SSVC)

===========================================================================

https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc?utm\_source=chatgpt.com

https://www.first.org/epss/?utm\_source=chatgpt.com

Read the tree implementation if it does not fit your org: 
  https://www.sei.cmu.edu/documents/606/2021\_019\_001\_653461.pdf

Vulnerability management should prioritize decisions and actions, not just severity scores.
Basically, "Given the available evidence, our responsibilities, and the consequences for our organization, what should we do about it?".
A wider margin of -0.5 to +0.5 of a CVE can often be interpreted.

**Stakeholder perspectives:**

Suppliers is mainly worried about how urgently it should be developed and release a fix.

Deployer is worried about the urgency of patching and mitigation.
Coordinator is concerned about how a vuln. report should be triaged and coordinated.
  Relevant towards SOC and vuln. coordination.

**SSVC Categories:**

\* Defer

  No immediate action is required, assess again when more relevant info. changes.

\* Scheduled

  Handle the vuln. within normal planned maintenance and remediation processes.

\* Out-of-cycle

  Prioritize remediation outside the normal schedule, reallocating resources where appropriate.

\* Immediate
  Initiate urgent coordinated action using necessary available resources.

**The main decision factors.**

Factor -> What it asks? -> Possible values

Exploitation -> Is the vulnerability being exploited? -> None, Proof of Concept, Active

System Exposure -> How accessible is the vulnerable system? -> Small, Controlled, Open

Automatable -> Can attackers reliably automate exploitation? -> No, Yes

Value Density -> How valuable is a successful compromise to attackers? -> Diffuse, Concentrated

Utility -> How efficient and rewarding would exploitation be? -> Laborious, Efficient, Super Effective

Human Impact -> What happens to people and the organization's essential functions? -> Low, Medium, High, Very High


The reason this is more preferred to an ML or a different algo. Is that this is a traceable system,

so a technician can act upon reason, and see the logic behind the Response priority / final decision.



