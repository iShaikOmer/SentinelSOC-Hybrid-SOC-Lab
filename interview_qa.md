# SOC L2 interview preparation — explain your project

**Q1. Why is AUTH-002 more severe than AUTH-001?**

A password-spray pattern alone shows suspicious authentication failures. A subsequent successful login from the same source increases concern about credential compromise, but it still requires validation against MFA, Conditional Access, client/device details and any legitimate admin usage.

**Q2. Why do you use distinct user count?**

It separates wide spraying across many accounts from one user repeatedly mistyping a password. The lab's negative control contains six failures for one account, which should not trigger a spray alert.

**Q3. What would you tune before production use?**

Service IP allowlists, NAT/shared networks, known scanning/test traffic, sign-in failure codes, time bins, ingestion delay, threshold and alert deduplication. I would test against a representative authorized dataset and document false-positive dispositions.

**Q4. How do you investigate encoded PowerShell?**

Inspect the process tree, account context, full command line, signer, host criticality, script contents if permitted, user/admin change request, EDR telemetry and network behavior. Encoded scripting is a lead, not proof of malware.

**Q5. What evidence supports privileged-group change detection?**

Windows Security Events 4728/4732/4756 can record additions to security-enabled groups. Validate target group sensitivity, actor, affected account, timing, and approved change ticket.

**Q6. What is the difference between the Python detector and KQL rules?**

The Python code executes locally on synthetic CSV files and uses a sliding window. The KQL files are examples for native Log Analytics/Sentinel tables using scheduled/fixed-bin logic; they need cloud-side verification and tuning.

**Q7. What does the SOAR workflow automate?**

It is a documented blueprint for low-risk enrichment, tagging, incident comments and triage task creation. It deliberately gates disruptive actions for an analyst; no Azure Logic App has been deployed in this project.

**Q8. How would you measure a real improvement?**

Choose a baseline window, consistent alerts/cases and timestamps. Measure MTTD from first observable security activity to alert creation, MTTR from incident initiation/validation to appropriate containment or closure according to the employer's definitions, and false-positive rate from adjudicated alerts. Do not assign performance percentages to this synthetic dataset.
