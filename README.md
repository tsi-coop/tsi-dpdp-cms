# TSI DPDP Consent Management System

An open-source consent management system compliant with India's DPDP Act, 2023.

TSI DPDP CMS serves two categories of adopters:

- **Data Fiduciaries**, who can self-host the solution to manage consents of their data principals
- **Consent Managers**, who can deploy the solution in multi-tenant mode to manage consent on behalf of one or more data fiduciaries

See Section 1.2 (Configure Consent Manager) of the System Design document, linked below, for details on both deployment modes.

## Introduction

[Launch Note](https://techadvisory.substack.com/p/tsi-dpdp-cms-an-open-source-consent)

[The Big Picture - Video](https://youtu.be/caQFjwrZj9w)

[System Design](https://github.com/tsi-coop/tsi-dpdp-cms/blob/main/docs/design/TSI%20DPDP%20Consent%20Management%20System%20-%20System%20Design5.pdf)

[Managing the Data Lifecycle](https://techadvisory.substack.com/p/managing-the-data-lifecycle-a-first)

### Future Forward Proposals

[Solving Consent Fatigue via Portable Consent Artifacts (PCA)](https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via)

[Standardized Erasure Interface for DPDP Consent Managers](https://techadvisory.substack.com/p/the-need-for-standardized-erasure)


## Release Notes

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for the full version history.

## Installation

### Docker

1.  **Clone the repository to a separate folder**
    ```bash
    git clone https://github.com/tsi-coop/tsi-dpdp-cms.git tsi-dpdp-cms-eval
    ```
    ```bash
    cd tsi-dpdp-cms-eval
    ```
2.  **Set the one-time setup token**

    Before first boot, generate a random value and put it in a `.env` file next to `docker-compose.yml`:
    ```bash
    echo "TSI_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)" >> .env
    ```
    This is a mandatory security step.

3.  **Start the TSI DPDP CMS service**
    ```bash
    sudo docker compose up -d
    ```

### Binary

Check out [v0.5.3 release](https://github.com/tsi-coop/tsi-dpdp-cms/releases/tag/v0.5.3)

## Post-Installation Steps

The system includes a pre-configured interactive tour designed for evaluators and administrators.

**Access the Tour**: Open your browser and navigate to:
http://localhost:8080/tour

Follow the Guided Journey:

1. System Setup: Open `/console/setup/init.html`, enter the `TSI_BOOTSTRAP_TOKEN` value from step 2 as the Setup Token, and configure your master admin credentials.

2. Fiduciary Provisioning: Onboard your Fiduciaries, link Apps, and publish Multilingual Data Policies. [Watch Video](https://youtu.be/216gZPlokuM)

3. ROPA Definition and Policy Creation: Define Records of Processing Activities for every data processing purpose, validate DPO accountability fields, and generate compliance reports. [Watch Video](https://youtu.be/O_yhxu2o4Mc)

4. User Rights Management: Notice & capture, purpose-limited verification, and exercise of rights: view artifacts, withdraw, and grievances. [Watch Video](https://youtu.be/nlthzXlBc1M)

5. Consent Verifier: Test real-time API validation used by Data Processors to ensure purpose-limited processing.

6. Enforcement Logic: View the logic for technical data deletion, retention periods, and audit trail integrity. [Managing the Data Lifecycle](https://techadvisory.substack.com/p/managing-the-data-lifecycle-a-first)

7. Compliance Management: Comprehensive video walkthrough of the administrative console for managing compliance workflows. [Watch Video](https://youtu.be/TE27zu859_s)

8. Grievance Management: Section 13: Review, assign, and resolve grievances raised by Data Principals within statutory timelines. [Watch Video](https://youtu.be/OGrfJgHgmJg)

9. Breach Notification: Section 8(6): Report a breach, notify affected Principals, generate the PDF record, and bulk-notify via CSV upload through the Job Manager. [Watch Video](https://youtu.be/lHOAQSIrxh8)

10. Legal Module: Turn activity logs into verified, BSA Section 63-compliant digital evidence that holds up in court and meets regulatory rules. [Watch Video](https://youtu.be/neS4x46erHA) | [Securing Court-Ready Evidence under BSA Section 62](https://techadvisory.substack.com/p/dpdp-consent-manager-securing-court)

11. System Integration: API specifications for Data Fiduciaries and Processors to integrate CMS logic into backend technical stacks. [Watch Video](https://youtu.be/P6kY9aBc_gM)

12. Verifiable Parental Consent: Experience the Section 9 workflow: verifiable parental consent with OTP-based guardian identification for learners under 18. [Watch Video](https://youtu.be/kz4idKMBLXk)

13. DPDP Wallet Demo: Experience portable privacy. Checkout the [DPDP Wallet](https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via) concept, then download your PCA from the User Dashboard to manage your processing rights independently. [Watch Video](https://youtu.be/1N4TYXfamsw)

14. Password Recovery: Explore the "break-glass" account recovery mechanism using secure Master Recovery Keys. [Watch Video](https://youtu.be/LYouy1cqiGE)

15. Voice Consent Gateway: Experience hands-free, granular consent collection using Sarvam AI (TTS/STT) to obtain informed voice affirmations for processing purposes. [Watch Video](https://youtu.be/d6WuPd0mr9U) | [DPDP Inclusion: Interactive Voice Consent using Sarvam AI](https://techadvisory.substack.com/p/dpdp-inclusion-voice-consent-gateway)

16. Partner White Labeling: See how the `BRAND_NAME` environment variable rebrands the console, rights portal, tour, and report footers for partner deployments. [Watch Video](https://youtu.be/DyU4GI_3-DY)

## Guides

Pick the guide for your role:

| Your role | Guide | Covers |
|---|---|---|
| Compliance officers, DPOs, and the engineers configuring policy with them | [Implementation Guide](docs/guides/implementation-guide.md) | Data discovery, RoPA authoring, JSON policy compilation, DPIA, and the policy publishing/lifecycle workflow. |
| Developers at Data Fiduciaries/Processors integrating the client API | [System Integration Guide](docs/guides/system-integration-guide.md) | Authentication, permission scopes, and the policy/consent/grievance/purge endpoints for capturing consent and validating processing in real time. |
| Developers integrating a chatbot, IVR, or helpline CRM | [Chatbot and Voice Helpline Integration Guide](docs/guides/chatbot-and-voice-integration-guide.md) | Architecture diagrams, conversational and call lifecycles, and guardrails (deterministic consent, gated tool calls, unified phone-hash identity) for conversational channels. |
| Developers consuming notification and purge events after the fact | [Webhook Integration Guide](docs/guides/webhook-integration-guide.md)<br><br>[Client Polling Integration Guide](docs/guides/polling-integration-guide.md) | Push delivery (HMAC-SHA256-signed webhooks for Notification/Purge/OTP, v0.4.8+) and its reliable pull-based counterpart - the reconciliation path for anything a missed webhook delivery would drop. |
| Developers building from source | [Local Development Guide](docs/guides/local-development-guide.md) | Prerequisites (JDK, Maven, Docker, Jetty) and step-by-step build/run instructions, for both Docker and non-Docker setups. |
| DevOps / system administrators going to production | [Production Deployment Guide](docs/guides/production-deployment-guide.md) | Secrets management, running as a non-root user, disk encryption, data-tier isolation, and offsite backups, for both Docker and Binary installs. |

## Standards

- **Contribution & security process:** see [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).
- **API spec:** an OpenAPI 3.0 spec for the client API lives at [`docs/api/openapi.yaml`](docs/api/openapi.yaml) (static viewer at `docs/api/index.html`).
- **Accessibility:** the Data Principal rights portal (`web/rights`) has ARIA roles, live regions, keyboard focus management, semantic form labels, and WCAG-AA color contrast.
- **Rate limiting:** the principal OTP request/verification endpoints and the first-run bootstrap endpoint are rate-limited, both per-target and per-source-IP.
- **Testing:** see the [Testing](#testing) section below for the regression suite and load test.

## Data Portability & Non-PII Extraction

The TSI DPDP CMS lets administrators export system-generated configurations, audit logs, and processing definitions in open, non-proprietary formats:

* **Formats Supported:** Administrative configuration, Record of Processing Activities (RoPA) records, and event data are structured in JSON and CSV. The RoPA registry can be exported as CSV from the DPO console.
* **Interoperable APIs:** The system exposes standard REST API endpoints (see the [OpenAPI spec](docs/api/openapi.yaml)) and HMAC-signed webhooks (see the [Webhook Integration Guide](docs/guides/webhook-integration-guide.md)), allowing integration and synchronization with external data protection systems.
* **Non-PII Separation:** System configuration, RoPA definitions, and aggregate metrics can be extracted without Data Principal identities. Exports that reference individual consent or audit records may contain principal identifiers and should be handled as personal data.

## Privacy, Security, & Compliance

* **Regulatory Compliance:** Built in accordance with India's Digital Personal Data Protection (DPDP) Act, 2023, with signed, immutable audit and compliance log entries and verifiable consent withdrawal and erasure workflows.
* **Security Patching:** This repository actively patches and mitigates vulnerabilities. Standard deployments should use version 0.5.1 or later, which fixed missing server-side authentication on the admin and DPO console pages and on the first-run setup endpoint (CVE-2026-84840 / CVE-2026-84841). See the [release notes](RELEASE_NOTES.md) for details and [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.
* **Community Conduct:** Participation in the project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md), which sets expected behavior and explains how to report harassment or abuse.

## Testing

- **Regression tests:** [`docs/test-cases/regression-test-cases.md`](docs/test-cases/regression-test-cases.md) is a living, versioned suite of test cases covering the admin/DPO consoles, the data principal rights portal, the client and public APIs, webhooks, and the full purge lifecycle.
- **Load testing:** a runnable [Apache JMeter](https://jmeter.apache.org/) load test lives in [`tests/`](tests/), covering the full consent lifecycle against the client API: notice/policy retrieval, consent capture, processing validation (`validate_consent`), rights/dashboard reads, withdrawal/erasure, grievances, purge polling, and the full guardian OTP login round trip. See [`tests/README.md`](tests/README.md) for a quick-start and [`tests/load-testing-plan.md`](tests/load-testing-plan.md) for methodology and sizing guidance.

## White-Labeling

Partners can rebrand the entire UI - console, login screens, the data-principal rights portal, the evaluator tour, and report footers - with a single environment variable:

```bash
BRAND_NAME=Acme Privacy
```

`BRAND_NAME` is capped at **12 characters**, the exact length of the default brand "TSI DPDP CMS". The cap is intentional: it guarantees any compliant partner name is a drop-in replacement that fits every layout (sidebar widths, title bars, report footers) without redesign or risk of overflow. If `BRAND_NAME` is set but exceeds the limit, the application refuses to start with a clear error - the same fail-fast behavior as `JWT_SECRET` and `DB_ENCRYPTION_KEY`. Leave it unset to keep the default branding; nothing else changes.


## License & Contributions

This project is fully open-source and distributed under the **Apache 2.0 License**. You are completely free to fork, modify, and customize the codebase to fit your specific technical or enterprise needs without any restriction.

### Contributing Back to the Main Project
If you have built an optimization, bug fix, or feature extension that you believe would add value to the core platform, we would love to review it. To ensure the main repository remains highly stable and securely managed, direct commits to the `main` branch are restricted.

If you wish to give back your changes to the project, please follow this process:

* **Email the Repository Owner:** Send a brief summary of your modifications and a link to your code branch directly to **admin@tsicoop.org**.

Every contribution is manually evaluated for architectural alignment, readability, and long-term maintenance impact before integration. Thank you for respecting this workflow and helping us maintain a clean, resilient core!

