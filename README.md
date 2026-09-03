# TSI DPDP Consent Management System

An open-source consent management system compliant with India's DPDP Act, 2023.

This system serves two categories of adopters:

- **Data Fiduciaries**, who can deploy the CMS directly (Single Mode) to manage consent for their own Data Principals, without depending on a third party.
- **Consent Managers**, who can deploy the CMS (Aggregator Mode) to manage consent on behalf of one or more Data Fiduciaries as a managed service.

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
    This gates the Super-Admin creation endpoint. If it's left unset, that endpoint stays disabled rather than falling back to an insecure default - so this step isn't optional.

3.  **Start the TSI DPDP CMS service**
    ```bash
    sudo docker compose up -d
    ```

### Binary

Check out [v0.5.1 release](https://github.com/tsi-coop/tsi-dpdp-cms/releases/tag/v0.5.1)

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
| Developers consuming notification and purge events after the fact | [Webhook Integration Guide](docs/guides/webhook-integration-guide.md)<br><br>[Client Polling Integration Guide](docs/guides/polling-integration-guide.md) | Push delivery (HMAC-SHA256-signed webhooks for Notification/Purge/OTP, v0.4.8+) and its reliable pull-based counterpart - the reconciliation path for anything a missed webhook delivery would drop. |
| Developers building from source | [Local Development Guide](docs/guides/local-development-guide.md) | Prerequisites (JDK, Maven, Docker, Jetty) and step-by-step build/run instructions, for both Docker and non-Docker setups. |
| DevOps / system administrators going to production | [Production Deployment Guide](docs/guides/production-deployment-guide.md) | Secrets management, running as a non-root user, disk encryption, data-tier isolation, and offsite backups, for both Docker and Binary installs. |

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

[Managing the Data Lifecycle](https://techadvisory.substack.com/p/managing-the-data-lifecycle-a-first)

