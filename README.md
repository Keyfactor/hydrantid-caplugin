<h1 align="center" style="border-bottom: none">
    HID Global AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/hydrantid-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/hydrantid-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/hydrantid-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/hydrantid-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>

The HID Global HydrantId AnyCA Gateway REST plugin extends the capabilities of HydrantId Certificate Authority Service to Keyfactor Command via the Keyfactor AnyCA Gateway. This plugin leverages the HydrantId REST API with Hawk authentication to provide comprehensive certificate lifecycle management. The plugin represents a fully featured AnyCA Plugin with the following capabilities:

* **CA Sync**:
    * Download all certificates issued by the HydrantId CA
    * Support for incremental and full synchronization
    * Automatic extraction of end-entity certificates from PEM chains
* **Certificate Enrollment**:
    * Support certificate enrollment with new key pairs
    * Dynamic policy (profile) discovery from the CA
    * Intelligent renewal vs. re-issue logic based on certificate expiration
    * Support for PKCS#10 CSR format
    * Configurable certificate validity periods
* **Certificate Revocation**:
    * Request revocation of previously issued certificates
    * Support for standard CRL revocation reasons

## Compatibility

The HID Global AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 26.2 and later.

## Support
The HID Global AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com.

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

### HydrantId System Prerequisites

Before configuring the AnyCA Gateway plugin, ensure the following prerequisites are met:

1. **HydrantId Account**:
   - Active HydrantId account with API access enabled
   - Access to the HydrantId management portal
   - HydrantId Certificate Authority Service configured and operational

2. **API Credentials**:
   - HydrantId API Authentication ID (AuthId)
   - HydrantId API Authentication Key (AuthKey)
   - These credentials must have permissions for:
     - Certificate enrollment (CSR submission)
     - Certificate retrieval
     - Certificate revocation
     - Policy/profile listing

3. **Network Connectivity**:
   - Gateway server must have HTTPS access to the HydrantId API endpoint
   - Default endpoint format: `https://<environment>.hydrantid.com`
   - Example: `https://acm-stage.hydrantid.com` or `https://acm.hydrantid.com`
   - TLS 1.2 or higher must be supported

### Obtaining Required Configuration Information

#### 1. HydrantId Base URL

The HydrantId Base URL is the root endpoint for the HydrantId API.

**Common HydrantId environments:**
- Production: `https://acm.hydrantid.com`
- Staging: `https://acm-stage.hydrantid.com`
- Custom instances may have different URLs

**To obtain your Base URL:**
1. Contact your HydrantId account representative
2. Check your HydrantId account documentation
3. Verify the URL is accessible from the Gateway server

#### 2. API Authentication Credentials

The Gateway authenticates to HydrantId using Hawk authentication protocol with an AuthId and AuthKey pair.

**Steps to obtain API credentials:**

1. **Access HydrantId Portal**:
   - Log in to your HydrantId management portal
   - Navigate to API or Integration settings

2. **Generate API Credentials**:
   - Request API credentials from your HydrantId administrator
   - You will receive:
     - **AuthId**: A unique identifier for your API client
     - **AuthKey**: A secret key used for HMAC-based authentication
   - Store these credentials securely

3. **Verify Permissions**:
   - Ensure the API credentials have the following permissions:
     - Certificate enrollment (POST /api/v2/csr)
     - Certificate renewal (POST /api/v2/certificates/{id}/renew)
     - Certificate retrieval (GET /api/v2/certificates)
     - Certificate revocation (PATCH /api/v2/certificates/{id})
     - Policy listing (GET /api/v2/policies)

#### 3. Certificate Policies

Certificate policies define the types of certificates that can be issued. The plugin automatically discovers available policies from the HydrantId system.

**Policy discovery:**
- Policies are automatically retrieved when the CA is configured
- Policies appear in Keyfactor Command as "Product IDs" after CA registration
- Each policy represents a certificate template configured in HydrantId

**To view available policies:**
1. Policies are retrieved automatically using the GET /api/v2/policies endpoint
2. Ensure the API credentials have permissions to list policies
3. Policies will be displayed during CA configuration in the Gateway

#### 4. Certificate Validity Configuration

For each certificate template, you can configure:

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| **ValidityPeriod** | Time unit for certificate lifetime | `Days`, `Months`, `Years` |
| **ValidityUnits** | Numeric value for the validity period | `365` (for days), `12` (for months), `2` (for years) |
| **RenewalDays** | Days before expiration to trigger renewal vs. re-issue | `30`, `60`, `90` |

**Renewal vs. Re-issue Logic:**
- If a certificate is within the RenewalDays window before expiration, the plugin performs a **renewal**
- If a certificate is outside the RenewalDays window, the plugin performs a **re-issue** (new enrollment)

### Supported Revocation Reasons

The plugin supports the following standard CRL revocation reasons:

| Reason Code | Reason Name | HydrantId API Value |
|-------------|-------------|---------------------|
| 0 | Unspecified | `Unspecified` |
| 1 | Key Compromise | `KeyCompromise` |
| 2 | CA Compromise | `CaCompromise` |
| 3 | Affiliation Changed | `AffiliationChanged` |
| 4 | Superseded | `Superseded` |
| 5 | Cessation of Operation | `CessationOfOperation` |

**Note**: Verify with your HydrantId administrator which revocation reasons are supported in your environment.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [HID Global AnyCA Gateway REST plugin](https://github.com/Keyfactor/hydrantid-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net10.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net10.0\Extensions
    ```

    > The directory containing the HID Global AnyCA Gateway REST plugin DLLs (`net10.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the HID Global plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        ### CA Connection Configuration
        
        When registering the HydrantId CA in the AnyCA Gateway, you'll need to provide the following configuration parameters:
        
        | Parameter | Description | Required | Example |
        |-----------|-------------|----------|---------|
        | **HydrantIdBaseUrl** | Full URL to the HydrantId API endpoint | Yes | `https://acm.hydrantid.com` or `https://acm-stage.hydrantid.com` |
        | **HydrantIdAuthId** | API Authentication ID provided by HydrantId | Yes | `your-auth-id` |
        | **HydrantIdAuthKey** | API Authentication Key provided by HydrantId | Yes | `your-secret-auth-key` |
        | **HydrantIdAccountId** | Account id required by some HydrantId tenants when creating a domain validation request (`POST /domains/`) as part of enrollment against a policy with a validator configured. Leave blank if domain validation already succeeds without it — if left blank and it turns out to be required, domain validation creation fails with `{"message":"Error: unauthorized","status":"Failure"}`. Obtain from the HydrantId portal's account settings, HydrantId support, or the `account.id` field on any existing certificate returned by the API. | No | `aba34551-51e9-4cb3-a5b8-895d64d45344` |
        | **HydrantIdOrgName** | Organization name required by some HydrantId validators (e.g. IdenTrust) on domain validation requests. Leave blank if your validator doesn't need it — check `GET /api/v2/domains/validators`'s `requiredPayload` for the validator in use; a non-empty `requiredPayload` means these fields are needed. If required and left blank, domain validation creation fails with `{"message":"The domain request is missing the organization name","status":"Failure"}`. | No | `Acme Corp` |
        | **HydrantIdOrgPrimaryContactFullName** | Organization primary contact full name, paired with HydrantIdOrgName. | No | `Jane Doe` |
        | **HydrantIdOrgStreetAddress** | Organization street address, paired with HydrantIdOrgName. | No | `123 Main St` |
        | **HydrantIdOrgCityProvPostalCodeCountry** | Organization city/province/postal code/country, paired with HydrantIdOrgName. | No | `Anytown, OH 44131, US` |
        | **HydrantIdEmailAddress** | Organization contact email address, paired with HydrantIdOrgName. | No | `jane@acme.com` |
        | **HydrantIdPhoneNumber** | Organization contact phone number, paired with HydrantIdOrgName. | No | `+1-555-555-0100` |
        | **DnsPropagationDelaySeconds** | Seconds to wait after a DNS provider plugin writes the validation TXT record before asking HydrantId to check it. Only used on the automated path; ignored when validation is done by hand. Set to `0` to start polling immediately. Defaults to `30` when blank. | No | `30` |
        | **DomainValidationTimeoutSeconds** | Maximum seconds to hold the enrollment open while polling HydrantId for domain validation after a DNS provider plugin has staged the record. On timeout the enrollment falls back to external validation rather than failing. Defaults to `300` when blank. | No | `300` |
        | **DomainValidationPollIntervalSeconds** | Seconds between HydrantId domain validation status checks while waiting for a staged record. Defaults to `10` when blank. | No | `10` |
        
        ### Automated Domain Validation (DNS Provider Plugins)
        
        When a policy has a `validator` configured, HydrantId requires domain control validation (DCV)
        before it will issue. The plugin can complete DCV either automatically or by hand, and picks
        per domain without any configuration switch.
        
        **Automated path.** If the AnyCA Gateway supplies an `IDomainValidatorFactory` and a DNS provider
        plugin is deployed and configured for the zone that owns the domain, a single enrollment does all
        of the following without operator involvement:
        
        1. Creates (or re-checks) the HydrantId domain validation record to obtain its TXT code.
        2. Asks the resolved DNS provider plugin to write that record. The record name is **the domain
           itself** — not an `_acme-challenge` subdomain, as in ACME — and the value is HydrantId's whole
           code string, e.g. `identrust_validate=1kiQrHax...`, matching the `codeInstructions` HydrantId
           returns.
        3. Waits `DnsPropagationDelaySeconds`, then polls HydrantId every
           `DomainValidationPollIntervalSeconds` until the domain reports `VALIDATED`, up to
           `DomainValidationTimeoutSeconds`.
        4. Deletes the TXT record it wrote, whether or not validation succeeded. HydrantId's DCV remains
           valid until `domainValidUntil` (roughly six months for IdenTrust), so no record needs to stay
           in the zone.
        5. Submits the CSR and waits for the certificate, returning the issued certificate from the same
           enrollment call.
        
        A cleanup failure is logged but never fails an enrollment that otherwise succeeded — a leftover
        TXT record cannot block issuance.
        
        **Manual fallback.** Any domain that cannot be automated falls back to the previous behaviour:
        the enrollment returns an external-validation status carrying the TXT record to publish, and the
        operator resubmits once it is live. This happens when:
        
        - the Gateway supplies no `IDomainValidatorFactory`;
        - no DNS provider plugin is configured for that domain's zone;
        - the DNS provider plugin fails or throws while writing the record;
        - HydrantId returns no validation code; or
        - validation is still pending when `DomainValidationTimeoutSeconds` runs out.
        
        Because the fallback is per domain, a certificate with some domains in an automated zone and
        others outside it still makes progress on the automated ones.
        
        Domains that are already `VALIDATED`, or covered by an already-validated parent domain, skip DCV
        entirely and never touch a DNS provider plugin.
        
        > **Note on validation type.** DNS provider plugins are resolved with a validation type of
        > `dns-01` first, then `DNS`. The reference ACME CA plugin resolves with `dns-01` at runtime while
        > that project's DNS plugin documentation describes `GetValidationType()` as returning `DNS`, so
        > both spellings are attempted rather than silently missing a plugin that is deployed.
        
        ### Gateway Registration Notes
        
        - Each defined Certificate Authority in the AnyCA Gateway REST can support one HydrantId API endpoint
        - If you have multiple HydrantId environments or accounts, you must define multiple Certificate Authorities in the AnyCA Gateway
        - Each CA configuration will manifest in Command as a separate CA entry
        - The plugin uses Hawk authentication protocol for all API communications
        - Authentication uses HMAC-SHA256 for secure API access
        - The plugin automatically handles:
        - Policy/template discovery
        - Certificate status mapping
        - End-entity certificate extraction from PEM chains
        - Enrollment completion polling (30-second timeout)
        
        ### Security Considerations
        
        1. **Credential Storage**: Store API credentials securely and restrict access to the Gateway configuration
        2. **Secret Management**: Consider using a secrets management system for AuthKey storage
        3. **Network Security**: Ensure TLS/SSL is properly configured for all API communications
        4. **Least Privilege**: Request API credentials with minimal required permissions
        5. **Audit Logging**: Enable comprehensive logging in both the Gateway and HydrantId for security monitoring
        6. **Credential Rotation**: Regularly rotate API credentials according to your security policy
        
        **CA Connection**
        
        Populate using the configuration fields collected in the [requirements](#requirements) section.
        
        * **HydrantIdBaseUrl** - The base URL for the HydrantId API endpoint. For example, `https://acm.hydrantid.com` or `https://acm-stage.hydrantid.com`.
        * **HydrantIdAuthId** - The API Authentication ID provided by HydrantId for API access.
        * **HydrantIdAuthKey** - The API Authentication Key (secret) provided by HydrantId for API access.
        * **HydrantIdAccountId** - Optional. Required by some HydrantId tenants for domain validation to succeed; see the table above.
        * **HydrantIdOrgName**, **HydrantIdOrgPrimaryContactFullName**, **HydrantIdOrgStreetAddress**, **HydrantIdOrgCityProvPostalCodeCountry**, **HydrantIdEmailAddress**, **HydrantIdPhoneNumber** - Optional. Required by some domain validators (e.g. IdenTrust); see the table above.
        * **DnsPropagationDelaySeconds**, **DomainValidationTimeoutSeconds**, **DomainValidationPollIntervalSeconds** - Optional timing controls for automated domain validation; see [Automated Domain Validation](#automated-domain-validation-dns-provider-plugins). Leave blank to use the defaults.
        
        2. **Certificate Template Configuration**
        
         After adding the CA to the Gateway, configure each certificate template:
        
         1. Navigate to the Templates/Products section for the newly added CA
         2. For each template (policy) discovered from HydrantId, configure:
            - **ValidityPeriod**: Select `Days`, `Months`, or `Years`
            - **ValidityUnits**: Enter the numeric value (e.g., `365` for one year in days)
            - **RenewalDays**: Enter the renewal window in days (e.g., `30`)
        
         Example configurations:
         - **1-Year Certificate (Days)**: ValidityPeriod=`Days`, ValidityUnits=`365`, RenewalDays=`30`
         - **2-Year Certificate (Years)**: ValidityPeriod=`Years`, ValidityUnits=`2`, RenewalDays=`60`
         - **6-Month Certificate (Months)**: ValidityPeriod=`Months`, ValidityUnits=`6`, RenewalDays=`30`
        
        3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **HydrantIdBaseUrl** - The Base URL For the HydrantId Endpoint similar to https://acm-stage.hydrantid.com.  Get this from HydrantId.
        * **HydrantIdAuthId** - The AuthId Obtained from HydrantId.
        * **HydrantIdAuthKey** - The AuthKey Obtained from HydrantId.
        * **HydrantIdAccountId** - Optional. Some HydrantId tenants require the account id to be included when creating a domain validation request (POST /domains/); leave blank if domain validation already works without it. Obtain from the HydrantId portal's account settings, HydrantId support, or the 'account.id' field on any existing certificate returned by the API.
        * **HydrantIdOrgName** - Optional. Organization name required by some HydrantId validators (e.g. IdenTrust) on domain validation requests. Leave blank if not required by your validator -- omitted from the request entirely when blank.
        * **HydrantIdOrgPrimaryContactFullName** - Optional. Organization primary contact full name required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.
        * **HydrantIdOrgStreetAddress** - Optional. Organization street address required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.
        * **HydrantIdOrgCityProvPostalCodeCountry** - Optional. Organization city/province/postal code/country required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.
        * **HydrantIdEmailAddress** - Optional. Organization contact email address required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.
        * **HydrantIdPhoneNumber** - Optional. Organization contact phone number required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.
        * **DnsPropagationDelaySeconds** - Seconds to wait after a DNS provider plugin writes the validation TXT record before asking HydrantId to check it, allowing the record to propagate to the authoritative nameservers. Only used when a DNS provider plugin is handling the record; ignored on the manual validation path. Set to 0 to skip the delay and start polling immediately.
        * **DomainValidationTimeoutSeconds** - Maximum seconds to hold the enrollment open while polling HydrantId for domain validation to complete after a DNS provider plugin has staged the TXT record. On timeout the enrollment falls back to external validation (manual DNS publish and resubmit) rather than failing.
        * **DomainValidationPollIntervalSeconds** - Seconds between HydrantId domain validation status checks while waiting for a staged DNS record to be validated.
        * **Enabled** - Flag to Enable or Disable the CA connector.

2. ### Template (Product) Configuration

  Each certificate template (policy) discovered from HydrantId requires configuration for enrollment:

  | Parameter | Description | Required | Example |
  |-----------|-------------|----------|---------|
  | **ValidityPeriod** | Time unit for certificate lifetime | Yes | `Days`, `Months`, or `Years` |
  | **ValidityUnits** | Numeric value for the validity period | Yes | `365` (for 1 year in days), `12` (for 1 year in months), `2` (for 2 years) |
  | **RenewalDays** | Days before expiration to trigger renewal | Yes | `30` (renew within 30 days of expiration) |

  **Important Notes:**
  - Template names (Product IDs) are automatically discovered from HydrantId using the GET /api/v2/policies endpoint
  - The ValidityPeriod and ValidityUnits combine to determine the certificate lifetime
  - RenewalDays determines the behavior for certificate renewal:
    - Within window: Performs a renewal operation (maintains certificate lineage)
    - Outside window: Performs a re-issue operation (new certificate enrollment)

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:

    * **ValidityPeriod** - The desired lifetime time period could be Days, Months or Years.
    * **ValidityUnits** - The desired lifetime time value some number indicating days, months or years.
    * **RenewalDays** - The window that determines whether it is a renewal vs a re-issue.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [HID Global HydrantId AnyCA Gateway REST plugin](https://github.com/Keyfactor/hydrantid-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:

    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the HID Global HydrantId AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the HID Global HydrantId plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Functional Test Plan

The test cases below are written as manual steps to run through the Keyfactor Command UI against a configured HydrantId CA, so a tester can execute them and record Pass/Fail results. They exercise the same code paths the plugin implements: connectivity/config validation, enrollment (with and without domain control validation), renewal vs. re-issue selection, revocation, and CA synchronization.

> **Note on DCV and policy type**: whether an enrollment requires domain control validation (DCV) is driven entirely by whether the matched HydrantId policy has a `validator` configured (e.g. IdenTrust, DigiCert, PrivateCA) — not by the policy's CA type. EJBCA policies typically have no validator configured (since they aren't publicly-trusted CAs subject to CA/Browser Forum DCV requirements), which is why they issue directly with no DNS step. If a validator is ever configured on a non-public-CA policy, the plugin will still attempt DCV for it.

### A. Connectivity / Configuration

| # | Test Case | Steps in Command | Expected Result |
|---|---|---|---|
| A1 | Valid connection test | CAs > add/edit HydrantId CA > enter valid `HydrantIdBaseUrl`, `HydrantIdAuthId`, `HydrantIdAuthKey` > Save/Test Connection | Connection succeeds (calls `Ping` → `GET /policies`) |
| A2 | Invalid AuthKey | Same as A1 but with a wrong `HydrantIdAuthKey` | Test Connection fails with a clear auth error, not a silent success |
| A3 | Missing required field | Leave `HydrantIdBaseUrl` blank, attempt Save | Save is rejected with a validation message naming the missing field(s) |
| A4 | CA disabled | Set `Enabled = false` on the CA config, Save | Save succeeds; connectivity/config validation is skipped (no error), consistent with a deliberately paused CA |
| A5 | Product/policy list populates | Open the Certificate Template mapping / "Available Templates" picker for this CA | List of HydrantId policies (EJBCA + any IdenTrust/DigiCert/PrivateCA policies) appears by name |

### B. Enrollment — policy has no validator configured (all current EJBCA policies)

Confirm via the policy list that `details.validator` is unset for the policy under test — this is what actually determines the no-DCV path, not the EJBCA type itself.

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| B1 | New enrollment, CSR | Enrollment > CSR Enrollment, select a Template mapped to a no-validator policy, submit a valid CSR | Certificate issues immediately (no DCV step); status shows Issued/Generated |
| B2 | New enrollment, PFX | Enrollment > PFX Enrollment, same policy | Certificate + private key returned; status Issued |
| B3 | Enrollment with SANs | Submit CSR with multiple DNS SANs against the same policy | All SANs present on issued cert |
| B4 | Enrollment against unmapped Product ID | Submit against a Template whose Product ID doesn't match any HydrantId policy name | Enrollment fails with "no policy found matching ProductID" — not a crash/500 |
| B5 | Enrollment with missing/invalid ValidityPeriod annotation | Submit against an unsaved/never-configured Template (annotation defaults only) | Falls back to annotation default (Years/1) rather than failing |

### C. Enrollment — policy has a validator configured (IdenTrust / DigiCert / PrivateCA)

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| C1 | First-time enrollment, domain never validated | CSR Enrollment against a policy with `validator` set, for a domain never validated before | Enrollment returns pending/"external validation" with DNS TXT record instructions in the status message — no cert issued yet |
| C2 | Publish TXT, resubmit | Publish the TXT record from C1 in real DNS, resubmit the same enrollment | Domain validates, certificate issues |
| C3 | Re-enroll same domain (already validated) | Submit a second CSR for the same already-validated domain | No new DCV required — issues directly (domain trust is reused while still valid) |
| C4 | Enroll for a subdomain of an already-validated domain | Use a subdomain (e.g. `www.example.com`) of a domain already `Validated` in the Domains list, same validator | Issues directly with no new domain validation record created — the plugin treats it as covered by the validated parent |
| C4b | Enroll for a subdomain of a still-pending (not yet validated) parent | Same as C4, but the parent domain's own validation is still `Pending` | Creates its own separate validation record for the subdomain (parent coverage only applies once the parent is actually `Validated`) |
| C5 | Never publish the TXT record | Same as C1 but don't publish the record, resubmit later | Stays pending; status message still shows the same/valid instructions, doesn't error |
| C6 | Domain validation expires mid-lifecycle (IdenTrust ~200 days) | Not practically testable end-to-end in a short QA pass — mark "not testable this cycle" unless a naturally-expired domain is available in the environment | Enrollment restarts DCV rather than getting stuck on a dead validation record |
| C7 | Automated DCV, happy path | Deploy and configure a DNS provider plugin for a zone you control, then enroll for a never-validated domain in that zone | Certificate issues from the single enrollment with no operator step; the TXT record appears in the zone during validation and is gone afterwards |
| C8 | Automated DCV, cleanup verified | After C7, list TXT records for the domain at the DNS provider | No `*_validate=` record remains; HydrantId still shows the domain `VALIDATED` with a future `domainValidUntil` |
| C9 | Automated DCV times out | Set `DomainValidationTimeoutSeconds` to a low value (e.g. `15`) and enroll for a domain in a zone whose validation is slow, or point the plugin at a zone HydrantId cannot resolve | Enrollment returns external-validation with TXT instructions rather than failing; the staged record is cleaned up |
| C10 | DNS provider plugin misconfigured | Configure the DNS provider plugin with a bad credential, then enroll | Enrollment falls back to external validation with TXT instructions; Gateway log records the plugin's staging error; enrollment does not fail outright |
| C11 | Mixed zones on one certificate | Enroll for a CN in an automated zone plus a SAN in a zone with no DNS plugin | The automated domain validates; the un-automated one is reported in the external-validation message for manual publication |
| C12 | No DNS plugin deployed at all | With no DNS provider plugin configured, repeat C1/C2 | Behaves exactly as C1/C2 did before automation existed |

### D. Renewal

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| D1 | Renew within RenewalDays window | Certificate Search > select a cert issued in B1/B3, close to expiry (or lower the Template's `RenewalDays` for testing) > Renew | Goes through the renewal path (reuses/updates same HydrantId cert record); new cert issued |
| D2 | Renew outside RenewalDays window | Renew a cert with plenty of validity left | Goes through the reissue path instead (new CSR against matched policy) |
| D3 | Renew with DCV policy, domain still valid | Renew a cert from the C-series tests | No DCV re-prompt, issues directly |
| D4 | Renew with `reuseCsr` scenario | If Command supports "renew without new CSR" for this Template | New cert issued reusing prior key/CSR per the policy's `renewCanReuseCSR` setting |

### E. Reissue

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| E1 | Reissue outside renewal window | Reissue a long-lived cert | New CSR submitted against the matched policy; new cert issued |
| E2 | Reissue where policy no longer exists/renamed | Reissue a cert whose original Template's policy was removed/renamed in HydrantId | Fails cleanly with "no policy found matching ProductID", not a crash |
| E3 | Reissue with pending DCV | Reissue for a domain whose validation just expired/was deleted in HydrantId | Returns external-validation-pending, same as C1 |

### F. Revocation

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| F1 | Revoke, unspecified reason | Certificate Search > select an issued cert > Revoke > reason "Unspecified" | Cert shows Revoked in both Command and the HydrantId portal |
| F2 | Revoke, key compromise | Revoke another cert with reason "Key Compromise" | Revoked; reason recorded correctly on the HydrantId side |
| F3 | Revoke already-revoked cert | Attempt to revoke F1's cert again | Fails/no-ops gracefully, no crash |
| F4 | Revoke cert not found in HydrantId | Revoke using a bad/stale CARequestID (if reproducible) | Clear error, not an unhandled exception |

### G. Synchronization / Inventory

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| G1 | Full sync | Orchestrators/Scheduled Jobs > run a full sync for this CA | All previously issued certs (B, C, D, E series) appear in Command's certificate inventory with correct status |
| G2 | Incremental sync | Issue/revoke one more cert, run an incremental sync | Only the delta is reflected; sync completes without re-processing everything |
| G3 | Sync reflects revocation | After F1's revoke, run sync | That cert's status updates to Revoked in Command if not already updated at revoke time |
| G4 | Sync with a large result set | If the HydrantId account has more than 100 certs | Paging completes without missing/duplicating certs |
| G5 | Sync cancellation | Start a sync and cancel it mid-run (if Command exposes this) | Job stops cleanly, no hung state |

### H. Negative / edge cases

| # | Test Case | Steps | Expected Result |
|---|---|---|---|
| H1 | Submit malformed CSR | CSR Enrollment with a truncated/corrupt CSR | Clear validation failure, not a 500 |
| H2 | Enroll while CA is Disabled | Set CA `Enabled=false`, attempt enrollment | Fails/blocked consistent with disabled state |
| H3 | Network/HydrantId outage simulated | Point `HydrantIdBaseUrl` at an unreachable host, attempt any operation | Fails with a clear connectivity error, not a hang |

**Prerequisites for the C-series tests**: a domain you actually control DNS for, so you can publish the real TXT records HydrantId returns. Tests C7–C11 additionally need a DNS provider plugin deployed to the Gateway and configured for that domain's zone.

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).
