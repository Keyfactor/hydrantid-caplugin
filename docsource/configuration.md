## Overview

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


## Gateway Registration

TODO Gateway Registration is a required section

## Certificate Template Creation Step

TODO Certificate Template Creation Step is a required section

## Custom Enrollment Parameter Creation Step

TODO Custom Enrollment Parameter Creation Step is an optional section. If this section doesn't seem necessary on initial glance, please delete it. Refer to the docs on [Confluence](https://keyfactor.atlassian.net/wiki/x/SAAyHg) for more info

## Mechanics

TODO Mechanics is an optional section. If this section doesn't seem necessary on initial glance, please delete it. Refer to the docs on [Confluence](https://keyfactor.atlassian.net/wiki/x/SAAyHg) for more info

