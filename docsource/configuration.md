## Overview

The HID Global HID AnyCA Gateway REST plugin extends the capabilities of HID Certificate Authority Service to Keyfactor Command via the Keyfactor AnyCA Gateway. This plugin leverages the HID REST API with Hawk authentication to provide comprehensive certificate lifecycle management. The plugin represents a fully featured AnyCA Plugin with the following capabilities:

* **CA Sync**:
    * Download all certificates issued by the HID CA
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

### HID System Prerequisites

Before configuring the AnyCA Gateway plugin, ensure the following prerequisites are met:

1. **HID Account**:
   - Active HID account with API access enabled
   - Access to the HID management portal
   - HID Certificate Authority Service configured and operational

2. **API Credentials**:
   - HID API Authentication ID (AuthId)
   - HID API Authentication Key (AuthKey)
   - These credentials must have permissions for:
     - Certificate enrollment (CSR submission)
     - Certificate retrieval
     - Certificate revocation
     - Policy/profile listing

3. **Network Connectivity**:
   - Gateway server must have HTTPS access to the HID API endpoint
   - Default endpoint format: `https://<environment>.HID.com`
   - Example: `https://acm-stage.HID.com` or `https://acm.HID.com`
   - TLS 1.2 or higher must be supported

### Obtaining Required Configuration Information

#### 1. HID Base URL

The HID Base URL is the root endpoint for the HID API.

**Common HID environments:**
- Production: `https://acm.HID.com`
- Staging: `https://acm-stage.HID.com`
- Custom instances may have different URLs

**To obtain your Base URL:**
1. Contact your HID account representative
2. Check your HID account documentation
3. Verify the URL is accessible from the Gateway server

#### 2. API Authentication Credentials

The Gateway authenticates to HID using Hawk authentication protocol with an AuthId and AuthKey pair.

**Steps to obtain API credentials:**

1. **Access HID Portal**:
   - Log in to your HID management portal
   - Navigate to API or Integration settings

2. **Generate API Credentials**:
   - Request API credentials from your HID administrator
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

Certificate policies define the types of certificates that can be issued. The plugin automatically discovers available policies from the HID system.

**Policy discovery:**
- Policies are automatically retrieved when the CA is configured
- Policies appear in Keyfactor Command as "Product IDs" after CA registration
- Each policy represents a certificate template configured in HID

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

| Reason Code | Reason Name | HID API Value |
|-------------|-------------|---------------------|
| 0 | Unspecified | `Unspecified` |
| 1 | Key Compromise | `KeyCompromise` |
| 2 | CA Compromise | `CaCompromise` |
| 3 | Affiliation Changed | `AffiliationChanged` |
| 4 | Superseded | `Superseded` |
| 5 | Cessation of Operation | `CessationOfOperation` |

**Note**: Verify with your HID administrator which revocation reasons are supported in your environment.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [HID Global HID AnyCA Gateway REST plugin](https://github.com/Keyfactor/HID-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:

    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the HID Global HID AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the HID Global HID plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Gateway Registration

### CA Connection Configuration

  When registering the HID CA in the AnyCA Gateway, you'll need to provide the following configuration parameters:

  | Parameter | Description | Required | Example |
  |-----------|-------------|----------|---------|
  | **HIDBaseUrl** | Full URL to the HID API endpoint | Yes | `https://acm.HID.com` or `https://acm-stage.HID.com` |
  | **HIDAuthId** | API Authentication ID provided by HID | Yes | `your-auth-id` |
  | **HIDAuthKey** | API Authentication Key provided by HID | Yes | `your-secret-auth-key` |

### Gateway Registration Notes

  - Each defined Certificate Authority in the AnyCA Gateway REST can support one HID API endpoint
  - If you have multiple HID environments or accounts, you must define multiple Certificate Authorities in the AnyCA Gateway
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
5. **Audit Logging**: Enable comprehensive logging in both the Gateway and HID for security monitoring
6. **Credential Rotation**: Regularly rotate API credentials according to your security policy

**CA Connection**

Populate using the configuration fields collected in the [requirements](#requirements) section.

* **HIDBaseUrl** - The base URL for the HID API endpoint. For example, `https://acm.HID.com` or `https://acm-stage.HID.com`.
* **HIDAuthId** - The API Authentication ID provided by HID for API access.
* **HIDAuthKey** - The API Authentication Key (secret) provided by HID for API access.

2. **Certificate Template Configuration**

 After adding the CA to the Gateway, configure each certificate template:

 1. Navigate to the Templates/Products section for the newly added CA
 2. For each template (policy) discovered from HID, configure:
    - **ValidityPeriod**: Select `Days`, `Months`, or `Years`
    - **ValidityUnits**: Enter the numeric value (e.g., `365` for one year in days)
    - **RenewalDays**: Enter the renewal window in days (e.g., `30`)

 Example configurations:
 - **1-Year Certificate (Days)**: ValidityPeriod=`Days`, ValidityUnits=`365`, RenewalDays=`30`
 - **2-Year Certificate (Years)**: ValidityPeriod=`Years`, ValidityUnits=`2`, RenewalDays=`60`
 - **6-Month Certificate (Months)**: ValidityPeriod=`Months`, ValidityUnits=`6`, RenewalDays=`30`

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

## Certificate Template Creation Step

### Template (Product) Configuration

  Each certificate template (policy) discovered from HID requires configuration for enrollment:

  | Parameter | Description | Required | Example |
  |-----------|-------------|----------|---------|
  | **ValidityPeriod** | Time unit for certificate lifetime | Yes | `Days`, `Months`, or `Years` |
  | **ValidityUnits** | Numeric value for the validity period | Yes | `365` (for 1 year in days), `12` (for 1 year in months), `2` (for 2 years) |
  | **RenewalDays** | Days before expiration to trigger renewal | Yes | `30` (renew within 30 days of expiration) |

  **Important Notes:**
  - Template names (Product IDs) are automatically discovered from HID using the GET /api/v2/policies endpoint
  - The ValidityPeriod and ValidityUnits combine to determine the certificate lifetime
  - RenewalDays determines the behavior for certificate renewal:
    - Within window: Performs a renewal operation (maintains certificate lineage)
    - Outside window: Performs a re-issue operation (new certificate enrollment)

