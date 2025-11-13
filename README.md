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

The HID Global AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.

## Support
The HID Global AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

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

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the HID Global AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

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


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).