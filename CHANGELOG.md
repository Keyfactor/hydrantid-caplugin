# v1.1.0
* Added automated DNS-01 style domain control validation: when the AnyCA Gateway supplies an IDomainValidatorFactory and a DNS provider plugin is configured for the domain's zone, the plugin now stages HydrantId's validation TXT record, polls until the domain is VALIDATED, removes the record, and issues the certificate within a single enrollment call
* Changed domain control validation to target the registrable base domain rather than the CSR's fully-qualified name; HydrantId links the vetted organization to the base domain only, and validating a subdomain produced a record with a null organizationIds that POST /csr rejected with "No valid domains associated with organization". A base-domain validation additionally covers every subdomain until domainValidUntil
* Changed DNS provider plugin resolution to try the base domain and then the requested name, because the Gateway matches a domain validation configuration on exact domain equality; a configuration registered against either name now resolves, and the record is still written on the base domain
* Changed the DNS provider validation type tried first from "dns-01" to "DNS", which is what deployed DNS plugins report to AnyCA Gateway 26.2; the other spelling is still attempted as a fallback
* Added a fallback to the fully-qualified name when HydrantId will not accept the derived base domain, so an unrecognized multi-label public suffix costs one rejected API call rather than a failed enrollment
* Added per-domain fallback to external validation when automation is unavailable (no factory, no DNS plugin for the zone, staging failure, no validation code, or validation timeout), preserving the previous manual publish-and-resubmit behaviour
* Added DnsPropagationDelaySeconds, DomainValidationTimeoutSeconds and DomainValidationPollIntervalSeconds CA connection settings
* Added domain control validation for policies that declare a validator, including reuse of an already-validated parent domain for subdomains and regeneration of expired validation codes
* Added HydrantIdAccountId and the HydrantIdOrg*/contact CA connection settings required by validators (e.g. IdenTrust) that declare a non-empty requiredPayload
* Made the policy domain validator optional - policies with no validator configured skip domain control validation entirely
* Fixed soft-deleted HydrantId domain records (deletedAt) being matched during domain control validation; re-checking a deleted record returned HTTP 500 and failed the enrollment instead of starting a fresh validation
* Fixed the extension registration key in manifest.json, which was GCPCASCAPlugin copy-paste residue rather than HydrantIdCAPlugin
* Synchronized integration-manifest.json CA connection settings with the plugin annotations; HydrantIdAccountId and the organization fields were previously missing from the generated documentation

# v1.0.3
* Added support for revocation reason 0 (Unspecified) now that HydrantId accepts it 
* Fixed sensitive credentials (HydrantIdAuthId, HydrantIdAuthKey) being written to trace logs in plain text; raw config JSON is now masked before logging

# v1.0.2
* Fixed revocation status handling - failed revocations no longer incorrectly set certificate status to FAILED; certificate retains its current active status
* Added FlowLogger utility for structured flow diagrams across all public plugin methods
* Added guard clauses and input validation (null checks, UUID length validation before Substring)
* Added null response guards after all API calls
* Added null-safe structured logging throughout plugin, RequestManager, and HydrantIdClient
* Added AggregateException flattening in catch blocks for better error reporting
* Added per-certificate error isolation in Synchronize to prevent one bad cert from aborting sync
* Added BlockingCollection.IsAddingCompleted guard before CompleteAdding()
* Improved error handling in HydrantIdClient - non-success HTTP responses now throw with status details
* Added .NET 10 target framework support

# v1.0.1
* SaaS Containerization Fixes, added enabled flag cleaned up some log messages

# v1.0.0
* Initial Release.  Sync, Enroll, and Revocation. 
