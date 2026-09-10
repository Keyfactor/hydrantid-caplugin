# v3.0.0
* Added a CertificateAuthorityId CA connection setting that scopes a logical CA to one certificate authority within the HydrantId tenant, matched against the certificateAuthorityId each policy reports on GET /api/v2/policies. HydrantId's policy and certificate endpoints are account-scoped rather than CA-scoped, so a tenant issuing from more than one CA previously had every logical CA defined against it offer every policy, synchronize every certificate, and be able to revoke any of them -- cross-contaminating each CA's inventory in Command. Blank preserves the previous unscoped behaviour for single-CA tenants
* Changed Synchronize to skip certificates whose policy belongs to another certificate authority, matching on the policy reference the certificate list already returns so a foreign certificate costs no detail fetch, and added filtered and error counts to the synchronization summary alongside the processed and skipped counts
* Changed GetProductIds to offer only the policies belonging to this CA, so a Command template cannot be mapped to a policy that issues from a different certificate authority
* Changed enrollment and re-issue to refuse a policy belonging to another certificate authority before submitting the request, rather than issuing a certificate from a CA the logical CA is not scoped to
* Fixed Revoke acting on any certificate in the tenant regardless of which certificate authority issued it: revocation now confirms the certificate was issued under one of this CA's policies first, and refuses when it was not or when its record cannot be read. Unscoped CAs are unaffected and pay no extra call
* Changed GetSingleRecord to refuse a certificate issued under another certificate authority's policy, naming the certificate's policy and the configured CA. The plugin's own post-enrollment and renewal lookups deliberately bypass the check, since enrollment has already verified the policy and re-checking would add a policy list round trip to every issuance
* Fixed a synchronization run whose CertificateAuthorityId scope could not be resolved leaving the Gateway's certificate buffer open, which stranded the sync job waiting on items that would never arrive instead of surfacing the error; the failure now completes the buffer on the way out like every other synchronization failure
* Added a warning when CertificateAuthorityId excludes every certificate in the account, listing the policies the CA owns against the policies seen on the excluded certificates, since the counts alone make that case indistinguishable from an empty CA
* Added validation of CertificateAuthorityId when the CA connection is saved, so a value matching no policy is reported on the config screen rather than at the first synchronization
* Added the policy id to the deserialized policy reference on certificate records, so CA scoping matches on the stable id where HydrantId supplies it and falls back to the policy name where it does not
* Fixed "No valid domains associated with organization" on POST /csr for a domain that was already VALIDATED at HydrantId but never linked to the enrolling policy's organization (e.g. validated before organizationIds was sent on creation, or under a different policy). The plugin now calls POST /domains/{id} to link or relink the organization at the moment validation is confirmed, instead of only logging a diagnostic warning
* Added automated DNS-01 style domain control validation: when the AnyCA Gateway supplies an IDomainValidatorFactory and a DNS provider plugin is configured for the domain's zone, the plugin now stages HydrantId's validation TXT record, polls until the domain is VALIDATED, removes the record, and issues the certificate within a single enrollment call
* Added the enrolling policy's organizationId to the domain validation request as organizationIds; HydrantId policies issue under an organization and POST /csr rejects domains that are not associated with it ("No valid domains associated with organization for IdenTrust policy"), and the plugin previously created every domain with a null organizationIds
* Changed domain control validation to target the registrable base domain rather than the CSR's fully-qualified name; HydrantId links the vetted organization to the base domain only, and validating a subdomain produced a record with a null organizationIds that POST /csr rejected with "No valid domains associated with organization". A base-domain validation additionally covers every subdomain until domainValidUntil
* Changed DNS provider plugin resolution to try the base domain and then the requested name, because the Gateway matches a domain validation configuration on exact domain equality; a configuration registered against either name now resolves, and the record is still written on the base domain
* Changed the DNS provider validation type tried first from "dns-01" to "DNS", which is what deployed DNS plugins report to AnyCA Gateway 26.2; the other spelling is still attempted as a fallback
* Added a fallback to the fully-qualified name when HydrantId will not accept the derived base domain, so an unrecognized multi-label public suffix costs one rejected API call rather than a failed enrollment
* Added a diagnostic that reports a validated domain's organizationIds, warning when it is empty, so the opaque "No valid domains associated with organization" failure from POST /csr is visible at the point domain validation completes
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
