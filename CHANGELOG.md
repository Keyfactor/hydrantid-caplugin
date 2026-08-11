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
