using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Keyfactor.HydrantId.Client;
using Keyfactor.HydrantId.Interfaces;
using Keyfactor.HydrantId;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Threading.Tasks;
using LogHandler = Keyfactor.Logging.LogHandler;
using Keyfactor.HydrantId.Client.Models;
using System.Diagnostics;
using Keyfactor.AnyGateway.Extensions;
using System.Data;
using System.Net.Http;
using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.PKI.X509;
using Keyfactor.HydrantId.Client.Models.Enums;

namespace Keyfactor.Extensions.CAPlugin.HydrantId
{
    public class HydrantIdCAPlugin : IAnyCAPlugin
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<HydrantIdCAPlugin>();
        private readonly RequestManager _requestManager = new RequestManager();
        private IAnyCAPluginConfigProvider Config { get; set; }
        private ICertificateDataReader certDataReader;
        private HydrantIdCAPluginConfig.Config _config;

        internal Func<IAnyCAPluginConfigProvider, IHydrantIdClient> ClientFactory { get; set; }
            = config => new HydrantIdClient(config);

        private readonly IDomainValidatorFactory _validatorFactory;

        // The validation type DNS provider plugins register themselves under. The Gateway stores
        // whatever the plugin's GetValidationType() returns in DomainValidatorTypes.ValidationType
        // and matches on it exactly, so the spelling has to agree. "DNS" is what the deployed
        // LuaDNS plugin reports (confirmed against AnyCA Gateway 26.2); the ACME CA plugin resolves
        // with "dns-01". Both are attempted, "DNS" first, so either style of plugin is found.
        internal const string DnsValidationType = "DNS";
        internal const string DnsValidationTypeAlternate = "dns-01";

        internal const int DefaultDnsPropagationDelaySeconds = 30;
        internal const int DefaultDomainValidationTimeoutSeconds = 300;
        internal const int DefaultDomainValidationPollIntervalSeconds = 10;

        /// <summary>
        /// Used when the Gateway does not supply a DNS provider factory. Domain validation still
        /// works, but only on the manual path -- enrollment returns EXTERNALVALIDATION carrying the
        /// TXT record for an operator to publish before resubmitting.
        /// </summary>
        public HydrantIdCAPlugin()
        {
        }

        /// <summary>
        /// Preferred constructor. <paramref name="validatorFactory"/> is supplied by the Gateway and
        /// resolves whichever deployed DNS provider plugin owns a given zone, letting this plugin
        /// write HydrantID's validation TXT record itself and issue without operator involvement.
        /// Unlike the ACME CA plugin a null factory is tolerated rather than fatal, because HydrantID
        /// policies using a private CA validator -- or no validator at all -- issue fine without any
        /// DNS automation.
        /// </summary>
        public HydrantIdCAPlugin(IDomainValidatorFactory validatorFactory)
        {
            _validatorFactory = validatorFactory;
        }

        // Command leaves a numeric connector field at 0 when the template has never been saved
        // (the same gap RenewalDays works around -- ADO 81803), so the annotation default is
        // re-applied here rather than trusting the deserialized value.
        // A delay of 0 is meaningful (skip waiting), so only a null -- an absent connector
        // field -- or a negative value falls back to the annotation default.
        internal int DnsPropagationDelaySeconds =>
            _config?.DnsPropagationDelaySeconds is int delay && delay >= 0
                ? delay
                : DefaultDnsPropagationDelaySeconds;

        // A budget or interval of 0 is nonsense, so those require a positive value.
        internal int DomainValidationTimeoutSeconds =>
            _config?.DomainValidationTimeoutSeconds is int timeout && timeout > 0
                ? timeout
                : DefaultDomainValidationTimeoutSeconds;

        internal int DomainValidationPollIntervalSeconds =>
            _config?.DomainValidationPollIntervalSeconds is int interval && interval > 0
                ? interval
                : DefaultDomainValidationPollIntervalSeconds;

        // Minimal IAnyCAPluginConfigProvider over a raw connectionInfo dictionary, used by
        // ValidateCAConnectionInfo -- that entry point runs before the Gateway ever calls
        // Initialize(), so Config would otherwise be null when Ping() builds a client.
        private sealed class ConnectionInfoProvider : IAnyCAPluginConfigProvider
        {
            public Dictionary<string, object> CAConnectionData { get; set; }
        }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            using var flow = new FlowLogger(_logger, "Initialize");
            _logger.MethodEntry();

            try
            {
                flow.Step("ValidateInputs", () =>
                {
                    if (configProvider == null)
                        throw new ArgumentNullException(nameof(configProvider), "configProvider cannot be null in Initialize");
                    if (certificateDataReader == null)
                        throw new ArgumentNullException(nameof(certificateDataReader), "certificateDataReader cannot be null in Initialize");
                });

                flow.Step("DeserializeConfig", () =>
                {
                    certDataReader = certificateDataReader;
                    Config = configProvider;
                    var rawData = JsonConvert.SerializeObject(configProvider.CAConnectionData);
                    _logger.LogTrace("Initialize: config JSON (sensitive keys masked): {Json}", MaskConfigForLog(rawData));
                    _config = JsonConvert.DeserializeObject<HydrantIdCAPluginConfig.Config>(rawData);
                });

                if (_config == null)
                {
                    flow.Fail("ConfigValidation", "Deserialized config is null");
                    _logger.LogError("Initialize: _config is null after deserialization.");
                    return;
                }

                flow.Step("ConfigValidation", $"Enabled={_config.Enabled}");
                _logger.LogTrace("Initialize: Enabled={Enabled}, BaseUrl='{BaseUrl}'",
                    _config.Enabled, _config.HydrantIdBaseUrl ?? "(null)");
            }
            catch (Exception ex)
            {
                flow.Fail("Initialize", ex.Message);
                _logger.LogError(ex, "Failed to initialize HydrantId CAPlugin: {Message}", ex.Message);
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        private static readonly HashSet<string> _sensitiveConfigKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId,
            HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthKey
        };

        internal static string MaskConfigForLog(string rawJson)
        {
            if (string.IsNullOrEmpty(rawJson)) return rawJson;
            try
            {
                var token = Newtonsoft.Json.Linq.JToken.Parse(rawJson);
                if (token is Newtonsoft.Json.Linq.JObject obj)
                {
                    foreach (var prop in obj.Properties())
                    {
                        if (_sensitiveConfigKeys.Contains(prop.Name) &&
                            prop.Value.Type != Newtonsoft.Json.Linq.JTokenType.Null)
                        {
                            prop.Value = "***REDACTED***";
                        }
                    }
                    return obj.ToString(Newtonsoft.Json.Formatting.None);
                }
                return token.ToString(Newtonsoft.Json.Formatting.None);
            }
            catch (Exception ex)
            {
                _logger.LogTrace("MaskConfigForLog: failed to parse config JSON for masking, redacting entire payload: {Message}", ex.Message);
                return "***REDACTED***";
            }
        }

        public async Task Ping()
        {
            using var flow = new FlowLogger(_logger, "Ping");
            _logger.MethodEntry();

            try
            {
                if (_config == null)
                {
                    flow.Fail("ConfigCheck", "_config is null");
                    _logger.LogError("Ping: _config is null. Initialize may not have been called.");
                    _logger.MethodExit(LogLevel.Trace);
                    return;
                }

                if (!_config.Enabled)
                {
                    flow.Skip("Ping", "CA is disabled");
                    _logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping connectivity test...");
                    _logger.MethodExit(LogLevel.Trace);
                    return;
                }

                _logger.LogDebug("Pinging HydrantId to validate connection");
                var client = ClientFactory(Config);
                var reachable = await client.Ping();

                if (!reachable)
                {
                    flow.Fail("PingCA", "GET /policies did not return a success status");
                    _logger.LogError("Ping: HydrantId connectivity check failed -- GET /policies did not return a success status.");
                    throw new Exception("HydrantId connectivity check failed.");
                }

                flow.Step("PingCA", "connectivity verified");
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            using var flow = new FlowLogger(_logger, "ValidateCAConnectionInfo");
            _logger.MethodEntry();

            flow.Step("ValidateInputs", () =>
            {
                if (connectionInfo == null)
                    throw new ArgumentNullException(nameof(connectionInfo), "connectionInfo cannot be null");
            });

            _logger.LogDebug("Validating HydrantId CA Connection properties");
            var rawData = JsonConvert.SerializeObject(connectionInfo);
            _logger.LogTrace("ValidateCAConnectionInfo: connectionInfo JSON (sensitive keys masked): {Json}", MaskConfigForLog(rawData));

            Config = new ConnectionInfoProvider { CAConnectionData = connectionInfo };
            _config = JsonConvert.DeserializeObject<HydrantIdCAPluginConfig.Config>(rawData);

            _logger.LogTrace("ValidateCAConnectionInfo: HydrantIdBaseUrl='{BaseUrl}', Enabled={Enabled}",
                _config?.HydrantIdBaseUrl ?? "(null)", _config?.Enabled);

            if (_config == null)
            {
                flow.Fail("DeserializeConfig", "Deserialized config is null");
                throw new InvalidOperationException("Failed to deserialize connection info into config.");
            }

            if (!_config.Enabled)
            {
                flow.Skip("Validation", "CA is disabled");
                _logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping config validation...");
                _logger.MethodExit();
                return Task.CompletedTask;
            }

            List<string> missingFields = new List<string>();

            if (string.IsNullOrEmpty(_config.HydrantIdBaseUrl)) missingFields.Add(nameof(_config.HydrantIdBaseUrl));
            if (string.IsNullOrEmpty(_config.HydrantIdAuthId)) missingFields.Add(nameof(_config.HydrantIdAuthId));
            if (string.IsNullOrEmpty(_config.HydrantIdAuthKey)) missingFields.Add(nameof(_config.HydrantIdAuthKey));

            if (missingFields.Count > 0)
            {
                flow.Fail("RequiredFields", $"Missing: {string.Join(", ", missingFields)}");
                throw new ArgumentException($"The following required fields are missing or empty: {string.Join(", ", missingFields)}");
            }

            flow.Step("RequiredFields", "all present");
            _logger.MethodExit();
            return Ping();
        }

        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry();
            //TODO: Evaluate Template (if avaiable) based on ProductInfo
            _logger.MethodExit();
            return Task.CompletedTask;
        }


        public List<string> GetProductIds()
        {
            using var flow = new FlowLogger(_logger, "GetProductIds");
            _logger.MethodEntry();

            try
            {
                var client = ClientFactory(Config);
                List<Policy> policies = null;

                flow.Step("FetchPolicies", () =>
                {
                    policies = client.GetPolicyList().GetAwaiter().GetResult();
                });

                if (policies == null)
                {
                    flow.Fail("ParsePolicies", "API returned null policy list");
                    _logger.LogWarning("GetProductIds: GetPolicyList returned null.");
                    return new List<string>();
                }

                var ids = policies
                    .Where(p => p.Id.HasValue)
                    .Select(p => p.Name.ToString())
                    .ToList();

                flow.Step("MapPolicyIds", $"{ids.Count} product IDs found");
                _logger.LogTrace("GetProductIds: found {Count} product IDs", ids.Count);
                return ids;
            }
            catch (Exception ex)
            {
                flow.Fail("UNHANDLED", ex.Message);
                _logger.LogError(ex, "GetProductIds: unhandled exception: {Message}", ex.Message);
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            using var flow = new FlowLogger(_logger, $"Synchronize(fullSync={fullSync})");
            _logger.MethodEntry();
            _logger.LogTrace("Synchronize: lastSync={LastSync}, fullSync={FullSync}", lastSync?.ToString() ?? "(null)", fullSync);

            var certs = new BlockingCollection<ICertificatesResponseItem>(100);
            var client = ClientFactory(Config);
            var processedCount = 0;
            var skippedCount = 0;

            _ = client.GetSubmitCertificateListRequestAsync(certs, cancelToken);

            try
            {
                foreach (var item in certs.GetConsumingEnumerable(cancelToken))
                {
                    cancelToken.ThrowIfCancellationRequested();

                    if (item == null)
                    {
                        _logger.LogTrace("Synchronize: skipping null item from queue");
                        skippedCount++;
                        continue;
                    }

                    _logger.LogTrace("Synchronize: processing Certificate ID={Id}", item.Id ?? "(null)");

                    var certStatus = _requestManager.GetMapReturnStatus(item.RevocationStatus);
                    _logger.LogTrace("Synchronize: ID={Id}, RevocationStatus={RevStatus}, MappedStatus={MappedStatus}",
                        item.Id ?? "(null)", item.RevocationStatus, certStatus);

                    if (certStatus != Convert.ToInt32(EndEntityStatus.GENERATED) &&
                        certStatus != Convert.ToInt32(EndEntityStatus.REVOKED))
                    {
                        _logger.LogTrace("Synchronize: skipping ID={Id} with status {Status} (not GENERATED or REVOKED)", item.Id ?? "(null)", certStatus);
                        skippedCount++;
                        continue;
                    }

                    _logger.LogTrace("Synchronize: Product ID={ProductId}", item.Policy?.Name ?? "(null)");

                    try
                    {
                        var cert = await client.GetSubmitGetCertificateAsync(item.Id);

                        if (cert == null)
                        {
                            _logger.LogWarning("Synchronize: GetSubmitGetCertificateAsync returned null for ID={Id}", item.Id ?? "(null)");
                            skippedCount++;
                            continue;
                        }

                        var fileContent = cert.Pem ?? string.Empty;

                        if (string.IsNullOrWhiteSpace(fileContent))
                        {
                            _logger.LogTrace("Synchronize: empty PEM for ID={Id}", item.Id ?? "(null)");
                            skippedCount++;
                            continue;
                        }

                        var endEntityCert = GetEndEntityCertificate(fileContent);

                        if (!string.IsNullOrEmpty(endEntityCert))
                        {
                            blockingBuffer.Add(new AnyCAPluginCertificate
                            {
                                CARequestID = item.Id,
                                Certificate = endEntityCert,
                                Status = certStatus,
                                ProductID = item.Policy?.Name
                            }, cancelToken);

                            processedCount++;
                            _logger.LogTrace("Synchronize: processed end entity cert for ID={Id} (total={Total})", item.Id ?? "(null)", processedCount);
                        }
                        else
                        {
                            _logger.LogWarning("Synchronize: could not extract end entity certificate for ID={Id}", item.Id ?? "(null)");
                            skippedCount++;
                        }
                    }
                    catch (Exception certEx)
                    {
                        _logger.LogError(certEx, "Synchronize: failed to retrieve or process cert ID={Id}: {Message}", item.Id ?? "(null)", certEx.Message);
                        skippedCount++;
                    }
                }

                flow.Step("SyncComplete", $"processed={processedCount}, skipped={skippedCount}");
            }
            catch (OperationCanceledException)
            {
                flow.Fail("Cancelled", "operation was cancelled");
                _logger.LogWarning("Synchronize: operation was cancelled. Processed={Processed}, Skipped={Skipped}", processedCount, skippedCount);
                if (!blockingBuffer.IsAddingCompleted)
                    blockingBuffer.CompleteAdding();
                throw;
            }
            catch (AggregateException ae)
            {
                var inner = ae.Flatten().InnerException;
                flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
                _logger.LogError(inner ?? ae, "Synchronize: AggregateException: {Message}", inner?.Message ?? ae.Message);
                if (!blockingBuffer.IsAddingCompleted)
                    blockingBuffer.CompleteAdding();
                throw;
            }
            catch (Exception ex)
            {
                flow.Fail("UNHANDLED", ex.Message);
                _logger.LogError(ex, "Synchronize: unhandled exception: {Message}", ex.Message);
                if (!blockingBuffer.IsAddingCompleted)
                    blockingBuffer.CompleteAdding();
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        // Helper method to extract end entity certificate from PEM chain
        internal string GetEndEntityCertificate(string certData)
        {
            _logger.LogTrace("GetEndEntityCertificate: input length={Length}", certData?.Length ?? 0);

            if (string.IsNullOrWhiteSpace(certData))
            {
                _logger.LogWarning("GetEndEntityCertificate: certData is null or empty");
                return string.Empty;
            }

            var splitCerts = certData.Split(
                new[] { "-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----" },
                StringSplitOptions.RemoveEmptyEntries);

            X509Certificate2Collection col = new X509Certificate2Collection();

            foreach (var cert in splitCerts)
            {
                if (cert == null)
                {
                    _logger.LogTrace("GetEndEntityCertificate: skipping null split segment");
                    continue;
                }

                _logger.LogTrace("GetEndEntityCertificate: split cert segment length={Length}", cert.Length);
                try
                {
                    var cleanCert = cert.Trim();
                    if (string.IsNullOrWhiteSpace(cleanCert))
                        continue;

                    if (!cleanCert.StartsWith("-----BEGIN CERTIFICATE-----"))
                    {
                        cleanCert = $"-----BEGIN CERTIFICATE-----\n{cleanCert}\n-----END CERTIFICATE-----";
                    }
                    col.Import(Encoding.UTF8.GetBytes(cleanCert));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("GetEndEntityCertificate: failed to import certificate segment: {Message}", ex.Message);
                }
            }

            if (col.Count == 0)
            {
                _logger.LogWarning("GetEndEntityCertificate: no certificates imported from PEM data");
                return string.Empty;
            }

            _logger.LogTrace("GetEndEntityCertificate: imported {Count} certificates, extracting end entity", col.Count);
            var currentCert = X509Utilities.ExtractEndEntityCertificateContents(ExportCollectionToPem(col), "");

            if (currentCert == null)
            {
                _logger.LogWarning("GetEndEntityCertificate: ExtractEndEntityCertificateContents returned null");
                return string.Empty;
            }

            var byteArray = currentCert.Export(X509ContentType.Cert);
            if (byteArray == null)
            {
                _logger.LogWarning("GetEndEntityCertificate: cert Export returned null");
                return string.Empty;
            }

            var certString = Convert.ToBase64String(byteArray);
            _logger.LogTrace("GetEndEntityCertificate: extracted cert length={Length}", certString.Length);
            return certString;
        }

        // Helper method to export X509Certificate2Collection to PEM format
        internal string ExportCollectionToPem(X509Certificate2Collection collection)
        {
            var sb = new StringBuilder();
            foreach (var cert in collection)
            {
                sb.AppendLine("-----BEGIN CERTIFICATE-----");
                sb.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                sb.AppendLine("-----END CERTIFICATE-----");
            }
            return sb.ToString();
        }

        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            using var flow = new FlowLogger(_logger, $"Enroll-{enrollmentType}");
            _logger.MethodEntry();
            _logger.LogTrace("Enroll: csr length={CsrLen}, subject='{Subject}', enrollmentType={Type}, productID='{ProductId}'",
                csr?.Length ?? 0, subject ?? "(null)", enrollmentType, productInfo?.ProductID ?? "(null)");

            Certificate csrTrackingResponse = null;
            var client = ClientFactory(Config);

            try
            {
                flow.Step("ValidateInputs", () =>
                {
                    if (string.IsNullOrEmpty(csr))
                        throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");
                    if (productInfo == null)
                        throw new ArgumentNullException(nameof(productInfo), "productInfo cannot be null.");
                });

                CertRequestResult enrollmentResponse = null;

                if (enrollmentType == EnrollmentType.New)
                {
                    _logger.LogTrace("Enroll: entering New Enrollment path");

                    List<Policy> policyListResult = null;
                    await flow.StepAsync("FetchPolicies", async () =>
                    {
                        policyListResult = await client.GetPolicyList();
                    });

                    if (policyListResult == null)
                    {
                        flow.Fail("FetchPolicies", "API returned null policy list");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = "Enrollment failed: policy list returned null from HydrantId."
                        };
                    }

                    _logger.LogTrace("Enroll: policy list result: {Json}", JsonConvert.SerializeObject(policyListResult));

                    var policyId = policyListResult.SingleOrDefault(p => p.Name.Equals(productInfo.ProductID));
                    if (policyId == null)
                    {
                        flow.Fail("MatchPolicy", $"No policy found matching ProductID '{productInfo.ProductID}'");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = $"Enrollment failed: no policy found matching ProductID '{productInfo.ProductID}'."
                        };
                    }

                    _logger.LogTrace("Enroll: matched policy: {Json}", JsonConvert.SerializeObject(policyId));
                    flow.Step("MatchPolicy", $"policyId={policyId.Id}");

                    var domainValidationResult = await EnsureDomainsValidatedForPolicyAsync(client, flow, policyId, csr, san);
                    if (domainValidationResult != null)
                        return domainValidationResult;

                    var enrollmentRequest = _requestManager.GetEnrollmentRequest(policyId.Id, productInfo, csr, san);
                    _logger.LogTrace("Enroll: enrollment request JSON: {Json}", JsonConvert.SerializeObject(enrollmentRequest));

                    await flow.StepAsync("SubmitEnrollment", async () =>
                    {
                        enrollmentResponse = await client.GetSubmitEnrollmentAsync(enrollmentRequest);
                    });
                }
                else if (enrollmentType == EnrollmentType.RenewOrReissue)
                {
                    _logger.LogTrace("Enroll: entering Renew/Reissue path");

                    if (productInfo.ProductParameters == null || !productInfo.ProductParameters.ContainsKey("PriorCertSN"))
                    {
                        flow.Fail("ValidateRenewParams", "PriorCertSN not found in ProductParameters");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = "Renewal failed: PriorCertSN not found in product parameters."
                        };
                    }

                    var sn = productInfo.ProductParameters["PriorCertSN"];
                    _logger.LogTrace("Enroll: Prior Cert Serial Number='{SerialNumber}'", sn ?? "(null)");

                    if (string.IsNullOrEmpty(sn))
                    {
                        flow.Fail("ValidateSerialNumber", "PriorCertSN is null or empty");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = "Renewal failed: PriorCertSN is null or empty."
                        };
                    }

                    var certificateId = await certDataReader.GetRequestIDBySerialNumber(sn);
                    _logger.LogTrace("Enroll: certificateId from serial lookup='{CertId}'", certificateId ?? "(null)");

                    if (string.IsNullOrEmpty(certificateId))
                    {
                        flow.Fail("LookupCertId", $"No certificate found for serial number '{sn}'");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = $"Renewal failed: no certificate found for serial number '{sn}'."
                        };
                    }

                    flow.Step("LookupCertId", $"certificateId={certificateId}");

                    var previousCert = await GetSingleRecord(certificateId);

                    if (previousCert == null || string.IsNullOrEmpty(previousCert.Certificate))
                    {
                        flow.Fail("FetchPreviousCert", $"Could not retrieve previous certificate for ID '{certificateId}'");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = $"Renewal failed: could not retrieve previous certificate for ID '{certificateId}'."
                        };
                    }

                    var previousX509 = new X509Certificate2(Encoding.ASCII.GetBytes(previousCert.Certificate));
                    var expiration = previousX509.NotAfter;
                    var now = DateTime.UtcNow;

                    // Resolve RenewalDays from the supplied parameters, falling back to the
                    // annotation default when Command has not yet populated it (unsaved
                    // template — ADO 81803). Only fail if there is no default either.
                    var renewalDays = RequestManager.ResolveTemplateParameter(productInfo, HydrantIdCAPluginConfig.EnrollmentParametersConstants.RenewalDays);
                    if (string.IsNullOrWhiteSpace(renewalDays))
                    {
                        flow.Fail("ValidateRenewalDays", "RenewalDays not supplied and no annotation default is defined");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = "Renewal failed: RenewalDays not found in product parameters and no default is defined."
                        };
                    }

                    var isRenewal = (expiration - now).TotalDays <= Convert.ToInt16(renewalDays);
                    _logger.LogTrace("Enroll: expiration={Expiration}, now={Now}, isRenewal={IsRenewal}",
                        expiration, now, isRenewal);
                    flow.Step("DetermineRenewOrReissue", isRenewal ? "Renewal" : "Re-Issue");

                    if (isRenewal)
                    {
                        _logger.LogTrace("Enroll: proceeding with Renewal request");

                        if (certificateId.Length < 36)
                        {
                            flow.Fail("ValidateCertId", $"certificateId '{certificateId}' too short ({certificateId.Length} chars) to extract UUID");
                            return new EnrollmentResult
                            {
                                Status = (int)EndEntityStatus.FAILED,
                                StatusMessage = $"Renewal failed: certificateId '{certificateId}' is too short to extract a UUID."
                            };
                        }

                        var renewRequest = _requestManager.GetRenewalRequest(csr, false);
                        _logger.LogTrace("Enroll: renewal request JSON: {Json}", JsonConvert.SerializeObject(renewRequest));

                        await flow.StepAsync("SubmitRenewal", async () =>
                        {
                            enrollmentResponse = await client.GetSubmitRenewalAsync(certificateId, renewRequest);
                        });
                    }
                    else
                    {
                        _logger.LogTrace("Enroll: proceeding with Re-Issue request");

                        List<Policy> policyListResult = null;
                        await flow.StepAsync("FetchPolicies", async () =>
                        {
                            policyListResult = await client.GetPolicyList();
                        });

                        if (policyListResult == null)
                        {
                            flow.Fail("FetchPolicies", "API returned null policy list");
                            return new EnrollmentResult
                            {
                                Status = (int)EndEntityStatus.FAILED,
                                StatusMessage = "Re-issue failed: policy list returned null from HydrantId."
                            };
                        }

                        var policyId = policyListResult.SingleOrDefault(p => p.Name.Equals(productInfo.ProductID));
                        if (policyId == null)
                        {
                            flow.Fail("MatchPolicy", $"No policy found matching ProductID '{productInfo.ProductID}'");
                            return new EnrollmentResult
                            {
                                Status = (int)EndEntityStatus.FAILED,
                                StatusMessage = $"Re-issue failed: no policy found matching ProductID '{productInfo.ProductID}'."
                            };
                        }

                        var reissueDomainValidationResult = await EnsureDomainsValidatedForPolicyAsync(client, flow, policyId, csr, san);
                        if (reissueDomainValidationResult != null)
                            return reissueDomainValidationResult;

                        var reissueRequest = _requestManager.GetEnrollmentRequest(policyId.Id, productInfo, csr, san);
                        _logger.LogTrace("Enroll: re-issue request JSON: {Json}", JsonConvert.SerializeObject(reissueRequest));

                        await flow.StepAsync("SubmitReissue", async () =>
                        {
                            enrollmentResponse = await client.GetSubmitEnrollmentAsync(reissueRequest);
                        });
                    }
                }

                if (enrollmentResponse == null)
                {
                    flow.Fail("EnrollmentResponse", "enrollment response is null");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Enrollment failed: received null response from HydrantId."
                    };
                }

                _logger.LogTrace("Enroll: enrollment response JSON: {Json}", JsonConvert.SerializeObject(enrollmentResponse));

                if (enrollmentResponse.ErrorReturn?.Status == "Failure")
                {
                    flow.Fail("EnrollmentResult", enrollmentResponse.ErrorReturn.Error ?? "(no error message)");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = $"Enrollment Failed with error {enrollmentResponse.ErrorReturn.Error ?? "(no error message)"}"
                    };
                }

                var requestId = enrollmentResponse.RequestStatus?.Id;
                _logger.LogTrace("Enroll: request tracking ID='{TrackingId}'", requestId ?? "(null)");

                if (string.IsNullOrEmpty(requestId))
                {
                    flow.Fail("TrackingId", "enrollment response has no request tracking ID");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Enrollment failed: no request tracking ID in response."
                    };
                }

                await flow.StepAsync("WaitForCertificate", async () =>
                {
                    csrTrackingResponse = await GetCertificateOnTimerAsync(requestId);
                });

                if (csrTrackingResponse == null)
                {
                    flow.Fail("WaitForCertificate", "Certificate not ready after polling");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Certificate may still be pending in Hydrant and is not ready for download"
                    };
                }

                _logger.LogTrace("Enroll: csrTrackingResponse ID={Id}", csrTrackingResponse.Id?.ToString() ?? "(null)");

                var cert = await GetSingleRecord(csrTrackingResponse.Id.ToString());
                var result = _requestManager.GetEnrollmentResult(csrTrackingResponse, cert);

                flow.Step("EnrollmentComplete", $"status={result?.Status}, caRequestId={result?.CARequestID ?? "(null)"}");
                return result;
            }
            catch (Exception ex)
            {
                flow.Fail("UNHANDLED", ex.Message);
                _logger.LogError(ex, "Enroll: unhandled exception during {EnrollmentType}: {Message}", enrollmentType, ex.Message);
                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = $"Enrollment failed with error: {ex.Message}"
                };
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        /// <summary>
        /// Resolves the validator for the matched policy, computes the domains (CN + DNS SANs) that
        /// need DNS-based domain control validation, and ensures each is VALIDATED before a CSR is
        /// submitted. Returns null when enrollment may proceed -- either because every domain is
        /// validated, or because the matched policy has no validator configured, in which case DCV
        /// is not required and is skipped entirely (not every policy uses domain validation).
        /// Returns a non-null EXTERNALVALIDATION EnrollmentResult when one or more domains are still
        /// pending and the caller should return immediately instead of proceeding.
        /// </summary>
        internal async Task<EnrollmentResult> EnsureDomainsValidatedForPolicyAsync(
            IHydrantIdClient client, FlowLogger flow, Policy policyId, string csr, Dictionary<string, string[]> san)
        {
            var validatorId = policyId.Details?.Validator;
            if (string.IsNullOrWhiteSpace(validatorId))
            {
                flow.Skip("DomainValidation", $"policy '{policyId.Name}' has no validator configured; skipping DCV");
                return null;
            }

            var domainsToValidate = _requestManager.GetDomainsToValidate(csr, san);
            flow.Step("ComputeDomainsToValidate", string.Join(", ", domainsToValidate));

            bool allValidated = true;
            string pendingMessage = null;
            await flow.StepAsync("EnsureDomainsValidated", async () =>
            {
                (allValidated, pendingMessage) = await EnsureDomainsValidatedAsync(
                    client, flow, domainsToValidate, validatorId, policyId.OrganizationId?.ToString());
            });

            if (allValidated)
                return null;

            flow.Fail("DomainValidation", "one or more domains pending DCV");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.EXTERNALVALIDATION,
                StatusMessage = pendingMessage
            };
        }

        /// <summary>
        /// Builds the org/contact "payload" some HydrantID validators (e.g. IdenTrust) require on
        /// domain validation creation, from the optional Hydrant Id* config fields. Returns null
        /// (and therefore omits "payload" from the request entirely) when none are configured, so
        /// validators that don't need it (e.g. DigiCert, PrivateCA) are unaffected.
        /// </summary>
        internal DomainValidationOrgPayload BuildOrgPayload()
        {
            if (_config == null)
                return null;

            if (string.IsNullOrEmpty(_config.HydrantIdOrgName) &&
                string.IsNullOrEmpty(_config.HydrantIdOrgPrimaryContactFullName) &&
                string.IsNullOrEmpty(_config.HydrantIdOrgStreetAddress) &&
                string.IsNullOrEmpty(_config.HydrantIdOrgCityProvPostalCodeCountry) &&
                string.IsNullOrEmpty(_config.HydrantIdEmailAddress) &&
                string.IsNullOrEmpty(_config.HydrantIdPhoneNumber))
            {
                return null;
            }

            return new DomainValidationOrgPayload
            {
                OrgName = _config.HydrantIdOrgName,
                OrgPrimaryContactFullName = _config.HydrantIdOrgPrimaryContactFullName,
                OrgStreetAddress = _config.HydrantIdOrgStreetAddress,
                OrgCityProvPostalCodeCountry = _config.HydrantIdOrgCityProvPostalCodeCountry,
                EmailAddress = _config.HydrantIdEmailAddress,
                PhoneNumber = _config.HydrantIdPhoneNumber
            };
        }

        /// <summary>
        /// Ensures every domain in <paramref name="domainsToValidate"/> is VALIDATED at HydrantID
        /// before a CSR is submitted, automating the TXT record through a Keyfactor DNS provider
        /// plugin whenever one owns the zone. Runs in three phases, mirroring the ACME CA plugin's
        /// stage / verify / cleanup lifecycle:
        ///
        ///   1. Stage   -- create, regenerate or re-check each HydrantID domain record to obtain its
        ///                 validation code, then have the resolved IDomainValidator write it.
        ///   2. Wait    -- after a propagation delay, poll HydrantID until every staged domain
        ///                 reports VALIDATED or the configured budget runs out.
        ///   3. Cleanup -- remove every record this call staged, whatever the outcome.
        ///
        /// Validation targets the registrable base domain rather than the CSR's fully-qualified
        /// name, because HydrantID links the vetted organization to the base domain only --
        /// validating a subdomain yields a record with a null organizationIds, and POST /csr then
        /// rejects the enrollment with "No valid domains associated with organization". A
        /// base-domain validation also covers every subdomain until domainValidUntil. If HydrantID
        /// will not accept the base domain, the fully-qualified name is retried as a fallback.
        ///
        /// Domains that could not be automated (no factory, no plugin for the zone, or no code
        /// returned) fall back to the manual path and appear in the returned pending message, so a
        /// CA with no DNS plugin deployed behaves exactly as it did before automation existed.
        ///
        /// Command re-invokes Enroll() from scratch on resubmit, and this plugin has no local state
        /// store, so listing existing domains and filtering by name is the only way to recover a
        /// previously-started validation's id across Enroll() calls.
        /// </summary>
        internal async Task<(bool AllValidated, string PendingMessage)> EnsureDomainsValidatedAsync(
            IHydrantIdClient client, FlowLogger flow, List<string> domainsToValidate, string validatorId,
            string organizationIds = null)
        {
            // HydrantID soft-deletes domain records rather than removing them, and it is not
            // established whether the list endpoint filters them out. A soft-deleted record must
            // never be matched: re-checking one returns HTTP 500 ("Cannot read properties of null
            // (reading 'accountId')"), which would fail the enrollment instead of simply starting
            // a fresh validation for the domain.
            var existingDomains = (await client.GetDomainListAsync())
                .Where(d => string.IsNullOrEmpty(d.DeletedAt))
                .ToList();

            // Records this call wrote, and is therefore responsible for removing.
            var staged = new List<StagedValidation>();
            // Domains left for an operator to publish by hand.
            var pending = new List<(string Domain, string Instructions)>();

            try
            {
                foreach (var domainName in domainsToValidate)
                {
                    var exactMatch = existingDomains.FirstOrDefault(d =>
                        string.Equals(d.DomainName, domainName, StringComparison.OrdinalIgnoreCase));

                    if (exactMatch?.Status == DomainStatusEnum.Validated)
                    {
                        flow.Step("DomainValidation.AlreadyValidated", $"domain='{domainName}'");
                        await EnsureOrganizationLinkedAsync(client, flow, exactMatch, domainName, organizationIds);
                        continue;
                    }

                    if (exactMatch == null && IsCoveredByValidatedAncestor(domainName, existingDomains, out var coveringDomain))
                    {
                        flow.Step("DomainValidation.CoveredByValidatedParent", $"domain='{domainName}', parent='{coveringDomain}'");
                        continue;
                    }

                    var (domain, target, targetError) =
                        await ResolveDomainValidationRecordAsync(client, flow, domainName, existingDomains, validatorId, organizationIds);

                    if (domain == null)
                    {
                        // Every candidate was rejected by HydrantID. Report the domain as pending
                        // with the failure detail rather than throwing, so the rest of the
                        // certificate's domains still make progress.
                        pending.Add((domainName, targetError ?? "(no detail returned by HydrantId)"));
                        continue;
                    }

                    if (domain.Status == DomainStatusEnum.Validated)
                    {
                        flow.Step("DomainValidation.NowValidated", $"domain='{target}'");
                        await EnsureOrganizationLinkedAsync(client, flow, domain, target, organizationIds);
                        continue;
                    }

                    flow.Step("DomainValidation.StillPending", $"domain='{target}', status={domain.Status?.ToString() ?? "(none)"}");
                    var instructions = domain.CodeInstructions ?? "(no instructions returned by HydrantId)";

                    // Look the plugin up by the record's own name first, then by the name the CSR
                    // asked for -- the Gateway's domain validation configuration may be registered
                    // against either. See ResolveDnsValidator.
                    var dnsValidator = ResolveDnsValidator(flow, target, domainName);
                    if (dnsValidator == null)
                    {
                        pending.Add((target, instructions));
                        continue;
                    }

                    if (string.IsNullOrWhiteSpace(domain.Code) || string.IsNullOrWhiteSpace(domain.Id))
                    {
                        flow.Skip($"DomainValidation.Stage:{target}", "HydrantId returned no validation code or domain id to publish");
                        pending.Add((target, instructions));
                        continue;
                    }

                    if (await StageDnsRecordAsync(flow, dnsValidator, target, domain.Code))
                        staged.Add(new StagedValidation(target, domain.Id, instructions, dnsValidator));
                    else
                        pending.Add((target, instructions));
                }

                if (staged.Count > 0)
                {
                    var propagationDelay = DnsPropagationDelaySeconds;
                    flow.Step("DomainValidation.PropagationDelay", $"{propagationDelay}s for {staged.Count} staged record(s)");
                    await Task.Delay(TimeSpan.FromSeconds(propagationDelay));

                    await flow.StepAsync("DomainValidation.AwaitValidation", async () =>
                    {
                        await AwaitStagedValidationsAsync(client, flow, staged, pending, organizationIds);
                    });
                }
            }
            finally
            {
                await CleanupStagedRecordsAsync(flow, staged);
            }

            if (pending.Count == 0)
                return (true, null);

            var message = "Domain validation required before this certificate can be issued. " +
                "Publish the following DNS record(s), then resubmit:\n" +
                string.Join("\n", pending.Select(p => $"  - {p.Domain}: {p.Instructions}"));

            return (false, message);
        }

        /// <summary>
        /// Obtains the HydrantID domain record to validate for <paramref name="domainName"/>, trying
        /// each candidate from <see cref="GetValidationTargets"/> in order: the registrable base
        /// domain first, then the fully-qualified name. A candidate HydrantID rejects (for example a
        /// bare public suffix that the naive base-domain derivation produced) falls through to the
        /// next one instead of failing the enrollment.
        /// </summary>
        /// <returns>
        /// The domain record and the name it belongs to, or (null, null, error) when every candidate
        /// was rejected.
        /// </returns>
        internal async Task<(Domain Domain, string Target, string Error)> ResolveDomainValidationRecordAsync(
            IHydrantIdClient client, FlowLogger flow, string domainName, List<Domain> existingDomains, string validatorId,
            string organizationIds = null)
        {
            var targets = GetValidationTargets(domainName);
            string lastError = null;

            foreach (var target in targets)
            {
                var match = existingDomains.FirstOrDefault(d =>
                    string.Equals(d.DomainName, target, StringComparison.OrdinalIgnoreCase));

                if (match?.Status == DomainStatusEnum.Validated)
                {
                    flow.Step("DomainValidation.AlreadyValidated", $"domain='{target}' (covers '{domainName}')");
                    return (match, target, null);
                }

                try
                {
                    Domain domain;
                    if (match == null || match.Status == DomainStatusEnum.Expired)
                    {
                        // HydrantID's "regenerate code" action for an expired domain is the same
                        // POST used to start a validation from scratch -- confirmed idempotent per
                        // domain name (does not create a duplicate record) against staging.
                        flow.Step("DomainValidation.CreateOrRegenerate",
                            $"domain='{target}', for='{domainName}', priorStatus={(match == null ? "(none)" : match.Status.ToString())}");
                        var payload = _requestManager.GetCreateDomainValidationRequest(
                            target, validatorId, _config?.HydrantIdAccountId, BuildOrgPayload(), organizationIds);
                        domain = await client.GetSubmitCreateDomainValidationAsync(payload);
                    }
                    else
                    {
                        flow.Step("DomainValidation.Recheck", $"domain='{target}', status={match.Status}, domainId='{match.Id}'");
                        domain = await client.GetSubmitCheckDomainValidationAsync(match.Id);
                    }

                    return (domain, target, null);
                }
                catch (Exception ex)
                {
                    lastError = $"HydrantId rejected domain validation for '{target}': {ex.Message}";
                    flow.Fail($"DomainValidation.Target:{target}", ex.Message);
                    _logger.LogWarning(ex, "ResolveDomainValidationRecordAsync: '{Target}' rejected for '{Domain}', trying next candidate: {Message}",
                        target, domainName, ex.Message);
                }
            }

            return (null, null, lastError);
        }

        /// <summary>
        /// The names to attempt domain control validation on for <paramref name="domainName"/>, most
        /// preferred first: the registrable base domain, then the fully-qualified name itself. The
        /// two collapse to one entry when the name is already a base domain.
        /// </summary>
        internal static List<string> GetValidationTargets(string domainName)
        {
            var normalized = NormalizeDomainName(domainName);
            if (string.IsNullOrEmpty(normalized))
                return new List<string>();

            var targets = new List<string>();
            var baseDomain = GetBaseDomain(domainName);

            if (!string.IsNullOrEmpty(baseDomain) &&
                !string.Equals(baseDomain, normalized, StringComparison.OrdinalIgnoreCase))
            {
                targets.Add(baseDomain);
            }

            targets.Add(normalized);
            return targets;
        }

        /// <summary>
        /// The registrable base domain of <paramref name="domainName"/> -- the last two labels,
        /// or three when the last two form a known multi-label public suffix. Any wildcard prefix
        /// and trailing dot are stripped first.
        ///
        /// This is deliberately not a full public suffix list. Getting it wrong costs one rejected
        /// API call, because <see cref="ResolveDomainValidationRecordAsync"/> falls back to the
        /// fully-qualified name; carrying a PSL dependency and keeping its data current costs more.
        /// </summary>
        internal static string GetBaseDomain(string domainName)
        {
            var normalized = NormalizeDomainName(domainName);
            if (string.IsNullOrEmpty(normalized))
                return normalized;

            var labels = normalized.Split('.');
            if (labels.Length <= 2)
                return normalized;

            var lastTwo = string.Join(".", labels.Skip(labels.Length - 2));
            if (!_multiLabelPublicSuffixes.Contains(lastTwo))
                return lastTwo;

            return labels.Length <= 3
                ? normalized
                : string.Join(".", labels.Skip(labels.Length - 3));
        }

        private static string NormalizeDomainName(string domainName)
        {
            if (string.IsNullOrWhiteSpace(domainName))
                return null;

            var normalized = domainName.Trim().TrimEnd('.');
            if (normalized.StartsWith("*.", StringComparison.Ordinal))
                normalized = normalized.Substring(2);

            return normalized.Length == 0 ? null : normalized;
        }

        // Multi-label public suffixes common enough to be worth special-casing, so the base-domain
        // derivation does not produce something unregistrable like "co.uk". Not exhaustive by
        // design -- see GetBaseDomain. Add entries when a customer's TLD needs them.
        private static readonly HashSet<string> _multiLabelPublicSuffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
            "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
            "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
            "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr", "ac.kr",
            "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in",
            "co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za",
            "co.il", "org.il", "net.il", "ac.il", "gov.il",
            "com.br", "net.br", "org.br", "gov.br", "edu.br",
            "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx",
            "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
            "com.co", "net.co", "org.co", "gov.co", "edu.co",
            "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
            "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
            "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
            "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
            "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
            "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
            "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
            "com.ru", "net.ru", "org.ru", "edu.ru",
            "com.es", "org.es", "nom.es", "gob.es", "edu.es",
            "co.id", "or.id", "web.id", "go.id", "ac.id",
            "co.th", "or.th", "in.th", "go.th", "ac.th",
            "eu.com", "us.com", "uk.com", "uk.co", "gb.com",
        };

        /// <summary>
        /// A HydrantID domain validation whose TXT record was written by this enrollment, and which
        /// must therefore be polled to completion and then cleaned up.
        /// </summary>
        internal sealed class StagedValidation
        {
            public StagedValidation(string domain, string domainId, string instructions, IDomainValidator validator)
            {
                Domain = domain;
                DomainId = domainId;
                Instructions = instructions;
                Validator = validator;
            }

            public string Domain { get; }
            public string DomainId { get; }
            public string Instructions { get; }
            public IDomainValidator Validator { get; }
        }

        /// <summary>
        /// Resolves the DNS provider plugin to write the validation record with, trying each of
        /// <paramref name="lookupNames"/> in order and returning the first match.
        ///
        /// The name used to *find* the plugin is deliberately separate from the name the TXT record
        /// goes on, the same split the ACME CA plugin makes. The Gateway matches a domain validation
        /// configuration on an exact string equality against the domains registered for it
        /// (Domains.Domain = @DomainName), so a configuration registered against the requested
        /// hostname will not match that hostname's base domain, and vice versa. Passing both means
        /// either registration style resolves. Whichever plugin is found then writes the record on
        /// the base domain, which its own zone discovery handles.
        ///
        /// Never throws: any failure here degrades to the manual validation path, which is strictly
        /// better than failing an enrollment because plugin resolution misbehaved.
        /// </summary>
        internal IDomainValidator ResolveDnsValidator(FlowLogger flow, params string[] lookupNames)
        {
            var candidates = (lookupNames ?? new string[0])
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var label = candidates.Count > 0 ? candidates[0] : "(none)";

            if (_validatorFactory == null)
            {
                flow.Skip($"DomainValidation.ResolveValidator:{label}",
                    "no IDomainValidatorFactory supplied by the Gateway; manual DNS validation only");
                return null;
            }

            try
            {
                foreach (var candidate in candidates)
                {
                    var validator = _validatorFactory.ResolveDomainValidator(candidate, DnsValidationType)
                                    ?? _validatorFactory.ResolveDomainValidator(candidate, DnsValidationTypeAlternate);

                    if (validator == null)
                        continue;

                    flow.Step($"DomainValidation.ResolveValidator:{label}",
                        $"{validator.GetType().Name} (matched on '{candidate}')");
                    return validator;
                }

                flow.Skip($"DomainValidation.ResolveValidator:{label}",
                    $"no DNS provider plugin is configured for {string.Join(" or ", candidates)}");
                return null;
            }
            catch (Exception ex)
            {
                flow.Fail($"DomainValidation.ResolveValidator:{label}", ex.Message);
                _logger.LogWarning(ex, "ResolveDnsValidator: could not resolve a DNS provider plugin for '{Domain}', falling back to manual validation: {Message}",
                    label, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Writes HydrantID's validation TXT record via a DNS provider plugin. The record name is the
        /// domain itself rather than an _acme-challenge subdomain, and the value is HydrantID's whole
        /// code string, matching the codeInstructions HydrantID returns: "create a new DNS TXT record
        /// for the domain containing the following data: &lt;validator&gt;_validate=&lt;token&gt;".
        /// Returns false rather than throwing, so the domain falls back to the manual path.
        /// </summary>
        internal async Task<bool> StageDnsRecordAsync(FlowLogger flow, IDomainValidator dnsValidator, string domainName, string code)
        {
            try
            {
                var result = await dnsValidator.StageValidation(domainName, code, CancellationToken.None);

                if (result == null || !result.Success)
                {
                    flow.Fail($"DomainValidation.Stage:{domainName}",
                        result?.ErrorMessage ?? "DNS provider plugin returned no result");
                    _logger.LogWarning("StageDnsRecordAsync: {Validator} failed to write the TXT record for '{Domain}': {Error}",
                        dnsValidator.GetType().Name, domainName, result?.ErrorMessage ?? "(no result)");
                    return false;
                }

                flow.Step($"DomainValidation.Stage:{domainName}", $"TXT written via {dnsValidator.GetType().Name}");
                return true;
            }
            catch (Exception ex)
            {
                flow.Fail($"DomainValidation.Stage:{domainName}", ex.Message);
                _logger.LogWarning(ex, "StageDnsRecordAsync: {Validator} threw writing the TXT record for '{Domain}': {Message}",
                    dnsValidator.GetType().Name, domainName, ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Polls HydrantID until every staged domain reports VALIDATED or the configured budget is
        /// exhausted. Anything still unvalidated at the deadline is appended to
        /// <paramref name="pending"/>, which sends the enrollment down the EXTERNALVALIDATION path
        /// rather than failing it -- the staged code stays usable until codeValidUntil, so a resubmit
        /// can still pick it up.
        /// </summary>
        internal async Task AwaitStagedValidationsAsync(
            IHydrantIdClient client, FlowLogger flow, List<StagedValidation> staged, List<(string Domain, string Instructions)> pending,
            string organizationIds = null)
        {
            var timeout = TimeSpan.FromSeconds(DomainValidationTimeoutSeconds);
            var interval = TimeSpan.FromSeconds(DomainValidationPollIntervalSeconds);
            var stopwatch = Stopwatch.StartNew();
            var remaining = staged.ToList();

            while (true)
            {
                var stillPending = new List<StagedValidation>();

                foreach (var entry in remaining)
                {
                    Domain rechecked = null;
                    try
                    {
                        rechecked = await client.GetSubmitCheckDomainValidationAsync(entry.DomainId);
                    }
                    catch (Exception ex)
                    {
                        // A transient check failure should cost one tick, not the whole wait.
                        _logger.LogWarning(ex, "AwaitStagedValidationsAsync: check failed for '{Domain}' (domainId='{DomainId}'), retrying: {Message}",
                            entry.Domain, entry.DomainId, ex.Message);
                    }

                    if (rechecked?.Status == DomainStatusEnum.Validated)
                    {
                        flow.Step("DomainValidation.NowValidated", $"domain='{entry.Domain}' after {stopwatch.Elapsed.TotalSeconds:F0}s");
                        await EnsureOrganizationLinkedAsync(client, flow, rechecked, entry.Domain, organizationIds);
                    }
                    else
                    {
                        stillPending.Add(entry);
                    }
                }

                remaining = stillPending;

                if (remaining.Count == 0)
                    return;

                if (stopwatch.Elapsed + interval >= timeout)
                    break;

                await Task.Delay(interval);
            }

            foreach (var entry in remaining)
            {
                flow.Fail($"DomainValidation.Timeout:{entry.Domain}",
                    $"still pending after {stopwatch.Elapsed.TotalSeconds:F0}s (budget {DomainValidationTimeoutSeconds}s)");
                pending.Add((entry.Domain, entry.Instructions));
            }
        }

        /// <summary>
        /// Ensures a validated HydrantID domain is linked to the organization the enrolling policy
        /// issues under, fixing the link when it is missing or wrong rather than only reporting it.
        ///
        /// An IdenTrust OV policy issues under an organization, and POST /api/v2/csr rejects the
        /// enrollment with "No valid domains associated with organization for IdenTrust policy" when
        /// the domain it is issuing for has none -- including a domain that was validated before
        /// this plugin started sending organizationIds on creation, or one linked to a different
        /// organization than the policy now in use. POST /api/v2/domains/{id} with just
        /// {"organizationIds": "..."} updates that link on the existing record without disturbing
        /// its validation status (confirmed against staging).
        ///
        /// Does nothing when <paramref name="organizationIds"/> is blank -- the matched policy
        /// reports no organization, so there is nothing to link -- other than warning if the domain
        /// also has no link, since a policy that turns out to require one will surface that at
        /// enrollment time as "No valid domains associated with organization" instead.
        /// </summary>
        internal async Task EnsureOrganizationLinkedAsync(
            IHydrantIdClient client, FlowLogger flow, Domain domain, string target, string organizationIds)
        {
            if (domain == null)
                return;

            if (string.Equals(domain.OrganizationIds, organizationIds, StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(domain.OrganizationIds))
                {
                    flow.Step("DomainValidation.OrganizationLink",
                        $"domain='{target}', organizationIds='{domain.OrganizationIds}'");
                }
                return;
            }

            if (string.IsNullOrWhiteSpace(organizationIds))
            {
                if (string.IsNullOrWhiteSpace(domain.OrganizationIds))
                {
                    flow.Step("DomainValidation.NoOrganizationLink", $"domain='{target}' has no organizationIds");
                    _logger.LogWarning(
                        "Domain '{Domain}' is VALIDATED at HydrantId but its organizationIds is empty and the matched " +
                        "policy reports no organization. A policy that issues under an organization (e.g. an IdenTrust " +
                        "OV policy) will reject enrollment with \"No valid domains associated with organization\".",
                        target);
                }
                return;
            }

            flow.Step("DomainValidation.LinkOrganization",
                $"domain='{target}', organizationIds='{organizationIds}' (was '{domain.OrganizationIds ?? "(none)"}')");

            try
            {
                var updated = await client.GetSubmitUpdateDomainOrganizationAsync(domain.Id, organizationIds);
                domain.OrganizationIds = updated?.OrganizationIds ?? organizationIds;
            }
            catch (Exception ex)
            {
                flow.Fail($"DomainValidation.LinkOrganization:{target}", ex.Message);
                _logger.LogWarning(ex,
                    "EnsureOrganizationLinkedAsync: failed to link domain '{Domain}' to organization '{OrganizationIds}': {Message}",
                    target, organizationIds, ex.Message);
            }
        }

        /// <summary>
        /// Removes every TXT record staged by this enrollment. A leftover record cannot break
        /// issuance, so a cleanup failure is logged and swallowed rather than allowed to fail an
        /// enrollment that otherwise succeeded.
        /// </summary>
        internal async Task CleanupStagedRecordsAsync(FlowLogger flow, List<StagedValidation> staged)
        {
            foreach (var entry in staged)
            {
                try
                {
                    var result = await entry.Validator.CleanupValidation(entry.Domain, CancellationToken.None);

                    if (result == null || !result.Success)
                    {
                        flow.Fail($"DomainValidation.Cleanup:{entry.Domain}",
                            result?.ErrorMessage ?? "DNS provider plugin returned no result");
                        _logger.LogWarning("CleanupStagedRecordsAsync: {Validator} failed to remove the TXT record for '{Domain}': {Error}",
                            entry.Validator.GetType().Name, entry.Domain, result?.ErrorMessage ?? "(no result)");
                    }
                    else
                    {
                        flow.Step($"DomainValidation.Cleanup:{entry.Domain}", "TXT record removed");
                    }
                }
                catch (Exception ex)
                {
                    flow.Fail($"DomainValidation.Cleanup:{entry.Domain}", ex.Message);
                    _logger.LogWarning(ex, "CleanupStagedRecordsAsync: {Validator} threw removing the TXT record for '{Domain}': {Message}",
                        entry.Validator.GetType().Name, entry.Domain, ex.Message);
                }
            }
        }

        /// <summary>
        /// True when <paramref name="domainName"/> is itself, or a subdomain of, some other domain
        /// in <paramref name="existingDomains"/> that is already Validated -- per HydrantID's own
        /// domain-validation documentation, DCV is scoped to the base domain and subdomains at any
        /// depth are covered without a separate validation record.
        /// </summary>
        internal static bool IsCoveredByValidatedAncestor(string domainName, List<Domain> existingDomains, out string coveringDomain)
        {
            coveringDomain = null;

            foreach (var candidate in existingDomains)
            {
                if (candidate.Status != DomainStatusEnum.Validated ||
                    !string.IsNullOrEmpty(candidate.DeletedAt) ||
                    string.IsNullOrEmpty(candidate.DomainName))
                    continue;

                if (string.Equals(domainName, candidate.DomainName, StringComparison.OrdinalIgnoreCase) ||
                    domainName.EndsWith("." + candidate.DomainName, StringComparison.OrdinalIgnoreCase))
                {
                    coveringDomain = candidate.DomainName;
                    return true;
                }
            }

            return false;
        }

        public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            using var flow = new FlowLogger(_logger, $"Revoke({caRequestID ?? "null"})");
            _logger.MethodEntry();
            _logger.LogTrace("Revoke: caRequestID='{CaRequestId}', hexSerialNumber='{SerialNumber}', revocationReason={Reason}",
                caRequestID ?? "(null)", hexSerialNumber ?? "(null)", revocationReason);

            try
            {
                flow.Step("ValidateInput", () =>
                {
                    if (string.IsNullOrEmpty(caRequestID))
                        throw new ArgumentNullException(nameof(caRequestID), "caRequestID cannot be null or empty.");
                    if (caRequestID.Length < 36)
                        throw new ArgumentException($"caRequestID '{caRequestID}' is too short ({caRequestID.Length} chars) to extract a UUID.", nameof(caRequestID));
                });

                var client = ClientFactory(Config);
                var hydrantId = caRequestID.Substring(0, 36);
                _logger.LogTrace("Revoke: extracted UUID='{Uuid}'", hydrantId);

                RevocationReasons revokeReason = default;
                flow.Step("MapRevokeReason", () =>
                {
                    revokeReason = _requestManager.GetMapRevokeReasons(revocationReason);
                });
                _logger.LogTrace("Revoke: mapped reason={Reason}", revokeReason);

                CertificateStatus revokeResponse = null;
                await flow.StepAsync("SubmitRevoke", async () =>
                {
                    revokeResponse = await client.GetSubmitRevokeCertificateAsync(hydrantId, revokeReason);
                });

                _logger.LogTrace("Revoke: response JSON: {Json}", JsonConvert.SerializeObject(revokeResponse));

                if (revokeResponse == null)
                {
                    flow.Fail("ParseResponse", "API returned null revocation response");
                    _logger.LogError("Revoke: GetSubmitRevokeCertificateAsync returned null for UUID='{Uuid}'", hydrantId);
                    throw new InvalidOperationException($"Revoke failed: received null response from HydrantId for UUID '{hydrantId}'.");
                }

                flow.Step("RevokeComplete", $"revocationStatus={revokeResponse.RevocationStatus}");
                return (int)EndEntityStatus.REVOKED;
            }
            catch (HttpRequestException httpEx)
            {
                flow.Fail("HttpError", httpEx.Message);
                _logger.LogError(httpEx, "Revoke: HTTP error for caRequestID='{CaRequestId}': {Message}", caRequestID ?? "(null)", httpEx.Message);
                throw;
            }
            catch (AggregateException ae)
            {
                var inner = ae.Flatten().InnerException;
                flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
                _logger.LogError(inner ?? ae, "Revoke: AggregateException for caRequestID='{CaRequestId}': {Message}",
                    caRequestID ?? "(null)", inner?.Message ?? ae.Message);
                throw new Exception($"Revoke failed for '{caRequestID}' with message {inner?.Message ?? ae.Message}", inner ?? ae);
            }
            catch (Exception e)
            {
                flow.Fail("UNHANDLED", e.Message);
                _logger.LogError(e, "Revoke: unhandled exception for caRequestID='{CaRequestId}': {Message}",
                    caRequestID ?? "(null)", e.Message);
                throw new Exception($"Revoke failed for '{caRequestID}' with message {e.Message}", e);
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        internal int PollIntervalMs { get; set; } = 1000;
        internal int PollTimeoutMs { get; set; } = 30000;

        internal async Task<Certificate> GetCertificateOnTimerAsync(string id)
        {
            _logger.LogTrace("GetCertificateOnTimerAsync: waiting for certificate with tracking ID='{Id}'", id ?? "(null)");
            var stopwatch = Stopwatch.StartNew();
            var client = ClientFactory(Config);

            while (stopwatch.ElapsedMilliseconds < PollTimeoutMs)
            {
                try
                {
                    var result = await client.GetSubmitGetCertificateByCsrAsync(id);
                    if (result != null)
                    {
                        _logger.LogTrace("GetCertificateOnTimerAsync: certificate available after {Elapsed}ms", stopwatch.ElapsedMilliseconds);
                        return result;
                    }
                }
                catch (Exception e)
                {
                    _logger.LogTrace("GetCertificateOnTimerAsync: not available yet ({Elapsed}ms): {Message}",
                        stopwatch.ElapsedMilliseconds, e.Message);
                }

                await Task.Delay(PollIntervalMs);
            }

            _logger.LogWarning("GetCertificateOnTimerAsync: timed out after {TimeoutMs}ms for tracking ID='{Id}'", PollTimeoutMs, id ?? "(null)");
            return null;
        }

        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            using var flow = new FlowLogger(_logger, $"GetSingleRecord({caRequestID ?? "null"})");
            _logger.MethodEntry();
            _logger.LogTrace("GetSingleRecord: caRequestID='{CaRequestId}'", caRequestID ?? "(null)");

            try
            {
                flow.Step("ValidateInput", () =>
                {
                    if (string.IsNullOrEmpty(caRequestID))
                        throw new ArgumentNullException(nameof(caRequestID), "caRequestID cannot be null or empty.");
                    if (caRequestID.Length < 36)
                        throw new ArgumentException($"caRequestID '{caRequestID}' is too short ({caRequestID.Length} chars) to extract a UUID.", nameof(caRequestID));
                });

                var client = ClientFactory(Config);
                var certId = caRequestID.Substring(0, 36);
                _logger.LogTrace("GetSingleRecord: extracted UUID='{CertId}'", certId);

                Certificate certificateResponse = null;
                await flow.StepAsync("FetchCertificate", async () =>
                {
                    certificateResponse = await client.GetSubmitGetCertificateAsync(certId);
                });

                if (certificateResponse == null)
                {
                    flow.Fail("ParseResponse", "API returned null");
                    _logger.LogWarning("GetSingleRecord: GetSubmitGetCertificateAsync returned null for certId='{CertId}'", certId);
                    return new AnyCAPluginCertificate
                    {
                        CARequestID = caRequestID,
                        Certificate = string.Empty,
                        Status = _requestManager.GetMapReturnStatus(RevocationStatusEnum.Failed)
                    };
                }

                _logger.LogTrace("GetSingleRecord: response JSON: {Json}", JsonConvert.SerializeObject(certificateResponse));

                var endEntityCert = GetEndEntityCertificate(certificateResponse.Pem);

                if (string.IsNullOrEmpty(endEntityCert))
                {
                    flow.Fail("ExtractCert", $"Could not extract end entity certificate for caRequestID '{caRequestID}'");
                    _logger.LogWarning("GetSingleRecord: could not extract end entity certificate for caRequestID='{CaRequestId}'", caRequestID);
                    return new AnyCAPluginCertificate
                    {
                        CARequestID = caRequestID,
                        Status = _requestManager.GetMapReturnStatus(RevocationStatusEnum.Failed)
                    };
                }

                var mappedStatus = _requestManager.GetMapReturnStatus(certificateResponse.RevocationStatus);
                flow.Step("MapStatus", $"{certificateResponse.RevocationStatus} -> {mappedStatus}");

                _logger.MethodExit();
                return new AnyCAPluginCertificate
                {
                    CARequestID = caRequestID,
                    Certificate = endEntityCert,
                    Status = mappedStatus,
                };
            }
            catch (AggregateException ae)
            {
                var inner = ae.Flatten().InnerException;
                flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
                _logger.LogError(inner ?? ae, "GetSingleRecord: AggregateException for caRequestID='{CaRequestId}': {Message}",
                    caRequestID ?? "(null)", inner?.Message ?? ae.Message);
                throw new Exception($"Error occurred getting single cert for '{caRequestID}': {inner?.Message ?? ae.Message}", inner ?? ae);
            }
            catch (Exception ex)
            {
                flow.Fail("UNHANDLED", ex.Message);
                _logger.LogError(ex, "GetSingleRecord: exception for caRequestID='{CaRequestId}': {Message}",
                    caRequestID ?? "(null)", ex.Message);
                throw new Exception($"Error occurred getting single cert for '{caRequestID}': {ex.Message}", ex);
            }
        }

        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return HydrantIdCAPluginConfig.GetPluginAnnotations();
        }

        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return HydrantIdCAPluginConfig.GetTemplateParameterAnnotations();
        }

    }
}
