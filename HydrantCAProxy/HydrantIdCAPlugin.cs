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
                (allValidated, pendingMessage) = await EnsureDomainsValidatedAsync(client, flow, domainsToValidate, validatorId);
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
        /// Checks each domain against HydrantID's Domains resource, starting DNS validation for any
        /// domain that has not been requested yet and re-checking any domain that is still pending.
        /// Command re-invokes Enroll() from scratch on resubmit, and this plugin has no local state
        /// store, so listing existing domains and filtering by name is the only way to recover a
        /// previously-started validation's id across Enroll() calls.
        /// </summary>
        internal async Task<(bool AllValidated, string PendingMessage)> EnsureDomainsValidatedAsync(
            IHydrantIdClient client, FlowLogger flow, List<string> domainsToValidate, string validatorId)
        {
            var existingDomains = await client.GetDomainListAsync();

            var pending = new List<(string Domain, string Instructions)>();

            foreach (var domainName in domainsToValidate)
            {
                var match = existingDomains.FirstOrDefault(d =>
                    string.Equals(d.DomainName, domainName, StringComparison.OrdinalIgnoreCase));

                Domain domain;
                if (match == null || match.Status == DomainStatusEnum.Expired)
                {
                    // HydrantID's "regenerate code" action for an expired domain is the same
                    // POST used to start a validation from scratch -- confirmed idempotent per
                    // domain name (does not create a duplicate record) against staging.
                    flow.Step("DomainValidation.CreateOrRegenerate",
                        $"domain='{domainName}', priorStatus={(match == null ? "(none)" : match.Status.ToString())}");
                    var payload = _requestManager.GetCreateDomainValidationRequest(domainName, validatorId);
                    domain = await client.GetSubmitCreateDomainValidationAsync(payload);
                }
                else if (match.Status != DomainStatusEnum.Validated)
                {
                    flow.Step("DomainValidation.Recheck", $"domain='{domainName}', status={match.Status}, domainId='{match.Id}'");
                    domain = await client.GetSubmitCheckDomainValidationAsync(match.Id);
                }
                else
                {
                    flow.Step("DomainValidation.AlreadyValidated", $"domain='{domainName}'");
                    continue;
                }

                if (domain?.Status != DomainStatusEnum.Validated)
                {
                    flow.Step("DomainValidation.StillPending", $"domain='{domainName}', status={domain?.Status.ToString() ?? "(null response)"}");
                    pending.Add((domainName, domain?.CodeInstructions ?? "(no instructions returned by HydrantId)"));
                }
                else
                {
                    flow.Step("DomainValidation.NowValidated", $"domain='{domainName}'");
                }
            }

            if (pending.Count == 0)
                return (true, null);

            var message = "Domain validation required before this certificate can be issued. " +
                "Publish the following DNS record(s), then resubmit:\n" +
                string.Join("\n", pending.Select(p => $"  - {p.Domain}: {p.Instructions}"));

            return (false, message);
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
