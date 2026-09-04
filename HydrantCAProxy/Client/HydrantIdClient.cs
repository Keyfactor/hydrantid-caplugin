// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.  You may obtain a
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
// required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for
// thespecific language governing permissions and limitations under the
// License.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Logging;
using Keyfactor.HydrantId.Client.Models;
using Keyfactor.HydrantId.Client.Models.Enums;
using Keyfactor.HydrantId.Exceptions;
using Keyfactor.HydrantId.Interfaces;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Microsoft.Extensions.Logging;
using Keyfactor.Extensions.CAPlugin.HydrantId;
using Keyfactor.AnyGateway.Extensions;
using HawkNet;
using System.Globalization;

namespace Keyfactor.HydrantId.Client
{
    public sealed class HydrantIdClient : IHydrantIdClient
    {
        private static readonly ILogger Log = LogHandler.GetClassLogger<HydrantIdClient>();
        private readonly HttpMessageHandler _handler;

        internal HydrantIdClient(IAnyCAPluginConfigProvider config, HttpMessageHandler handler) : this(config)
        {
            _handler = handler;
        }

        public HydrantIdClient(IAnyCAPluginConfigProvider config)
        {
            try
            {
                Log.MethodEntry();

                if (config == null)
                    throw new ArgumentNullException(nameof(config), "config cannot be null.");
                if (config.CAConnectionData == null)
                    throw new ArgumentNullException(nameof(config), "CAConnectionData cannot be null.");

                if (config.CAConnectionData.ContainsKey(HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId))
                {
                    ConfigProvider = config;
                    var baseUrlObj = ConfigProvider.CAConnectionData[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdBaseUrl];
                    BaseUrl = baseUrlObj?.ToString();

                    if (string.IsNullOrEmpty(BaseUrl))
                    {
                        Log.LogError("HydrantIdClient: BaseUrl is null or empty after reading config.");
                        throw new InvalidOperationException("HydrantIdBaseUrl is null or empty in CAConnectionData.");
                    }

                    Log.LogTrace("HydrantIdClient: BaseUrl='{BaseUrl}'", BaseUrl);
                    RequestManager = new RequestManager();
                }
                else
                {
                    Log.LogError("HydrantIdClient: HydrantIdAuthId key not found in CAConnectionData.");
                    throw new InvalidOperationException("HydrantIdAuthId not found in CAConnectionData.");
                }
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in HydrantIdClient constructor: {Message}", e.Message);
                throw;
            }
        }

        private string BaseUrl { get; }
        private int PageSize { get; } = 100;
        private string ApiId { get; set; }
        private RequestManager RequestManager { get; }

        private IAnyCAPluginConfigProvider ConfigProvider { get; }

        public async Task<CertRequestResult> GetSubmitEnrollmentAsync(CertRequestBody registerRequest)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitEnrollmentAsync: registerRequest is {Null}", registerRequest == null ? "NULL" : "present");

            if (registerRequest == null)
                throw new ArgumentNullException(nameof(registerRequest), "registerRequest cannot be null.");

            var apiEndpoint = "/api/v2/csr";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitEnrollmentAsync: API Url={Url}", fullUrl);

            var json = JsonConvert.SerializeObject(registerRequest);
            Log.LogTrace("GetSubmitEnrollmentAsync: request JSON: {Json}", json);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("post", fullUrl);
                using var resp = await restClient.PostAsync(apiEndpoint, new StringContent(json, Encoding.UTF8, "application/json"));
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetSubmitEnrollmentAsync: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (resp.StatusCode == HttpStatusCode.InternalServerError)
                {
                    var errorResponse = JsonConvert.DeserializeObject<ErrorReturn>(responseContent, settings);
                    Log.LogError("GetSubmitEnrollmentAsync: server error response: {Json}", JsonConvert.SerializeObject(errorResponse));
                    return new CertRequestResult { ErrorReturn = errorResponse };
                }

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetSubmitEnrollmentAsync: unexpected status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    return new CertRequestResult
                    {
                        ErrorReturn = new ErrorReturn { Status = "Failure", Error = $"HTTP {resp.StatusCode}: {responseContent}" }
                    };
                }

                var validResponse = JsonConvert.DeserializeObject<CertRequestStatus>(responseContent, settings);
                Log.LogTrace("GetSubmitEnrollmentAsync: valid response JSON: {Json}", JsonConvert.SerializeObject(validResponse));
                return new CertRequestResult { RequestStatus = validResponse };
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitEnrollmentAsync: exception: {Message}", e.Message);
                throw;
            }
        }


        public async Task<CertRequestResult> GetSubmitRenewalAsync(string certificateId, RenewalRequest renewRequest)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitRenewalAsync: certificateId='{CertId}', renewRequest is {Null}",
                certificateId ?? "(null)", renewRequest == null ? "NULL" : "present");

            if (string.IsNullOrEmpty(certificateId))
                throw new ArgumentNullException(nameof(certificateId), "certificateId cannot be null or empty.");
            if (renewRequest == null)
                throw new ArgumentNullException(nameof(renewRequest), "renewRequest cannot be null.");

            var apiEndpoint = $"/api/v2/certificates/{certificateId}/renew";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitRenewalAsync: API Url={Url}", fullUrl);

            var json = JsonConvert.SerializeObject(renewRequest);
            Log.LogTrace("GetSubmitRenewalAsync: request JSON: {Json}", json);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("post", fullUrl);
                using var resp = await restClient.PostAsync(apiEndpoint, new StringContent(json, Encoding.UTF8, "application/json"));
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetSubmitRenewalAsync: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (resp.StatusCode == HttpStatusCode.InternalServerError)
                {
                    var errorResponse = JsonConvert.DeserializeObject<ErrorReturn>(responseContent, settings);
                    Log.LogError("GetSubmitRenewalAsync: server error response: {Json}", JsonConvert.SerializeObject(errorResponse));
                    return new CertRequestResult { ErrorReturn = errorResponse };
                }

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetSubmitRenewalAsync: unexpected status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    return new CertRequestResult
                    {
                        ErrorReturn = new ErrorReturn { Status = "Failure", Error = $"HTTP {resp.StatusCode}: {responseContent}" }
                    };
                }

                var validResponse = JsonConvert.DeserializeObject<CertRequestStatus>(responseContent, settings);
                Log.LogTrace("GetSubmitRenewalAsync: valid response JSON: {Json}", JsonConvert.SerializeObject(validResponse));
                return new CertRequestResult { RequestStatus = validResponse };
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitRenewalAsync: exception: {Message}", e.Message);
                throw;
            }
        }



        public async Task<List<Policy>> GetPolicyList()
        {
            Log.MethodEntry();
            var apiEndpoint = "/api/v2/policies";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetPolicyList: API Url={Url}", fullUrl);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("get", fullUrl);
                using var resp = await restClient.GetAsync(apiEndpoint);
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetPolicyList: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetPolicyList: request failed with status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    throw new HttpRequestException($"GetPolicyList failed with HTTP {resp.StatusCode}: {responseContent}");
                }

                var policies = JsonConvert.DeserializeObject<List<Policy>>(responseContent, settings);

                if (policies == null)
                {
                    Log.LogWarning("GetPolicyList: deserialized policy list is null");
                    return new List<Policy>();
                }

                Log.LogTrace("GetPolicyList: returned {Count} policies", policies.Count);
                return policies;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetPolicyList: exception: {Message}", e.Message);
                throw;
            }
        }



        public async Task<List<Domain>> GetDomainListAsync()
        {
            Log.MethodEntry();
            var apiEndpoint = "/api/v2/domains/";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetDomainListAsync: API Url={Url}", fullUrl);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("get", fullUrl);
                using var resp = await restClient.GetAsync(apiEndpoint);
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetDomainListAsync: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetDomainListAsync: request failed with status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    throw new HttpRequestException($"GetDomainListAsync failed with HTTP {resp.StatusCode}: {responseContent}");
                }

                var domains = JsonConvert.DeserializeObject<List<Domain>>(responseContent, settings);

                if (domains == null)
                {
                    Log.LogWarning("GetDomainListAsync: deserialized domain list is null");
                    return new List<Domain>();
                }

                Log.LogTrace("GetDomainListAsync: returned {Count} domains", domains.Count);
                return domains;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetDomainListAsync: exception: {Message}", e.Message);
                throw;
            }
        }



        public async Task<Domain> GetSubmitCreateDomainValidationAsync(CreateDomainValidationPayload payload)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitCreateDomainValidationAsync: payload is {Null}", payload == null ? "NULL" : "present");

            if (payload == null)
                throw new ArgumentNullException(nameof(payload), "payload cannot be null.");

            var apiEndpoint = "/api/v2/domains/";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitCreateDomainValidationAsync: API Url={Url}", fullUrl);

            var json = JsonConvert.SerializeObject(payload);
            Log.LogTrace("GetSubmitCreateDomainValidationAsync: request JSON: {Json}", json);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("post", fullUrl);
                using var resp = await restClient.PostAsync(apiEndpoint, new StringContent(json, Encoding.UTF8, "application/json"));
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetSubmitCreateDomainValidationAsync: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetSubmitCreateDomainValidationAsync: request failed with status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    throw new HttpRequestException($"GetSubmitCreateDomainValidationAsync failed with HTTP {resp.StatusCode}: {responseContent}");
                }

                var domain = JsonConvert.DeserializeObject<Domain>(responseContent, settings);
                Log.LogTrace("GetSubmitCreateDomainValidationAsync: response JSON: {Json}", JsonConvert.SerializeObject(domain));
                return domain;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitCreateDomainValidationAsync: exception: {Message}", e.Message);
                throw;
            }
        }



        // Links an existing domain validation record to an organization after the fact. Needed
        // for records created before this plugin started sending organizationIds on creation (or
        // linked to the wrong organization), which HydrantId otherwise leaves associated with no
        // organization -- POST /api/v2/csr then rejects the enrollment with "No valid domains
        // associated with organization". Confirmed against staging: POST to the domain's own
        // resource URL (no trailing path segment, unlike creation's /api/v2/domains/) with just
        // {"organizationIds": "..."} updates the existing record rather than creating a new one.
        public async Task<Domain> GetSubmitUpdateDomainOrganizationAsync(string domainId, string organizationIds)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitUpdateDomainOrganizationAsync: domainId='{DomainId}', organizationIds='{OrganizationIds}'",
                domainId ?? "(null)", organizationIds ?? "(null)");

            if (string.IsNullOrEmpty(domainId))
                throw new ArgumentNullException(nameof(domainId), "domainId cannot be null or empty.");
            if (string.IsNullOrEmpty(organizationIds))
                throw new ArgumentNullException(nameof(organizationIds), "organizationIds cannot be null or empty.");

            var apiEndpoint = $"/api/v2/domains/{domainId}";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitUpdateDomainOrganizationAsync: API Url={Url}", fullUrl);

            var payload = new UpdateDomainOrganizationPayload { OrganizationIds = organizationIds };
            var json = JsonConvert.SerializeObject(payload);
            Log.LogTrace("GetSubmitUpdateDomainOrganizationAsync: request JSON: {Json}", json);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("post", fullUrl);
                using var resp = await restClient.PostAsync(apiEndpoint, new StringContent(json, Encoding.UTF8, "application/json"));
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetSubmitUpdateDomainOrganizationAsync: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetSubmitUpdateDomainOrganizationAsync: request failed with status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    throw new HttpRequestException($"GetSubmitUpdateDomainOrganizationAsync failed with HTTP {resp.StatusCode}: {responseContent}");
                }

                var domain = JsonConvert.DeserializeObject<Domain>(responseContent, settings);
                Log.LogTrace("GetSubmitUpdateDomainOrganizationAsync: response JSON: {Json}", JsonConvert.SerializeObject(domain));
                return domain;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitUpdateDomainOrganizationAsync: exception: {Message}", e.Message);
                throw;
            }
        }



        public async Task<Domain> GetSubmitCheckDomainValidationAsync(string domainId)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitCheckDomainValidationAsync: domainId='{DomainId}'", domainId ?? "(null)");

            if (string.IsNullOrEmpty(domainId))
                throw new ArgumentNullException(nameof(domainId), "domainId cannot be null or empty.");

            var apiEndpoint = $"/api/v2/domains/{domainId}/validate";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitCheckDomainValidationAsync: API Url={Url}", fullUrl);

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };

            try
            {
                var restClient = ConfigureRestClient("get", fullUrl);
                using var resp = await restClient.GetAsync(apiEndpoint);
                var responseContent = await resp.Content.ReadAsStringAsync();

                Log.LogTrace("GetSubmitCheckDomainValidationAsync: HTTP status={StatusCode}, response length={Len}",
                    resp.StatusCode, responseContent?.Length ?? 0);

                if (!resp.IsSuccessStatusCode)
                {
                    Log.LogError("GetSubmitCheckDomainValidationAsync: request failed with status {StatusCode}: {Response}", resp.StatusCode, responseContent);
                    throw new HttpRequestException($"GetSubmitCheckDomainValidationAsync failed with HTTP {resp.StatusCode}: {responseContent}");
                }

                var domain = JsonConvert.DeserializeObject<Domain>(responseContent, settings);
                Log.LogTrace("GetSubmitCheckDomainValidationAsync: response JSON: {Json}", JsonConvert.SerializeObject(domain));
                return domain;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitCheckDomainValidationAsync: exception: {Message}", e.Message);
                throw;
            }
        }



        public async Task<Certificate> GetSubmitGetCertificateAsync(string certificateId)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitGetCertificateAsync: certificateId='{CertId}'", certificateId ?? "(null)");

            if (string.IsNullOrEmpty(certificateId))
                throw new ArgumentNullException(nameof(certificateId), "certificateId cannot be null or empty.");

            var apiEndpoint = $"/api/v2/certificates/{certificateId}";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitGetCertificateAsync: API Url={Url}", fullUrl);

            try
            {
                var restClient = ConfigureRestClient("get", fullUrl);
                using var response = await restClient.GetAsync(apiEndpoint);

                var content = await response.Content.ReadAsStringAsync();
                Log.LogTrace("GetSubmitGetCertificateAsync: HTTP status={StatusCode}, response length={Len}",
                    response.StatusCode, content?.Length ?? 0);

                response.EnsureSuccessStatusCode();

                var cert = JsonConvert.DeserializeObject<Certificate>(content);
                if (cert == null)
                {
                    Log.LogWarning("GetSubmitGetCertificateAsync: deserialized certificate is null for ID='{CertId}'", certificateId);
                }

                return cert;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitGetCertificateAsync: exception for certificateId='{CertId}': {Message}", certificateId, e.Message);
                throw;
            }
        }


        public async Task<Certificate> GetSubmitGetCertificateByCsrAsync(string requestTrackingId)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitGetCertificateByCsrAsync: requestTrackingId='{TrackingId}'", requestTrackingId ?? "(null)");

            if (string.IsNullOrEmpty(requestTrackingId))
                throw new ArgumentNullException(nameof(requestTrackingId), "requestTrackingId cannot be null or empty.");

            try
            {
                var apiEndpoint = $"/api/v2/csr/{requestTrackingId}/certificate";
                var fullUrl = BaseUrl + apiEndpoint;
                Log.LogTrace("GetSubmitGetCertificateByCsrAsync: API Url={Url}", fullUrl);

                var restClient = ConfigureRestClient("get", fullUrl);

                using (var resp = await restClient.GetAsync(apiEndpoint))
                {
                    var content = await resp.Content.ReadAsStringAsync();
                    Log.LogTrace("GetSubmitGetCertificateByCsrAsync: HTTP status={StatusCode}, response length={Len}",
                        resp.StatusCode, content?.Length ?? 0);

                    resp.EnsureSuccessStatusCode();

                    var getCertificateResponse = JsonConvert.DeserializeObject<Certificate>(content);
                    if (getCertificateResponse == null)
                    {
                        Log.LogWarning("GetSubmitGetCertificateByCsrAsync: deserialized response is null for trackingId='{TrackingId}'", requestTrackingId);
                    }

                    return getCertificateResponse;
                }
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitGetCertificateByCsrAsync: exception for trackingId='{TrackingId}': {Message}", requestTrackingId, e.Message);
                throw;
            }
        }

        public async Task<CertificateStatus> GetSubmitRevokeCertificateAsync(string hydrantId, RevocationReasons revokeReason)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitRevokeCertificateAsync: hydrantId='{HydrantId}', revokeReason={Reason}", hydrantId ?? "(null)", revokeReason);

            if (string.IsNullOrEmpty(hydrantId))
                throw new ArgumentNullException(nameof(hydrantId), "hydrantId cannot be null or empty.");

            var apiEndpoint = $"/api/v2/certificates/{hydrantId}";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("GetSubmitRevokeCertificateAsync: API Url={Url}", fullUrl);

            var restClient = ConfigureRestClient("patch", fullUrl);
            var revokeRequest = RequestManager.GetRevokeRequest(revokeReason);
            Log.LogTrace("GetSubmitRevokeCertificateAsync: request JSON: {Json}", JsonConvert.SerializeObject(revokeRequest));

            try
            {
                using var response = await restClient.PatchAsync(new Uri(fullUrl), new StringContent(
                    JsonConvert.SerializeObject(revokeRequest), Encoding.UTF8, "application/json"));

                var json = await response.Content.ReadAsStringAsync();
                Log.LogTrace("GetSubmitRevokeCertificateAsync: HTTP status={StatusCode}, response length={Len}",
                    response.StatusCode, json?.Length ?? 0);

                if (!response.IsSuccessStatusCode)
                {
                    Log.LogError("GetSubmitRevokeCertificateAsync: revoke failed with status {StatusCode}: {Response}",
                        response.StatusCode, json);
                    throw new HttpRequestException($"Revoke API call failed with HTTP {response.StatusCode}: {json}");
                }

                var revokeResponse = JsonConvert.DeserializeObject<CertificateStatus>(
                    json,
                    new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

                Log.LogTrace("GetSubmitRevokeCertificateAsync: response JSON: {Json}", JsonConvert.SerializeObject(revokeResponse));
                return revokeResponse;
            }
            catch (Exception e)
            {
                Log.LogError(e, "GetSubmitRevokeCertificateAsync: exception for hydrantId='{HydrantId}': {Message}", hydrantId, e.Message);
                throw;
            }
        }


        public async Task GetSubmitCertificateListRequestAsync(BlockingCollection<ICertificatesResponseItem> bc,
            CancellationToken ct)
        {
            Log.MethodEntry();
            Log.LogTrace("GetSubmitCertificateListRequestAsync: starting certificate list retrieval, pageSize={PageSize}", PageSize);

            try
            {
                var itemsProcessed = 0;
                var pageCounter = 0;
                var isComplete = false;
                var retryCount = 0;
                do
                {
                    Log.LogTrace("GetSubmitCertificateListRequestAsync: pageCounter={PageCounter}, pageSize={PageSize}", pageCounter, PageSize);
                    var queryOrderRequest = RequestManager.GetCertificatesListRequest(pageCounter, PageSize);
                    Log.LogTrace("GetSubmitCertificateListRequestAsync: queryOrderRequest JSON: {Json}", JsonConvert.SerializeObject(queryOrderRequest));
                    var batchItemsProcessed = 0;

                    var apiEndpoint = "/api/v2/certificates";
                    var fullUrl = BaseUrl + apiEndpoint;
                    Log.LogTrace("GetSubmitCertificateListRequestAsync: API Url={Url}", fullUrl);
                    var restClient = ConfigureRestClient("post", fullUrl);

                    using (var resp = await restClient.PostAsync(apiEndpoint, new StringContent(
                        JsonConvert.SerializeObject(queryOrderRequest), Encoding.UTF8, "application/json"), ct))
                    {
                        if (!resp.IsSuccessStatusCode)
                        {
                            var responseMessage = await resp.Content.ReadAsStringAsync();
                            Log.LogError(
                                "GetSubmitCertificateListRequestAsync: request failed. StatusCode={StatusCode}, Message={Message}",
                                resp.StatusCode, responseMessage ?? "(null)");
                            retryCount++;
                            if (retryCount > 5)
                                throw new RetryCountExceededException(
                                    $"5 consecutive failures to {resp.RequestMessage?.RequestUri}");

                            continue;
                        }

                        retryCount = 0;
                        var stringResponse = await resp.Content.ReadAsStringAsync();

                        var batchResponse = JsonConvert.DeserializeObject<CertificatesResponse>(stringResponse);

                        Log.LogTrace("GetSubmitCertificateListRequestAsync: batchResponse is {Null}",
                            batchResponse == null ? "NULL" : "present");

                        if (batchResponse?.Items != null)
                        {
                            var batchCount = batchResponse.Items.Count;
                            Log.LogTrace("GetSubmitCertificateListRequestAsync: processing {Count} items in batch", batchCount);

                            do
                            {
                                var r = batchResponse.Items[batchItemsProcessed];
                                if (r == null)
                                {
                                    Log.LogTrace("GetSubmitCertificateListRequestAsync: skipping null item at index {Index}", batchItemsProcessed);
                                    batchItemsProcessed++;
                                    continue;
                                }

                                if (bc.TryAdd(r, 10, ct))
                                {
                                    Log.LogTrace("GetSubmitCertificateListRequestAsync: added ID={Id} to queue (batch {BatchIdx}/{BatchCount}, total={Total})",
                                        r.Id ?? "(null)", batchItemsProcessed + 1, batchCount, itemsProcessed + 1);
                                    batchItemsProcessed++;
                                    itemsProcessed++;
                                }
                                else
                                {
                                    Log.LogTrace("GetSubmitCertificateListRequestAsync: adding ID={Id} blocked, retrying", r.Id ?? "(null)");
                                }
                            } while (batchItemsProcessed < batchCount);
                        }
                        else
                        {
                            Log.LogWarning("GetSubmitCertificateListRequestAsync: batchResponse or Items is null at pageCounter={PageCounter}", pageCounter);
                        }
                    }

                    if (batchItemsProcessed < PageSize)
                        isComplete = true;
                    pageCounter = pageCounter + PageSize;
                } while (!isComplete);

                Log.LogTrace("GetSubmitCertificateListRequestAsync: completed. Total items processed={Total}", itemsProcessed);

                if (!bc.IsAddingCompleted)
                    bc.CompleteAdding();
            }
            catch (OperationCanceledException cancelEx)
            {
                Log.LogWarning("GetSubmitCertificateListRequestAsync: cancelled. Message={Message}", cancelEx.Message);
                if (!bc.IsAddingCompleted)
                    bc.CompleteAdding();
                throw;
            }
            catch (RetryCountExceededException retryEx)
            {
                Log.LogError(retryEx, "GetSubmitCertificateListRequestAsync: retries exceeded: {Message}", retryEx.Message);
                if (!bc.IsAddingCompleted)
                    bc.CompleteAdding();
                throw;
            }
            catch (HttpRequestException ex)
            {
                Log.LogError(ex, "GetSubmitCertificateListRequestAsync: HTTP request failed: {Message}", ex.Message);
                if (!bc.IsAddingCompleted)
                    bc.CompleteAdding();
                throw;
            }
            catch (Exception ex)
            {
                Log.LogError(ex, "GetSubmitCertificateListRequestAsync: unhandled exception: {Message}", ex.Message);
                if (!bc.IsAddingCompleted)
                    bc.CompleteAdding();
                throw;
            }

            Log.MethodExit();
        }

        public async Task<bool> Ping()
        {
            Log.MethodEntry();

            var apiEndpoint = "/api/v2/policies";
            var fullUrl = BaseUrl + apiEndpoint;
            Log.LogTrace("Ping: API Url={Url}", fullUrl);

            try
            {
                var restClient = ConfigureRestClient("get", fullUrl);
                using var response = await restClient.GetAsync(apiEndpoint);
                var content = await response.Content.ReadAsStringAsync();

                Log.LogTrace("Ping: HTTP status={StatusCode}, response length={Len}", response.StatusCode, content?.Length ?? 0);

                if (!response.IsSuccessStatusCode)
                {
                    Log.LogError("Ping: failed. Status={StatusCode}, Response={Response}", response.StatusCode, content);
                    return false;
                }

                Log.LogTrace("Ping: successful.");
                return true;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Ping: exception: {Message}", e.Message);
                return false;
            }
        }


        private HttpClient ConfigureRestClient(string method, string url)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("ConfigureRestClient: method='{Method}', url='{Url}'", method ?? "(null)", url ?? "(null)");

                if (string.IsNullOrEmpty(method))
                    throw new ArgumentNullException(nameof(method), "HTTP method cannot be null or empty.");
                if (string.IsNullOrEmpty(url))
                    throw new ArgumentNullException(nameof(url), "URL cannot be null or empty.");

                var bUrl = new Uri(BaseUrl);
                ApiId = ConfigProvider.CAConnectionData[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId]?.ToString();

                if (string.IsNullOrEmpty(ApiId))
                {
                    Log.LogError("ConfigureRestClient: ApiId is null or empty after reading from config.");
                    throw new InvalidOperationException("HydrantIdAuthId is null or empty in CAConnectionData.");
                }

                var authKey = ConfigProvider.CAConnectionData[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthKey]?.ToString();
                if (string.IsNullOrEmpty(authKey))
                {
                    Log.LogError("ConfigureRestClient: AuthKey is null or empty after reading from config.");
                    throw new InvalidOperationException("HydrantIdAuthKey is null or empty in CAConnectionData.");
                }

                var credentials = new HawkCredential
                {
                    Id = ApiId,
                    Key = authKey,
                    Algorithm = "sha256"
                };

                var byteArray = new byte[20];
                using (var rnd = RandomNumberGenerator.Create())
                {
                    rnd.GetBytes(byteArray);
                }

                var nOnce = Convert.ToBase64String(byteArray);
                var date = DateTime.Now;
                var ts = Hawk.ConvertToUnixTimestamp(date);
                var mac = Hawk.CalculateMac(bUrl.Host + ":" + bUrl.Port, method, new Uri(url), "",
                    ts.ToString(CultureInfo.InvariantCulture), nOnce, credentials, "header");
                var authorization =
                    $"id=\"{ApiId}\", ts=\"{ts}\", nonce=\"{nOnce}\", mac=\"{mac}\"";

                var clientHandler = _handler ?? new HttpClientHandler();

                var returnClient = new HttpClient(clientHandler, disposeHandler: _handler == null)
                {
                    BaseAddress = bUrl
                };

                returnClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                returnClient.DefaultRequestHeaders.Add("Authorization", "Hawk " + authorization);

                Log.LogTrace("ConfigureRestClient: configured client for {Method} {Url}", method, url);
                return returnClient;
            }
            catch (Exception e)
            {
                Log.LogError(e, "ConfigureRestClient: exception: {Message}", e.Message);
                throw;
            }
        }

    }

}
