// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.HydrantId;
using Keyfactor.HydrantId.Client;
using Keyfactor.HydrantId.Client.Models;
using Keyfactor.HydrantId.Client.Models.Enums;
using Keyfactor.HydrantId.Exceptions;
using Keyfactor.HydrantId.Interfaces;
using Xunit;

namespace HydrantCAProxy.Tests
{
    public class HydrantIdClientTests
    {
        private sealed class FakeConfigProvider : IAnyCAPluginConfigProvider
        {
            public Dictionary<string, object> CAConnectionData { get; set; }
        }

        private sealed class FakeHttpMessageHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, string, HttpResponseMessage> _responder;

            public FakeHttpMessageHandler(Func<HttpRequestMessage, string, HttpResponseMessage> responder)
            {
                _responder = responder;
            }

            public HttpRequestMessage LastRequest { get; private set; }
            public string LastRequestBody { get; private set; }
            public int CallCount { get; private set; }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CallCount++;
                LastRequest = request;
                LastRequestBody = request.Content != null ? await request.Content.ReadAsStringAsync(cancellationToken) : null;
                return _responder(request, LastRequestBody);
            }
        }

        private static HttpResponseMessage JsonResponse(HttpStatusCode status, string json) =>
            new HttpResponseMessage(status) { Content = new StringContent(json ?? string.Empty, Encoding.UTF8, "application/json") };

        private static IAnyCAPluginConfigProvider ValidConfig(string baseUrl = "https://acm-stage.hydrantid.test") =>
            new FakeConfigProvider
            {
                CAConnectionData = new Dictionary<string, object>
                {
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdBaseUrl] = baseUrl,
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId] = "test-auth-id",
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthKey] = "test-auth-key"
                }
            };

        private static HydrantIdClient MakeClient(
            Func<HttpRequestMessage, string, HttpResponseMessage> responder,
            out FakeHttpMessageHandler handler,
            IAnyCAPluginConfigProvider config = null)
        {
            handler = new FakeHttpMessageHandler(responder);
            return new HydrantIdClient(config ?? ValidConfig(), handler);
        }

        // ---------------------------------------------------------------------
        // Constructor validation
        // ---------------------------------------------------------------------

        [Fact]
        public void Constructor_NullConfig_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new HydrantIdClient(null));
        }

        [Fact]
        public void Constructor_NullConnectionData_Throws()
        {
            var config = new FakeConfigProvider { CAConnectionData = null };
            Assert.Throws<ArgumentNullException>(() => new HydrantIdClient(config));
        }

        [Fact]
        public void Constructor_MissingAuthIdKey_Throws()
        {
            var config = new FakeConfigProvider { CAConnectionData = new Dictionary<string, object>() };
            Assert.Throws<InvalidOperationException>(() => new HydrantIdClient(config));
        }

        [Fact]
        public void Constructor_EmptyBaseUrl_Throws()
        {
            var config = new FakeConfigProvider
            {
                CAConnectionData = new Dictionary<string, object>
                {
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId] = "id",
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdBaseUrl] = ""
                }
            };
            Assert.Throws<InvalidOperationException>(() => new HydrantIdClient(config));
        }

        // ---------------------------------------------------------------------
        // ConfigureRestClient / Hawk header construction
        // ---------------------------------------------------------------------

        [Fact]
        public async Task ConfigureRestClient_BuildsWellFormedHawkAuthorizationHeader()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "[]"), out var handler);

            await client.GetPolicyList();

            var authHeader = handler.LastRequest.Headers.GetValues("Authorization").Single();
            Assert.StartsWith("Hawk ", authHeader);
            Assert.Matches(new Regex("id=\"[^\"]+\", ts=\"\\d+\", nonce=\"[^\"]+\", mac=\"[^\"]+\""), authHeader);
        }

        [Fact]
        public async Task ConfigureRestClient_MissingAuthIdAtCallTime_Throws()
        {
            var config = new FakeConfigProvider
            {
                CAConnectionData = new Dictionary<string, object>
                {
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId] = "id",
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdBaseUrl] = "https://acm-stage.hydrantid.test"
                }
            };
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "[]"), out _, config);
            // Simulate the auth id being cleared out from underlying config after construction.
            config.CAConnectionData[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId] = "";

            await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetPolicyList());
        }

        [Fact]
        public async Task ConfigureRestClient_EmptyAuthKeyAtCallTime_Throws()
        {
            var config = new FakeConfigProvider
            {
                CAConnectionData = new Dictionary<string, object>
                {
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId] = "test-auth-id",
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthKey] = "",
                    [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdBaseUrl] = "https://acm-stage.hydrantid.test"
                }
            };
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "[]"), out _, config);

            await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetPolicyList());
        }

        // ---------------------------------------------------------------------
        // Ping
        // ---------------------------------------------------------------------

        [Fact]
        public async Task Ping_SuccessStatus_ReturnsTrue()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "[]"), out _);

            Assert.True(await client.Ping());
        }

        [Fact]
        public async Task Ping_NonSuccessStatus_ReturnsFalse()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.Unauthorized, "{}"), out _);

            Assert.False(await client.Ping());
        }

        [Fact]
        public async Task Ping_TransportThrows_ReturnsFalse()
        {
            var client = MakeClient((req, body) => throw new HttpRequestException("network down"), out _);

            Assert.False(await client.Ping());
        }

        // ---------------------------------------------------------------------
        // GetPolicyList
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetPolicyList_Success_ReturnsPolicies()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "[{\"id\":\"" + Guid.NewGuid() + "\",\"name\":\"Test Policy\"}]"), out _);

            var result = await client.GetPolicyList();

            Assert.Single(result);
            Assert.Equal("Test Policy", result[0].Name);
        }

        [Fact]
        public async Task GetPolicyList_NullBody_ReturnsEmptyList()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "null"), out _);

            var result = await client.GetPolicyList();

            Assert.Empty(result);
        }

        [Fact]
        public async Task GetPolicyList_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.InternalServerError, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetPolicyList());
        }

        // ---------------------------------------------------------------------
        // GetDomainListAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetDomainListAsync_Success_ReturnsDomains()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "[{\"id\":\"d1\",\"domain\":\"example.com\",\"status\":\"VALIDATED\"}]"), out _);

            var result = await client.GetDomainListAsync();

            Assert.Single(result);
            Assert.Equal(DomainStatusEnum.Validated, result[0].Status);
        }

        [Fact]
        public async Task GetDomainListAsync_NullBody_ReturnsEmptyList()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "null"), out _);

            Assert.Empty(await client.GetDomainListAsync());
        }

        [Fact]
        public async Task GetDomainListAsync_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.BadGateway, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetDomainListAsync());
        }

        // ---------------------------------------------------------------------
        // GetSubmitCreateDomainValidationAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitCreateDomainValidationAsync_NullPayload_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() => client.GetSubmitCreateDomainValidationAsync(null));
        }

        [Fact]
        public async Task GetSubmitCreateDomainValidationAsync_Success_ReturnsDomain()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"id\":\"d1\",\"domain\":\"example.com\",\"status\":\"PENDING\"}"), out var handler);

            var result = await client.GetSubmitCreateDomainValidationAsync(new CreateDomainValidationPayload
            {
                DomainName = "example.com",
                Validator = "IdenTrust",
                Method = ValidationMethod.Dns
            });

            Assert.Equal(DomainStatusEnum.Pending, result.Status);
            Assert.Contains("example.com", handler.LastRequestBody);
        }

        [Fact]
        public async Task GetSubmitCreateDomainValidationAsync_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.Unauthorized, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() =>
                client.GetSubmitCreateDomainValidationAsync(new CreateDomainValidationPayload { DomainName = "x", Validator = "y" }));
        }

        // ---------------------------------------------------------------------
        // GetSubmitCheckDomainValidationAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitCheckDomainValidationAsync_NullOrEmptyId_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() => client.GetSubmitCheckDomainValidationAsync(""));
        }

        [Fact]
        public async Task GetSubmitCheckDomainValidationAsync_Success_ReturnsDomain()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"id\":\"d1\",\"status\":\"EXPIRED\"}"), out _);

            var result = await client.GetSubmitCheckDomainValidationAsync("d1");

            Assert.Equal(DomainStatusEnum.Expired, result.Status);
        }

        [Fact]
        public async Task GetSubmitCheckDomainValidationAsync_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.NotFound, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetSubmitCheckDomainValidationAsync("d1"));
        }

        // ---------------------------------------------------------------------
        // GetSubmitGetCertificateAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitGetCertificateAsync_NullOrEmptyId_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() => client.GetSubmitGetCertificateAsync(null));
        }

        [Fact]
        public async Task GetSubmitGetCertificateAsync_Success_ReturnsCertificate()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"id\":\"" + Guid.NewGuid() + "\",\"pem\":\"PEMDATA\"}"), out _);

            var result = await client.GetSubmitGetCertificateAsync(Guid.NewGuid().ToString());

            Assert.Equal("PEMDATA", result.Pem);
        }

        [Fact]
        public async Task GetSubmitGetCertificateAsync_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.NotFound, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetSubmitGetCertificateAsync("abc"));
        }

        [Fact]
        public async Task GetSubmitGetCertificateAsync_SuccessNullBody_ReturnsNull()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "null"), out _);

            var result = await client.GetSubmitGetCertificateAsync("abc");

            Assert.Null(result);
        }

        // ---------------------------------------------------------------------
        // GetSubmitGetCertificateByCsrAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitGetCertificateByCsrAsync_NullOrEmptyId_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() => client.GetSubmitGetCertificateByCsrAsync(""));
        }

        [Fact]
        public async Task GetSubmitGetCertificateByCsrAsync_Success_ReturnsCertificate()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"pem\":\"PEMDATA\"}"), out _);

            var result = await client.GetSubmitGetCertificateByCsrAsync("tracking-id");

            Assert.Equal("PEMDATA", result.Pem);
        }

        [Fact]
        public async Task GetSubmitGetCertificateByCsrAsync_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.NotFound, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetSubmitGetCertificateByCsrAsync("tracking-id"));
        }

        // ---------------------------------------------------------------------
        // GetSubmitRevokeCertificateAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitRevokeCertificateAsync_NullOrEmptyId_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                client.GetSubmitRevokeCertificateAsync(null, RevocationReasons.Unspecified));
        }

        [Fact]
        public async Task GetSubmitRevokeCertificateAsync_Success_ReturnsStatus()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"id\":\"" + Guid.NewGuid() + "\",\"revocationStatus\":\"REVOKED\"}"), out var handler);

            var result = await client.GetSubmitRevokeCertificateAsync("abc", RevocationReasons.KeyCompromise);

            Assert.Equal(RevocationStatusEnum.Revoked, result.RevocationStatus);
            Assert.Equal(HttpMethod.Patch, handler.LastRequest.Method);
        }

        [Fact]
        public async Task GetSubmitRevokeCertificateAsync_NonSuccess_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.Forbidden, "{}"), out _);

            await Assert.ThrowsAsync<HttpRequestException>(() =>
                client.GetSubmitRevokeCertificateAsync("abc", RevocationReasons.Unspecified));
        }

        // ---------------------------------------------------------------------
        // GetSubmitEnrollmentAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitEnrollmentAsync_NullRequest_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() => client.GetSubmitEnrollmentAsync(null));
        }

        [Fact]
        public async Task GetSubmitEnrollmentAsync_Success_ReturnsRequestStatus()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"id\":\"tracking-1\",\"issuanceStatus\":\"PENDING\"}"), out _);

            var result = await client.GetSubmitEnrollmentAsync(new CertRequestBody { Csr = "csr" });

            Assert.Equal("tracking-1", result.RequestStatus.Id);
            Assert.Null(result.ErrorReturn);
        }

        [Fact]
        public async Task GetSubmitEnrollmentAsync_InternalServerError_ReturnsParsedErrorReturn()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.InternalServerError, "{\"status\":\"Failure\",\"message\":\"boom\"}"), out _);

            var result = await client.GetSubmitEnrollmentAsync(new CertRequestBody { Csr = "csr" });

            Assert.Null(result.RequestStatus);
            Assert.Equal("Failure", result.ErrorReturn.Status);
            Assert.Equal("boom", result.ErrorReturn.Error);
        }

        [Fact]
        public async Task GetSubmitEnrollmentAsync_OtherNonSuccess_ReturnsSyntheticErrorReturn()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.BadRequest, "bad request body"), out _);

            var result = await client.GetSubmitEnrollmentAsync(new CertRequestBody { Csr = "csr" });

            Assert.Null(result.RequestStatus);
            Assert.Equal("Failure", result.ErrorReturn.Status);
            Assert.Contains("BadRequest", result.ErrorReturn.Error);
        }

        // ---------------------------------------------------------------------
        // GetSubmitRenewalAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitRenewalAsync_NullOrEmptyArgs_Throws()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);

            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                client.GetSubmitRenewalAsync("", new RenewalRequest { Csr = "csr" }));
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                client.GetSubmitRenewalAsync("cert-id", null));
        }

        [Fact]
        public async Task GetSubmitRenewalAsync_Success_ReturnsRequestStatus()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"id\":\"tracking-2\",\"issuanceStatus\":\"ISSUED\"}"), out _);

            var result = await client.GetSubmitRenewalAsync("cert-id", new RenewalRequest { Csr = "csr" });

            Assert.Equal("tracking-2", result.RequestStatus.Id);
        }

        [Fact]
        public async Task GetSubmitRenewalAsync_InternalServerError_ReturnsParsedErrorReturn()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.InternalServerError, "{\"status\":\"Failure\",\"message\":\"renew boom\"}"), out _);

            var result = await client.GetSubmitRenewalAsync("cert-id", new RenewalRequest { Csr = "csr" });

            Assert.Equal("renew boom", result.ErrorReturn.Error);
        }

        [Fact]
        public async Task GetSubmitRenewalAsync_OtherNonSuccess_ReturnsSyntheticErrorReturn()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.Conflict, "conflict"), out _);

            var result = await client.GetSubmitRenewalAsync("cert-id", new RenewalRequest { Csr = "csr" });

            Assert.Equal("Failure", result.ErrorReturn.Status);
        }

        // ---------------------------------------------------------------------
        // GetSubmitCertificateListRequestAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_SinglePartialPage_CompletesAfterOnePage()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK,
                    "{\"count\":1,\"items\":[{\"id\":\"c1\",\"commonName\":\"test.local\",\"revocationStatus\":\"VALID\"}]}"),
                out var handler);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);

            await client.GetSubmitCertificateListRequestAsync(bc, CancellationToken.None);

            Assert.True(bc.IsAddingCompleted);
            var items = new List<ICertificatesResponseItem>(bc.GetConsumingEnumerable());
            Assert.Single(items);
            Assert.Equal("c1", items[0].Id);
            Assert.Equal(1, handler.CallCount);
        }

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_NullItems_CompletesWithNoItems()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{\"count\":0}"), out _);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);

            await client.GetSubmitCertificateListRequestAsync(bc, CancellationToken.None);

            Assert.True(bc.IsAddingCompleted);
            Assert.Empty(bc.GetConsumingEnumerable());
        }

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_NullItemInBatch_SkipsIt()
        {
            var client = MakeClient((req, body) =>
                JsonResponse(HttpStatusCode.OK, "{\"count\":1,\"items\":[null]}"), out _);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);

            await client.GetSubmitCertificateListRequestAsync(bc, CancellationToken.None);

            Assert.Empty(bc.GetConsumingEnumerable());
        }

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_RepeatedFailures_ThrowsAfterFiveRetries()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.InternalServerError, "{}"), out var handler);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);

            await Assert.ThrowsAsync<RetryCountExceededException>(() =>
                client.GetSubmitCertificateListRequestAsync(bc, CancellationToken.None));

            Assert.True(bc.IsAddingCompleted);
            Assert.Equal(6, handler.CallCount);
        }

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_TransportThrows_ThrowsHttpRequestExceptionAndCompletesAdding()
        {
            var client = MakeClient((req, body) => throw new HttpRequestException("network down"), out _);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);

            await Assert.ThrowsAsync<HttpRequestException>(() =>
                client.GetSubmitCertificateListRequestAsync(bc, CancellationToken.None));

            Assert.True(bc.IsAddingCompleted);
        }

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_MalformedJson_ThrowsAndCompletesAdding()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "not valid json"), out _);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);

            await Assert.ThrowsAsync<Newtonsoft.Json.JsonReaderException>(() =>
                client.GetSubmitCertificateListRequestAsync(bc, CancellationToken.None));

            Assert.True(bc.IsAddingCompleted);
        }

        [Fact]
        public async Task GetSubmitCertificateListRequestAsync_CancelledToken_ThrowsOperationCanceled()
        {
            var client = MakeClient((req, body) => JsonResponse(HttpStatusCode.OK, "{}"), out _);
            var bc = new BlockingCollection<ICertificatesResponseItem>(10);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                client.GetSubmitCertificateListRequestAsync(bc, cts.Token));

            Assert.True(bc.IsAddingCompleted);
        }
    }
}
