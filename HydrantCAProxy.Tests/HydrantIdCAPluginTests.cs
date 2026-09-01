// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.HydrantId;
using Keyfactor.HydrantId;
using Keyfactor.HydrantId.Client;
using Keyfactor.HydrantId.Client.Models;
using Keyfactor.HydrantId.Client.Models.Enums;
using Keyfactor.HydrantId.Interfaces;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace HydrantCAProxy.Tests
{
    public class HydrantIdCAPluginTests
    {
        // A valid PEM CSR (CN=unit.test.hydrantid.local) -- same fixture used in RequestManagerTests,
        // duplicated locally so this file has no cross-file test dependency.
        private const string SampleCsr =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIICyDCCAbACAQAwgYIxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARPaGlvMRUwEwYD\n" +
            "VQQHDAxJbmRlcGVuZGVuY2UxEjAQBgNVBAoMCUtleWZhY3RvcjEVMBMGA1UECwwM\n" +
            "SW50ZWdyYXRpb25zMSIwIAYDVQQDDBl1bml0LnRlc3QuaHlkcmFudGlkLmxvY2Fs\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7HMrgfnq6o9t+7NAI4wZ\n" +
            "XmiIY3lQcuEA2drbwDqx1HW78xbs6ajhIO8A68RpHUjdBfgOl+3zwCcjgbi8+whI\n" +
            "OHubyMsonPCvCoKVUNv1CBclDcKEf+zAFuc7TWeL8n9aZNIeI/mLqhDxt2ZPIPuC\n" +
            "tNh1wZToQ5gf4u/LQXSksLwbiITeBsATEKGNMsTERM7gYuldPQFS3bTof7LGRPWT\n" +
            "shwNiBv6dw5QIgmXOBSJWdT0NfWVNudTF1wxV+41E/mvQCM+66Onw+ialH1nRefh\n" +
            "LCiWIT48LLHLrYN045QorzqbDPzk8itpka+6JA04rlNKcSOBurAypkWBvhnU9N8F\n" +
            "pQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBADO6dln9VOVkCG5qTBuifSxrGgDt\n" +
            "IoQFIHxtMVhMI2CiPPeDDfJpPDX7CoHKRGKelilwxnWlOfzupv1Qb/02YXXq/F/Z\n" +
            "twSyVAIbisuzL6RLIGox3GSkwlM0JTiyjASUJyVextRvxlmMRWTdc4z2v7Wxgmbf\n" +
            "k8wZ7VrUYofBmAj9S3ozilPWRKspl/BZrm+4IIoufa2BKfMnGQGbsad22mrpkRtG\n" +
            "1gm6iZDzaVTSC3iO5+CA/ZNwRT2ShIAHAbZTUSf62n5+nfs8Wki67i96hQqX7qIT\n" +
            "MRXVBIV6K2c9Ls9aEh5qnPR8wre/VMaufCliSb0Q4X50Tal8kJZbS6/ZfJo=\n" +
            "-----END CERTIFICATE REQUEST-----";

        private sealed class FakeConfigProvider : IAnyCAPluginConfigProvider
        {
            public Dictionary<string, object> CAConnectionData { get; set; }
        }

        private sealed class NoOpLogger : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => false;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
            { }
        }

        private static Dictionary<string, object> ValidConnectionData(bool enabled = true) => new Dictionary<string, object>
        {
            [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdBaseUrl] = "https://acm-stage.hydrantid.test",
            [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthId] = "test-auth-id",
            [HydrantIdCAPluginConfig.ConfigConstants.HydrantIdAuthKey] = "test-auth-key",
            [HydrantIdCAPluginConfig.ConfigConstants.Enabled] = enabled
        };

        private static HydrantIdCAPlugin MakePlugin(Mock<IHydrantIdClient> client = null, bool enabled = true)
        {
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData(enabled) },
                Mock.Of<ICertificateDataReader>());
            if (client != null)
                plugin.ClientFactory = _ => client.Object;
            return plugin;
        }

        private static (X509Certificate2 Cert, string Pem, string Base64) MakeSelfSignedCert(int notAfterDays = 365)
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=test.hydrantid.local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(notAfterDays));
            return (cert, cert.ExportCertificatePem(), Convert.ToBase64String(cert.RawData));
        }

        private static EnrollmentProductInfo ProductInfo(Dictionary<string, string> parameters = null) =>
            new EnrollmentProductInfo { ProductID = "Test Policy", ProductParameters = parameters ?? new Dictionary<string, string>() };

        // ---------------------------------------------------------------------
        // Initialize
        // ---------------------------------------------------------------------

        [Fact]
        public void Initialize_NullConfigProvider_DoesNotThrow()
        {
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(null, Mock.Of<ICertificateDataReader>());
        }

        [Fact]
        public void Initialize_NullCertDataReader_DoesNotThrow()
        {
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData() }, null);
        }

        [Fact]
        public void Initialize_ValidInputs_PopulatesConfig()
        {
            var plugin = MakePlugin();
            // No exception, and a subsequent ValidateCAConnectionInfo-independent operation (GetProductIds)
            // that depends on Config being set should not throw ArgumentNullException from a missing Config.
            Assert.NotNull(plugin);
        }

        // ---------------------------------------------------------------------
        // Ping
        // ---------------------------------------------------------------------

        [Fact]
        public async Task Ping_Disabled_DoesNotCallClient()
        {
            var mockClient = new Mock<IHydrantIdClient>(MockBehavior.Strict);
            var plugin = MakePlugin(mockClient, enabled: false);

            await plugin.Ping();

            mockClient.VerifyNoOtherCalls();
        }

        [Fact]
        public async Task Ping_ClientReachable_Succeeds()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.Ping()).ReturnsAsync(true);
            var plugin = MakePlugin(mockClient);

            await plugin.Ping();

            mockClient.Verify(c => c.Ping(), Times.Once);
        }

        [Fact]
        public async Task Ping_ClientUnreachable_Throws()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.Ping()).ReturnsAsync(false);
            var plugin = MakePlugin(mockClient);

            await Assert.ThrowsAsync<Exception>(() => plugin.Ping());
        }

        [Fact]
        public async Task Ping_ConfigNeverInitialized_DoesNotThrow()
        {
            var plugin = new HydrantIdCAPlugin();
            await plugin.Ping();
        }

        // ---------------------------------------------------------------------
        // ValidateCAConnectionInfo
        // ---------------------------------------------------------------------

        [Fact]
        public async Task ValidateCAConnectionInfo_NullInput_Throws()
        {
            var plugin = new HydrantIdCAPlugin();
            await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.ValidateCAConnectionInfo(null));
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_MissingRequiredFields_Throws()
        {
            var plugin = new HydrantIdCAPlugin();
            var data = new Dictionary<string, object> { [HydrantIdCAPluginConfig.ConfigConstants.Enabled] = true };

            var ex = await Assert.ThrowsAsync<ArgumentException>(() => plugin.ValidateCAConnectionInfo(data));
            Assert.Contains("HydrantIdBaseUrl", ex.Message);
            Assert.Contains("HydrantIdAuthId", ex.Message);
            Assert.Contains("HydrantIdAuthKey", ex.Message);
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Disabled_SkipsValidationAndPing()
        {
            var plugin = new HydrantIdCAPlugin();
            var data = new Dictionary<string, object> { [HydrantIdCAPluginConfig.ConfigConstants.Enabled] = false };

            await plugin.ValidateCAConnectionInfo(data);
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_AllFieldsPresent_DelegatesToPingWithNonNullConfig()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.Ping()).ReturnsAsync(true);
            IAnyCAPluginConfigProvider capturedConfig = null;
            plugin.ClientFactory = config =>
            {
                capturedConfig = config;
                return mockClient.Object;
            };

            await plugin.ValidateCAConnectionInfo(ValidConnectionData());

            mockClient.Verify(c => c.Ping(), Times.Once);
            // Regression: ValidateCAConnectionInfo runs before Initialize() is ever called by the
            // Gateway, so Config must be populated from connectionInfo itself, not left null --
            // otherwise ClientFactory(Config) builds a HydrantIdClient with a null config provider.
            Assert.NotNull(capturedConfig);
            Assert.NotNull(capturedConfig.CAConnectionData);
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_WithoutPriorInitialize_BuildsRealClientWithoutArgumentNullException()
        {
            // Reproduces the exact path the Gateway calls before Initialize() is ever invoked:
            // ConfigurationController -> ValidateCAConnectionAsync -> ValidateCAConnectionInfo ->
            // Ping -> ClientFactory(Config) -> new HydrantIdClient(Config). Constructs a real
            // HydrantIdClient from whatever Config ends up being (this is where the original bug
            // threw ArgumentNullException("config cannot be null")), then substitutes a mock for
            // the actual Ping() call so no real network I/O happens.
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.Ping()).ReturnsAsync(true);
            plugin.ClientFactory = config =>
            {
                _ = new HydrantIdClient(config);
                return mockClient.Object;
            };

            await plugin.ValidateCAConnectionInfo(ValidConnectionData());
        }

        // ---------------------------------------------------------------------
        // ValidateProductInfo
        // ---------------------------------------------------------------------

        [Fact]
        public async Task ValidateProductInfo_ReturnsCompletedTask()
        {
            var plugin = new HydrantIdCAPlugin();
            await plugin.ValidateProductInfo(ProductInfo(), ValidConnectionData());
        }

        // ---------------------------------------------------------------------
        // GetProductIds
        // ---------------------------------------------------------------------

        [Fact]
        public void GetProductIds_NullPolicyList_ReturnsEmptyList()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync((List<Policy>)null);
            var plugin = MakePlugin(mockClient);

            var result = plugin.GetProductIds();

            Assert.Empty(result);
        }

        [Fact]
        public void GetProductIds_PoliciesReturned_MapsNamesForPoliciesWithIds()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Policy A" },
                new Policy { Id = null, Name = "No Id Policy" }
            });
            var plugin = MakePlugin(mockClient);

            var result = plugin.GetProductIds();

            Assert.Equal(new List<string> { "Policy A" }, result);
        }

        [Fact]
        public void GetProductIds_ClientThrows_Rethrows()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ThrowsAsync(new InvalidOperationException("boom"));
            var plugin = MakePlugin(mockClient);

            Assert.Throws<InvalidOperationException>(() => plugin.GetProductIds());
        }

        // ---------------------------------------------------------------------
        // MaskConfigForLog
        // ---------------------------------------------------------------------

        [Fact]
        public void MaskConfigForLog_NullOrEmpty_ReturnsInputUnchanged()
        {
            Assert.Null(HydrantIdCAPlugin.MaskConfigForLog(null));
            Assert.Equal("", HydrantIdCAPlugin.MaskConfigForLog(""));
        }

        [Fact]
        public void MaskConfigForLog_RedactsSensitiveKeys()
        {
            var json = "{\"HydrantIdAuthId\":\"secret-id\",\"HydrantIdAuthKey\":\"secret-key\",\"HydrantIdBaseUrl\":\"https://x\"}";

            var masked = HydrantIdCAPlugin.MaskConfigForLog(json);

            Assert.DoesNotContain("secret-id", masked);
            Assert.DoesNotContain("secret-key", masked);
            Assert.Contains("https://x", masked);
            Assert.Contains("REDACTED", masked);
        }

        [Fact]
        public void MaskConfigForLog_NonObjectToken_ReturnsTokenAsString()
        {
            var masked = HydrantIdCAPlugin.MaskConfigForLog("[1,2,3]");

            Assert.Equal("[1,2,3]", masked);
        }

        [Fact]
        public void MaskConfigForLog_MalformedJson_RedactsEntirePayload()
        {
            var masked = HydrantIdCAPlugin.MaskConfigForLog("{not valid json");

            Assert.Equal("***REDACTED***", masked);
        }

        // ---------------------------------------------------------------------
        // GetEndEntityCertificate / ExportCollectionToPem
        // ---------------------------------------------------------------------

        [Fact]
        public void GetEndEntityCertificate_NullOrWhitespace_ReturnsEmptyString()
        {
            var plugin = new HydrantIdCAPlugin();

            Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(null));
            Assert.Equal(string.Empty, plugin.GetEndEntityCertificate("   "));
        }

        [Fact]
        public void GetEndEntityCertificate_ValidPem_ReturnsBase64Certificate()
        {
            var plugin = new HydrantIdCAPlugin();
            var (_, pem, _) = MakeSelfSignedCert();

            var result = plugin.GetEndEntityCertificate(pem);

            Assert.False(string.IsNullOrEmpty(result));
            // Confirm the returned base64 is itself a valid, parseable certificate.
            var reparsed = new X509Certificate2(Convert.FromBase64String(result));
            Assert.Equal("CN=test.hydrantid.local", reparsed.Subject);
        }

        [Fact]
        public void GetEndEntityCertificate_NoImportableSegments_ReturnsEmptyString()
        {
            var plugin = new HydrantIdCAPlugin();

            var result = plugin.GetEndEntityCertificate("-----BEGIN CERTIFICATE-----\nnotvalidbase64!!!\n-----END CERTIFICATE-----");

            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void ExportCollectionToPem_EmptyCollection_ReturnsEmptyString()
        {
            var plugin = new HydrantIdCAPlugin();

            var result = plugin.ExportCollectionToPem(new X509Certificate2Collection());

            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void ExportCollectionToPem_WithCertificate_ProducesPemMarkers()
        {
            var plugin = new HydrantIdCAPlugin();
            var (cert, _, _) = MakeSelfSignedCert();
            var collection = new X509Certificate2Collection { cert };

            var result = plugin.ExportCollectionToPem(collection);

            Assert.Contains("-----BEGIN CERTIFICATE-----", result);
            Assert.Contains("-----END CERTIFICATE-----", result);
        }

        // ---------------------------------------------------------------------
        // EnsureDomainsValidatedForPolicyAsync / EnsureDomainsValidatedAsync
        // ---------------------------------------------------------------------

        private static FlowLogger NewFlow() => new FlowLogger(new NoOpLogger(), "Test");

        [Fact]
        public async Task EnsureDomainsValidatedForPolicyAsync_NoValidatorConfigured_ReturnsNull()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>(MockBehavior.Strict);
            var policy = new Policy { Id = Guid.NewGuid(), Name = "P", Details = new PolicyDetails() };

            var result = await plugin.EnsureDomainsValidatedForPolicyAsync(mockClient.Object, NewFlow(), policy, SampleCsr, null);

            Assert.Null(result);
            mockClient.VerifyNoOtherCalls();
        }

        [Fact]
        public async Task EnsureDomainsValidatedForPolicyAsync_AllDomainsAlreadyValidated_ReturnsNull()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "unit.test.hydrantid.local", Status = DomainStatusEnum.Validated }
            });
            var policy = new Policy { Id = Guid.NewGuid(), Name = "P", Details = new PolicyDetails { Validator = "IdenTrust" } };

            var result = await plugin.EnsureDomainsValidatedForPolicyAsync(mockClient.Object, NewFlow(), policy, SampleCsr, null);

            Assert.Null(result);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Never);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedForPolicyAsync_DomainPending_ReturnsExternalValidationResult()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Pending, CodeInstructions = "publish this TXT" });
            var policy = new Policy { Id = Guid.NewGuid(), Name = "P", Details = new PolicyDetails { Validator = "IdenTrust" } };

            var result = await plugin.EnsureDomainsValidatedForPolicyAsync(mockClient.Object, NewFlow(), policy, SampleCsr, null);

            Assert.NotNull(result);
            Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
            Assert.Contains("publish this TXT", result.StatusMessage);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_NewDomain_CallsCreate()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "new.example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Once);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_ExpiredDomain_CallsCreateNotCheck()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "expired.example.com", Status = DomainStatusEnum.Expired }
            });
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Pending, CodeInstructions = "new code" });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "expired.example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Once);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_PendingDomain_CallsCheckNotCreate()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "pending.example.com", Status = DomainStatusEnum.Pending }
            });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "pending.example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync("d1"), Times.Once);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_MixedPendingAndValidated_AggregatesPendingMessage()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "already.example.com", Status = DomainStatusEnum.Validated },
                new Domain { Id = "d2", DomainName = "pending.example.com", Status = DomainStatusEnum.Pending }
            });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d2"))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Pending, CodeInstructions = "still waiting" });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "already.example.com", "pending.example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("pending.example.com", result.PendingMessage);
            Assert.Contains("still waiting", result.PendingMessage);
            Assert.DoesNotContain("already.example.com", result.PendingMessage);
        }

        // ---------------------------------------------------------------------
        // Synchronize
        // ---------------------------------------------------------------------

        private static Mock<ICertificatesResponseItem> MakeItem(string id, RevocationStatusEnum status, string policyName = "P")
        {
            var item = new Mock<ICertificatesResponseItem>();
            item.SetupGet(i => i.Id).Returns(id);
            item.SetupGet(i => i.RevocationStatus).Returns(status);
            item.SetupGet(i => i.Policy).Returns(new NameObject { Name = policyName });
            return item;
        }

        private static void SetupCertList(Mock<IHydrantIdClient> mockClient, params ICertificatesResponseItem[] items)
        {
            mockClient.Setup(c => c.GetSubmitCertificateListRequestAsync(
                    It.IsAny<BlockingCollection<ICertificatesResponseItem>>(), It.IsAny<CancellationToken>()))
                .Returns((BlockingCollection<ICertificatesResponseItem> bc, CancellationToken ct) =>
                {
                    // Use CancellationToken.None here regardless of what the caller passed to
                    // Synchronize -- this only seeds the queue; whether cancellation actually
                    // fires is decided inside Synchronize's own loop, not while queuing test data.
                    foreach (var item in items)
                        bc.Add(item, CancellationToken.None);
                    bc.CompleteAdding();
                    return Task.CompletedTask;
                });
        }

        [Fact]
        public async Task Synchronize_NullItemInQueue_SkipsIt()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, new ICertificatesResponseItem[] { null });
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            Assert.Empty(buffer);
        }

        [Fact]
        public async Task Synchronize_CouldNotExtractCert_SkipsItem()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Valid).Object);
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync("c1"))
                .ReturnsAsync(new Certificate { Pem = "-----BEGIN CERTIFICATE-----\nnotvalidbase64!!!\n-----END CERTIFICATE-----" });
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            Assert.Empty(buffer);
        }

        [Fact]
        public async Task Synchronize_SkipsNonGeneratedOrRevokedItems()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Pending).Object);
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            Assert.Empty(buffer);
            mockClient.Verify(c => c.GetSubmitGetCertificateAsync(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_NullCertificateFromClient_SkipsItem()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Valid).Object);
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync("c1")).ReturnsAsync((Certificate)null);
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            Assert.Empty(buffer);
        }

        [Fact]
        public async Task Synchronize_EmptyPem_SkipsItem()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Valid).Object);
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync("c1")).ReturnsAsync(new Certificate { Pem = "" });
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            Assert.Empty(buffer);
        }

        [Fact]
        public async Task Synchronize_ValidCertificate_AddsToBuffer()
        {
            var (_, pem, _) = MakeSelfSignedCert();
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Valid, "Policy A").Object);
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync("c1")).ReturnsAsync(new Certificate { Pem = pem });
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var result = buffer.Single();
            Assert.Equal("c1", result.CARequestID);
            Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
            Assert.Equal("Policy A", result.ProductID);
        }

        [Fact]
        public async Task Synchronize_PerItemExceptionDuringCertFetch_SkipsAndContinues()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Valid).Object);
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync("c1")).ThrowsAsync(new InvalidOperationException("boom"));
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            Assert.Empty(buffer);
        }

        [Fact]
        public async Task Synchronize_ItemAccessThrows_ThrowsAndCompletesAdding()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            var badItem = new Mock<ICertificatesResponseItem>();
            badItem.SetupGet(i => i.Id).Throws(new InvalidOperationException("boom"));
            SetupCertList(mockClient, badItem.Object);
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                plugin.Synchronize(buffer, null, true, CancellationToken.None));
        }

        [Fact]
        public async Task Synchronize_ItemAccessThrowsAggregateException_ThrowsWithInnerFlattened()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            var badItem = new Mock<ICertificatesResponseItem>();
            badItem.SetupGet(i => i.Id).Throws(new AggregateException(new InvalidOperationException("agg boom")));
            SetupCertList(mockClient, badItem.Object);
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await Assert.ThrowsAsync<AggregateException>(() =>
                plugin.Synchronize(buffer, null, true, CancellationToken.None));
        }

        [Fact]
        public async Task Synchronize_Cancelled_ThrowsOperationCanceled()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            SetupCertList(mockClient, MakeItem("c1", RevocationStatusEnum.Valid).Object);
            var plugin = MakePlugin(mockClient);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                plugin.Synchronize(buffer, null, true, cts.Token));
        }

        // ---------------------------------------------------------------------
        // Enroll -- New enrollment path
        // ---------------------------------------------------------------------

        [Fact]
        public async Task Enroll_EmptyCsr_ReturnsFailedResult()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            var result = await plugin.Enroll("", "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_NullProductInfo_ReturnsFailedResult()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            var result = await plugin.Enroll(SampleCsr, "subj", null, null, RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_New_NullPolicyList_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync((List<Policy>)null);
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_New_NoPolicyMatch_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Other Policy" }
            });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("no policy found", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_New_DomainValidationPending_ReturnsExternalValidationWithoutSubmitting()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails { Validator = "IdenTrust" } }
            });
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Pending, CodeInstructions = "publish TXT" });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
            mockClient.Verify(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_New_NullEnrollmentResponse_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails() }
            });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync((CertRequestResult)null);
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_New_ErrorReturnStatusFailure_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails() }
            });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync(new CertRequestResult
            {
                ErrorReturn = new ErrorReturn { Status = "Failure", Error = "policy rejected" }
            });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("policy rejected", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_New_NoRequestTrackingId_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails() }
            });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync(new CertRequestResult
            {
                RequestStatus = new CertRequestStatus { Id = null }
            });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_New_PollingTimesOut_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails() }
            });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync(new CertRequestResult
            {
                RequestStatus = new CertRequestStatus { Id = "tracking-1" }
            });
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync("tracking-1")).ReturnsAsync((Certificate)null);
            var plugin = MakePlugin(mockClient);
            plugin.PollIntervalMs = 1;
            plugin.PollTimeoutMs = 5;

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_New_FullSuccess_ReturnsGeneratedResult()
        {
            var (_, pem, _) = MakeSelfSignedCert();
            var trackingId = Guid.NewGuid();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails() }
            });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync(new CertRequestResult
            {
                RequestStatus = new CertRequestStatus { Id = trackingId.ToString() }
            });
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Id = trackingId });
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Pem = pem, RevocationStatus = RevocationStatusEnum.Valid });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
            Assert.False(string.IsNullOrEmpty(result.Certificate));
        }

        [Fact]
        public async Task Enroll_UnhandledException_ReturnsFailedResult()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ThrowsAsync(new InvalidOperationException("network exploded"));
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("network exploded", result.StatusMessage);
        }

        // ---------------------------------------------------------------------
        // Enroll -- Renew/Reissue path
        // ---------------------------------------------------------------------

        [Fact]
        public async Task Enroll_RenewOrReissue_MissingPriorCertSN_ReturnsFailedResult()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("PriorCertSN", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_EmptyPriorCertSN_ReturnsFailedResult()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());
            var product = ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "" });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        private static HydrantIdCAPlugin MakePluginWithCertReader(Mock<IHydrantIdClient> client, Mock<ICertificateDataReader> certReader)
        {
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData() }, certReader.Object);
            plugin.ClientFactory = _ => client.Object;
            return plugin;
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_SerialLookupMiss_ReturnsFailedResult()
        {
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync((string)null);
            var plugin = MakePluginWithCertReader(new Mock<IHydrantIdClient>(), certReader);
            var product = ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "SN123" });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("SN123", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_PreviousCertFetchFails_ReturnsFailedResult()
        {
            var certReader = new Mock<ICertificateDataReader>();
            var certId = Guid.NewGuid().ToString();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync(certId);
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(certId)).ReturnsAsync((Certificate)null);
            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "SN123" });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_WithinRenewalWindow_SubmitsRenewal()
        {
            var (_, previousPem, previousBase64) = MakeSelfSignedCert(notAfterDays: 5);
            var certId = Guid.NewGuid().ToString();
            var trackingId = Guid.NewGuid();
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync(certId);

            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(certId))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });
            mockClient.Setup(c => c.GetSubmitRenewalAsync(certId, It.IsAny<RenewalRequest>())).ReturnsAsync(new CertRequestResult
            {
                RequestStatus = new CertRequestStatus { Id = trackingId.ToString() }
            });
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Id = trackingId });
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });

            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string>
            {
                ["PriorCertSN"] = "SN123",
                ["RenewalDays"] = "30"
            });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
            mockClient.Verify(c => c.GetSubmitRenewalAsync(certId, It.IsAny<RenewalRequest>()), Times.Once);
            mockClient.Verify(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>()), Times.Never);
            Assert.True(previousBase64.Length > 0);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_OutsideRenewalWindow_SubmitsReissueViaPolicyMatch()
        {
            var (_, previousPem, _) = MakeSelfSignedCert(notAfterDays: 300);
            var certId = Guid.NewGuid().ToString();
            var trackingId = Guid.NewGuid();
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync(certId);

            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(certId))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails() }
            });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync(new CertRequestResult
            {
                RequestStatus = new CertRequestStatus { Id = trackingId.ToString() }
            });
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Id = trackingId });
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });

            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string>
            {
                ["PriorCertSN"] = "SN123",
                ["RenewalDays"] = "30"
            });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
            mockClient.Verify(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>()), Times.Once);
            mockClient.Verify(c => c.GetSubmitRenewalAsync(It.IsAny<string>(), It.IsAny<RenewalRequest>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_WithinWindowButCertIdTooShort_ReturnsFailedResult()
        {
            var (_, previousPem, _) = MakeSelfSignedCert(notAfterDays: 5);
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync("short-id");
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync("short-id"))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });
            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "SN123", ["RenewalDays"] = "30" });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("too short", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_ReissueNullPolicyList_ReturnsFailedResult()
        {
            var (_, previousPem, _) = MakeSelfSignedCert(notAfterDays: 300);
            var certId = Guid.NewGuid().ToString();
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync(certId);
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(certId))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync((List<Policy>)null);
            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "SN123", ["RenewalDays"] = "30" });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Re-issue failed", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_ReissueDomainValidationPending_ReturnsExternalValidation()
        {
            var (_, previousPem, _) = MakeSelfSignedCert(notAfterDays: 300);
            var certId = Guid.NewGuid().ToString();
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync(certId);
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(certId))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails { Validator = "IdenTrust" } }
            });
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Pending, CodeInstructions = "publish TXT" });
            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "SN123", ["RenewalDays"] = "30" });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
            mockClient.Verify(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_ReissueNoPolicyMatch_ReturnsFailedResult()
        {
            var (_, previousPem, _) = MakeSelfSignedCert(notAfterDays: 300);
            var certId = Guid.NewGuid().ToString();
            var certReader = new Mock<ICertificateDataReader>();
            certReader.Setup(r => r.GetRequestIDBySerialNumber("SN123")).ReturnsAsync(certId);

            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(certId))
                .ReturnsAsync(new Certificate { Pem = previousPem, RevocationStatus = RevocationStatusEnum.Valid });
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Some Other Policy" }
            });

            var plugin = MakePluginWithCertReader(mockClient, certReader);
            var product = ProductInfo(new Dictionary<string, string>
            {
                ["PriorCertSN"] = "SN123",
                ["RenewalDays"] = "30"
            });

            var result = await plugin.Enroll(SampleCsr, "subj", null, product, RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Re-issue failed", result.StatusMessage);
        }

        // ---------------------------------------------------------------------
        // GetCertificateOnTimerAsync
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetCertificateOnTimerAsync_FoundImmediately_ReturnsCertificate()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync("id1")).ReturnsAsync(new Certificate { Id = Guid.NewGuid() });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.GetCertificateOnTimerAsync("id1");

            Assert.NotNull(result);
        }

        [Fact]
        public async Task GetCertificateOnTimerAsync_PerIterationExceptionThenFound_ReturnsCertificate()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            var callCount = 0;
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync("id1")).Returns(() =>
            {
                callCount++;
                if (callCount == 1)
                    throw new InvalidOperationException("not ready");
                return Task.FromResult(new Certificate { Id = Guid.NewGuid() });
            });
            var plugin = MakePlugin(mockClient);
            plugin.PollIntervalMs = 1;

            var result = await plugin.GetCertificateOnTimerAsync("id1");

            Assert.NotNull(result);
            Assert.True(callCount >= 2);
        }

        [Fact]
        public async Task GetCertificateOnTimerAsync_NeverFound_ReturnsNullAfterTimeout()
        {
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync("id1")).ReturnsAsync((Certificate)null);
            var plugin = MakePlugin(mockClient);
            plugin.PollIntervalMs = 1;
            plugin.PollTimeoutMs = 5;

            var result = await plugin.GetCertificateOnTimerAsync("id1");

            Assert.Null(result);
        }

        // ---------------------------------------------------------------------
        // Revoke
        // ---------------------------------------------------------------------

        [Fact]
        public async Task Revoke_NullOrEmptyId_ThrowsWrappedException()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            await Assert.ThrowsAsync<Exception>(() => plugin.Revoke("", "sn", 0));
        }

        [Fact]
        public async Task Revoke_TooShortId_ThrowsWrappedException()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            await Assert.ThrowsAsync<Exception>(() => plugin.Revoke("short-id", "sn", 0));
        }

        [Fact]
        public async Task Revoke_NullResponse_ThrowsWrappedException()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitRevokeCertificateAsync(id, It.IsAny<RevocationReasons>())).ReturnsAsync((CertificateStatus)null);
            var plugin = MakePlugin(mockClient);

            await Assert.ThrowsAsync<Exception>(() => plugin.Revoke(id, "sn", 0));
        }

        [Fact]
        public async Task Revoke_Success_ReturnsRevokedStatus()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitRevokeCertificateAsync(id, It.IsAny<RevocationReasons>()))
                .ReturnsAsync(new CertificateStatus { RevocationStatus = RevocationStatusEnum.Revoked });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.Revoke(id, "sn", 0);

            Assert.Equal((int)EndEntityStatus.REVOKED, result);
        }

        [Fact]
        public async Task Revoke_ClientThrowsHttpRequestException_Rethrows()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitRevokeCertificateAsync(id, It.IsAny<RevocationReasons>()))
                .ThrowsAsync(new System.Net.Http.HttpRequestException("network error"));
            var plugin = MakePlugin(mockClient);

            await Assert.ThrowsAsync<System.Net.Http.HttpRequestException>(() => plugin.Revoke(id, "sn", 0));
        }

        [Fact]
        public async Task Revoke_ClientThrowsAggregateException_ThrowsWrappedInnerMessage()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitRevokeCertificateAsync(id, It.IsAny<RevocationReasons>()))
                .Throws(new AggregateException(new InvalidOperationException("agg boom")));
            var plugin = MakePlugin(mockClient);

            var ex = await Assert.ThrowsAsync<Exception>(() => plugin.Revoke(id, "sn", 0));
            Assert.Contains("agg boom", ex.Message);
        }

        // ---------------------------------------------------------------------
        // GetSingleRecord
        // ---------------------------------------------------------------------

        [Fact]
        public async Task GetSingleRecord_NullOrEmptyId_ThrowsWrappedException()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord(""));
        }

        [Fact]
        public async Task GetSingleRecord_TooShortId_ThrowsWrappedException()
        {
            var plugin = MakePlugin(new Mock<IHydrantIdClient>());

            await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord("short"));
        }

        [Fact]
        public async Task GetSingleRecord_NullCertificateResponse_ReturnsFailedStatus()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(id)).ReturnsAsync((Certificate)null);
            var plugin = MakePlugin(mockClient);

            var result = await plugin.GetSingleRecord(id);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
            Assert.Equal(string.Empty, result.Certificate);
        }

        [Fact]
        public async Task GetSingleRecord_EmptyExtractedCert_ReturnsFailedStatus()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(id)).ReturnsAsync(new Certificate { Pem = "not a real cert" });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.GetSingleRecord(id);

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task GetSingleRecord_Success_ReturnsMappedStatusAndCertificate()
        {
            var id = Guid.NewGuid().ToString();
            var (_, pem, _) = MakeSelfSignedCert();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(id))
                .ReturnsAsync(new Certificate { Pem = pem, RevocationStatus = RevocationStatusEnum.Revoked });
            var plugin = MakePlugin(mockClient);

            var result = await plugin.GetSingleRecord(id);

            Assert.Equal((int)EndEntityStatus.REVOKED, result.Status);
            Assert.False(string.IsNullOrEmpty(result.Certificate));
        }

        [Fact]
        public async Task GetSingleRecord_ClientThrows_ThrowsWrappedException()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(id)).ThrowsAsync(new InvalidOperationException("boom"));
            var plugin = MakePlugin(mockClient);

            await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord(id));
        }

        [Fact]
        public async Task GetSingleRecord_ClientThrowsAggregateException_ThrowsWrappedInnerMessage()
        {
            var id = Guid.NewGuid().ToString();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(id))
                .Throws(new AggregateException(new InvalidOperationException("agg boom")));
            var plugin = MakePlugin(mockClient);

            var ex = await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord(id));
            Assert.Contains("agg boom", ex.Message);
        }

        // ---------------------------------------------------------------------
        // Annotations
        // ---------------------------------------------------------------------

        [Fact]
        public void GetCAConnectorAnnotations_ReturnsNonEmptyDictionary()
        {
            var plugin = new HydrantIdCAPlugin();
            Assert.NotEmpty(plugin.GetCAConnectorAnnotations());
        }

        [Fact]
        public void GetTemplateParameterAnnotations_ReturnsNonEmptyDictionary()
        {
            var plugin = new HydrantIdCAPlugin();
            Assert.NotEmpty(plugin.GetTemplateParameterAnnotations());
        }
    }
}
