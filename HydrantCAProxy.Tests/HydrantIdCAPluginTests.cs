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

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "new-example.com" }, "IdenTrust");

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
                new Domain { Id = "d1", DomainName = "expired-example.com", Status = DomainStatusEnum.Expired }
            });
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Pending, CodeInstructions = "new code" });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "expired-example.com" }, "IdenTrust");

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
                new Domain { Id = "d1", DomainName = "pending-example.com", Status = DomainStatusEnum.Pending }
            });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "pending-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync("d1"), Times.Once);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_SubdomainOfValidatedParent_SkipsWithoutCreatingRecord()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "keyfactorhydrantid.com", Status = DomainStatusEnum.Validated }
            });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "www.keyfactorhydrantid.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Never);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_SubdomainOfPendingParent_RechecksTheParentInsteadOfCreatingItsOwn()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "keyfactorhydrantid.com", Status = DomainStatusEnum.Pending }
            });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "www.keyfactorhydrantid.com" }, "IdenTrust");

            // The base domain carries the organization link, so its in-flight validation is the
            // one to finish -- creating a second record for the subdomain would produce another
            // record with a null organizationIds.
            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync("d1"), Times.Once);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Never);
        }

        [Theory]
        [InlineData("www.example.com", "example.com", true)]
        [InlineData("a.b.example.com", "example.com", true)]
        [InlineData("example.com", "example.com", true)]
        [InlineData("notexample.com", "example.com", false)]
        [InlineData("example.com.evil.com", "example.com", false)]
        public void IsCoveredByValidatedAncestor_MatchesExpectedScope(string domainName, string validatedDomain, bool expected)
        {
            var existingDomains = new List<Domain> { new Domain { DomainName = validatedDomain, Status = DomainStatusEnum.Validated } };

            var result = HydrantIdCAPlugin.IsCoveredByValidatedAncestor(domainName, existingDomains, out _);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void IsCoveredByValidatedAncestor_SoftDeletedParent_ReturnsFalse()
        {
            var domains = new List<Domain>
            {
                new Domain
                {
                    DomainName = "example.com",
                    Status = DomainStatusEnum.Validated,
                    DeletedAt = "2026-09-01T20:23:52.000Z"
                }
            };

            Assert.False(HydrantIdCAPlugin.IsCoveredByValidatedAncestor("www.example.com", domains, out var covering));
            Assert.Null(covering);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_SoftDeletedPendingRecord_IsIgnoredAndValidationRestarted()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            // A soft-deleted record must not be re-checked: GET /domains/{id}/validate on a deleted
            // id returns HTTP 500 from HydrantId, which would fail the enrollment outright.
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain
                {
                    Id = "deleted-1",
                    DomainName = "gone-example.com",
                    Status = DomainStatusEnum.Pending,
                    DeletedAt = "2026-09-01T20:23:52.000Z"
                }
            });
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Id = "fresh-1", Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "gone-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Once);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_SoftDeletedValidatedRecord_DoesNotCountAsValidated()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain
                {
                    Id = "deleted-1",
                    DomainName = "gone-example.com",
                    Status = DomainStatusEnum.Validated,
                    DeletedAt = "2026-09-01T20:23:52.000Z"
                }
            });
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Id = "fresh-1", Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "gone-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Once);
        }

        [Fact]
        public void IsCoveredByValidatedAncestor_ParentNotValidated_ReturnsFalse()
        {
            var existingDomains = new List<Domain> { new Domain { DomainName = "example.com", Status = DomainStatusEnum.Pending } };

            Assert.False(HydrantIdCAPlugin.IsCoveredByValidatedAncestor("www.example.com", existingDomains, out _));
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_MixedPendingAndValidated_AggregatesPendingMessage()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "already-example.com", Status = DomainStatusEnum.Validated },
                new Domain { Id = "d2", DomainName = "pending-example.com", Status = DomainStatusEnum.Pending }
            });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d2"))
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Pending, CodeInstructions = "still waiting" });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "already-example.com", "pending-example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("pending-example.com", result.PendingMessage);
            Assert.Contains("still waiting", result.PendingMessage);
            Assert.DoesNotContain("already-example.com", result.PendingMessage);
        }

        // ---------------------------------------------------------------------
        // BuildOrgPayload
        // ---------------------------------------------------------------------

        [Fact]
        public void BuildOrgPayload_NoOrgFieldsConfigured_ReturnsNull()
        {
            var plugin = MakePlugin();

            Assert.Null(plugin.BuildOrgPayload());
        }

        [Fact]
        public void BuildOrgPayload_ConfigNeverInitialized_ReturnsNull()
        {
            var plugin = new HydrantIdCAPlugin();

            Assert.Null(plugin.BuildOrgPayload());
        }

        [Fact]
        public void BuildOrgPayload_OneFieldConfigured_ReturnsPopulatedPayload()
        {
            var data = ValidConnectionData();
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdOrgName] = "Acme Corp";
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());

            var payload = plugin.BuildOrgPayload();

            Assert.NotNull(payload);
            Assert.Equal("Acme Corp", payload.OrgName);
            Assert.Null(payload.EmailAddress);
        }

        [Fact]
        public void BuildOrgPayload_AllFieldsConfigured_ReturnsFullyPopulatedPayload()
        {
            var data = ValidConnectionData();
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdOrgName] = "Acme Corp";
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdOrgPrimaryContactFullName] = "Jane Doe";
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdOrgStreetAddress] = "123 Main St";
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdOrgCityProvPostalCodeCountry] = "Anytown, OH 44131, US";
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdEmailAddress] = "jane@acme.com";
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdPhoneNumber] = "+1-555-555-0100";
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());

            var payload = plugin.BuildOrgPayload();

            Assert.Equal("Acme Corp", payload.OrgName);
            Assert.Equal("Jane Doe", payload.OrgPrimaryContactFullName);
            Assert.Equal("123 Main St", payload.OrgStreetAddress);
            Assert.Equal("Anytown, OH 44131, US", payload.OrgCityProvPostalCodeCountry);
            Assert.Equal("jane@acme.com", payload.EmailAddress);
            Assert.Equal("+1-555-555-0100", payload.PhoneNumber);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_OrgPayloadConfigured_IsIncludedInCreateRequest()
        {
            var data = ValidConnectionData();
            data[HydrantIdCAPluginConfig.ConfigConstants.HydrantIdOrgName] = "Acme Corp";
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            CreateDomainValidationPayload capturedPayload = null;
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(p => capturedPayload = p)
                .ReturnsAsync(new Domain { Status = DomainStatusEnum.Validated });
            plugin.ClientFactory = _ => mockClient.Object;

            await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(), new List<string> { "new-example.com" }, "IdenTrust");

            Assert.NotNull(capturedPayload.Payload);
            Assert.IsType<DomainValidationOrgPayload>(capturedPayload.Payload);
            Assert.Equal("Acme Corp", ((DomainValidationOrgPayload)capturedPayload.Payload).OrgName);
        }

        // ---------------------------------------------------------------------
        // DNS provider plugin automation (IDomainValidatorFactory)
        // ---------------------------------------------------------------------

        // Timings that keep these tests instant: no propagation wait, and a budget that allows
        // exactly one status check before timing out.
        private static Dictionary<string, object> FastDnsConnectionData()
        {
            var data = ValidConnectionData();
            data[HydrantIdCAPluginConfig.ConfigConstants.DnsPropagationDelaySeconds] = 0;
            data[HydrantIdCAPluginConfig.ConfigConstants.DomainValidationPollIntervalSeconds] = 1;
            data[HydrantIdCAPluginConfig.ConfigConstants.DomainValidationTimeoutSeconds] = 1;
            return data;
        }

        private static HydrantIdCAPlugin MakePluginWithDnsFactory(
            Mock<IHydrantIdClient> client, IDomainValidatorFactory factory, Dictionary<string, object> data = null)
        {
            var plugin = new HydrantIdCAPlugin(factory);
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = data ?? FastDnsConnectionData() },
                Mock.Of<ICertificateDataReader>());
            if (client != null)
                plugin.ClientFactory = _ => client.Object;
            return plugin;
        }

        private static Mock<IDomainValidator> StubDnsValidator(bool stageSucceeds = true, bool cleanupSucceeds = true)
        {
            var validator = new Mock<IDomainValidator>();
            validator.Setup(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new DomainValidationResult
                {
                    Success = stageSucceeds,
                    ErrorMessage = stageSucceeds ? null : "zone not found"
                });
            validator.Setup(v => v.CleanupValidation(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new DomainValidationResult
                {
                    Success = cleanupSucceeds,
                    ErrorMessage = cleanupSucceeds ? null : "delete failed"
                });
            return validator;
        }

        private static Mock<IDomainValidatorFactory> StubDnsFactory(IDomainValidator validator)
        {
            var factory = new Mock<IDomainValidatorFactory>();
            factory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), HydrantIdCAPlugin.DnsValidationType))
                .Returns(validator);
            return factory;
        }

        // A factory that only answers for one exact domain, mirroring the Gateway's
        // Domains.Domain = @DomainName equality match.
        private static Mock<IDomainValidatorFactory> StubDnsFactoryForDomain(IDomainValidator validator, string domain)
        {
            var factory = new Mock<IDomainValidatorFactory>();
            factory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((IDomainValidator)null);
            factory.Setup(f => f.ResolveDomainValidator(domain, HydrantIdCAPlugin.DnsValidationType))
                .Returns(validator);
            return factory;
        }

        // ---------------------------------------------------------------------
        // Validation target selection (base domain, with FQDN fallback)
        // ---------------------------------------------------------------------

        [Theory]
        [InlineData("keyfactorluadns.com", "keyfactorluadns.com")]
        [InlineData("brian1.keyfactorluadns.com", "keyfactorluadns.com")]
        [InlineData("a.b.c.keyfactorluadns.com", "keyfactorluadns.com")]
        [InlineData("*.keyfactorluadns.com", "keyfactorluadns.com")]
        [InlineData("brian1.keyfactorluadns.com.", "keyfactorluadns.com")]
        [InlineData("  brian1.keyfactorluadns.com  ", "keyfactorluadns.com")]
        [InlineData("WWW.Example.COM", "Example.COM")]
        // Multi-label public suffixes must not collapse to something unregistrable.
        [InlineData("example.co.uk", "example.co.uk")]
        [InlineData("www.example.co.uk", "example.co.uk")]
        [InlineData("a.b.example.co.uk", "example.co.uk")]
        [InlineData("co.uk", "co.uk")]
        [InlineData("example.com.au", "example.com.au")]
        [InlineData("host.example.com.au", "example.com.au")]
        // Single-label and empty inputs pass through rather than throwing.
        [InlineData("localhost", "localhost")]
        [InlineData("", null)]
        [InlineData(null, null)]
        public void GetBaseDomain_ReturnsRegistrableBase(string input, string expected)
        {
            Assert.Equal(expected, HydrantIdCAPlugin.GetBaseDomain(input));
        }

        [Fact]
        public void GetValidationTargets_Subdomain_PrefersBaseDomainThenFqdn()
        {
            var targets = HydrantIdCAPlugin.GetValidationTargets("brian1.keyfactorluadns.com");

            Assert.Equal(new[] { "keyfactorluadns.com", "brian1.keyfactorluadns.com" }, targets);
        }

        [Fact]
        public void GetValidationTargets_AlreadyBaseDomain_ReturnsSingleTarget()
        {
            var targets = HydrantIdCAPlugin.GetValidationTargets("keyfactorluadns.com");

            Assert.Equal(new[] { "keyfactorluadns.com" }, targets);
        }

        [Fact]
        public void GetValidationTargets_EmptyInput_ReturnsNoTargets()
        {
            Assert.Empty(HydrantIdCAPlugin.GetValidationTargets(null));
            Assert.Empty(HydrantIdCAPlugin.GetValidationTargets("   "));
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_Subdomain_ValidatesTheBaseDomain()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            CreateDomainValidationPayload captured = null;
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(pl => captured = pl)
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "brian1.keyfactorluadns.com" }, "IdenTrust");

            // HydrantId links the vetted organization to the base domain only.
            Assert.True(result.AllValidated);
            Assert.Equal("keyfactorluadns.com", captured.DomainName);
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Once);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_BaseDomainRejected_FallsBackToTheFqdn()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            var attempted = new List<string>();
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(pl => attempted.Add(pl.DomainName))
                .Returns((CreateDomainValidationPayload pl) => pl.DomainName == "example.invalid"
                    ? throw new InvalidOperationException("HTTP 400: domain not registrable")
                    : Task.FromResult(new Domain { Id = "d1", Status = DomainStatusEnum.Validated }));

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "host.example.invalid" }, "IdenTrust");

            Assert.True(result.AllValidated);
            Assert.Equal(new[] { "example.invalid", "host.example.invalid" }, attempted);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_AllTargetsRejected_ReportsPendingWithTheError()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ThrowsAsync(new InvalidOperationException("HTTP 400: domain not permitted"));

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "host.example.invalid" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("domain not permitted", result.PendingMessage);
            // Both candidates attempted before giving up, and the failure is reported rather than thrown.
            mockClient.Verify(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()), Times.Exactly(2));
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_OneDomainRejected_OtherDomainsStillProgress()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Returns((CreateDomainValidationPayload pl) => pl.DomainName.EndsWith(".invalid")
                    ? throw new InvalidOperationException("HTTP 400: domain not permitted")
                    : Task.FromResult(new Domain { Id = "d1", Status = DomainStatusEnum.Validated }));

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "good-example.com", "host.example.invalid" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("host.example.invalid", result.PendingMessage);
            Assert.DoesNotContain("good-example.com", result.PendingMessage);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_SubdomainStaging_WritesTxtOnTheBaseDomain()
        {
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "brian1.keyfactorluadns.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            validator.Verify(v => v.StageValidation("keyfactorluadns.com", "identrust_validate=abc123", It.IsAny<CancellationToken>()), Times.Once);
            validator.Verify(v => v.CleanupValidation("keyfactorluadns.com", It.IsAny<CancellationToken>()), Times.Once);
        }

        // ---------------------------------------------------------------------
        // Organization association on domain validation creation
        // ---------------------------------------------------------------------

        [Fact]
        public async Task EnsureDomainsValidatedAsync_OrganizationIdSupplied_IsSentOnCreate()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            CreateDomainValidationPayload captured = null;
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(pl => captured = pl)
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });

            await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "orgid-example.com" }, "IdenTrust", "b9bc825f-09d7-4736-8938-fb541822234a");

            Assert.Equal("b9bc825f-09d7-4736-8938-fb541822234a", captured.OrganizationIds);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_NoOrganizationId_OmitsItFromTheCreate()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            CreateDomainValidationPayload captured = null;
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(pl => captured = pl)
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });

            await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "orgid-example.com" }, "IdenTrust");

            // Null rather than empty, so NullValueHandling.Ignore drops it from the JSON entirely.
            Assert.Null(captured.OrganizationIds);
        }

        [Fact]
        public void GetCreateDomainValidationRequest_BlankOrganizationIds_SerializesWithoutTheProperty()
        {
            var payload = new RequestManager().GetCreateDomainValidationRequest(
                "example.com", "IdenTrust", null, null, "");

            var json = Newtonsoft.Json.JsonConvert.SerializeObject(payload);

            Assert.DoesNotContain("organizationIds", json);
        }

        [Fact]
        public void GetCreateDomainValidationRequest_OrganizationIds_SerializesAsOrganizationIds()
        {
            var payload = new RequestManager().GetCreateDomainValidationRequest(
                "example.com", "IdenTrust", null, null, "b9bc825f-09d7-4736-8938-fb541822234a");

            var json = Newtonsoft.Json.JsonConvert.SerializeObject(payload);

            Assert.Contains("\"organizationIds\":\"b9bc825f-09d7-4736-8938-fb541822234a\"", json);
        }

        [Fact]
        public async Task EnsureDomainsValidatedForPolicyAsync_PassesThePolicysOrganizationIdThrough()
        {
            var organizationId = Guid.Parse("b9bc825f-09d7-4736-8938-fb541822234a");
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            CreateDomainValidationPayload captured = null;
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(pl => captured = pl)
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            var policy = new Policy
            {
                Id = Guid.NewGuid(),
                Name = "Keyfactor IdenTrust TLS OV",
                OrganizationId = organizationId,
                Details = new PolicyDetails { Validator = "IdenTrust" }
            };

            var result = await plugin.EnsureDomainsValidatedForPolicyAsync(mockClient.Object, NewFlow(), policy, SampleCsr, null);

            // The organization the policy issues under is the one the domain must be linked to.
            Assert.Null(result);
            Assert.Equal(organizationId.ToString(), captured.OrganizationIds);
        }

        [Fact]
        public async Task EnsureDomainsValidatedForPolicyAsync_PolicyWithoutOrganizationId_SendsNone()
        {
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            CreateDomainValidationPayload captured = null;
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .Callback<CreateDomainValidationPayload>(pl => captured = pl)
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            var policy = new Policy
            {
                Id = Guid.NewGuid(),
                Name = "P",
                OrganizationId = null,
                Details = new PolicyDetails { Validator = "PrivateCA" }
            };

            await plugin.EnsureDomainsValidatedForPolicyAsync(mockClient.Object, NewFlow(), policy, SampleCsr, null);

            Assert.Null(captured.OrganizationIds);
        }

        // ---------------------------------------------------------------------
        // Organization link diagnostic
        // ---------------------------------------------------------------------

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("b9bc825f-09d7-4736-8938-fb541822234a")]
        public void ReportOrganizationLink_NeverThrows_ForAnyOrganizationIdsValue(string organizationIds)
        {
            var plugin = new HydrantIdCAPlugin();

            plugin.ReportOrganizationLink(NewFlow(),
                new Domain { DomainName = "example.com", Status = DomainStatusEnum.Validated, OrganizationIds = organizationIds },
                "example.com");
        }

        [Fact]
        public void ReportOrganizationLink_NullDomain_IsIgnored()
        {
            var plugin = new HydrantIdCAPlugin();

            plugin.ReportOrganizationLink(NewFlow(), null, "example.com");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("b9bc825f-09d7-4736-8938-fb541822234a")]
        public async Task EnsureDomainsValidatedAsync_OrganizationLinkDiagnostic_DoesNotChangeTheOutcome(string organizationIds)
        {
            // The diagnostic reports what HydrantId returned; whether a policy actually requires an
            // organization is HydrantId's call, so a missing link must not fail validation here.
            var plugin = new HydrantIdCAPlugin();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Validated,
                    OrganizationIds = organizationIds
                });

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "orglink-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            Assert.Null(result.PendingMessage);
        }

        [Fact]
        public void ResolveDnsValidator_NoFactorySupplied_ReturnsNull()
        {
            var plugin = new HydrantIdCAPlugin();

            Assert.Null(plugin.ResolveDnsValidator(NewFlow(), "example.com"));
        }

        [Fact]
        public void ResolveDnsValidator_NoPluginForZone_ReturnsNullAfterTryingBothValidationTypes()
        {
            var factory = new Mock<IDomainValidatorFactory>();
            factory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((IDomainValidator)null);
            var plugin = MakePluginWithDnsFactory(null, factory.Object);

            Assert.Null(plugin.ResolveDnsValidator(NewFlow(), "example.com"));
            factory.Verify(f => f.ResolveDomainValidator("example.com", HydrantIdCAPlugin.DnsValidationType), Times.Once);
            factory.Verify(f => f.ResolveDomainValidator("example.com", HydrantIdCAPlugin.DnsValidationTypeAlternate), Times.Once);
        }

        [Fact]
        public void ResolveDnsValidator_AlternateValidationType_IsUsedWhenPrimaryMisses()
        {
            var validator = StubDnsValidator().Object;
            var factory = new Mock<IDomainValidatorFactory>();
            factory.Setup(f => f.ResolveDomainValidator("example.com", HydrantIdCAPlugin.DnsValidationType))
                .Returns((IDomainValidator)null);
            factory.Setup(f => f.ResolveDomainValidator("example.com", HydrantIdCAPlugin.DnsValidationTypeAlternate))
                .Returns(validator);
            var plugin = MakePluginWithDnsFactory(null, factory.Object);

            Assert.Same(validator, plugin.ResolveDnsValidator(NewFlow(), "example.com"));
        }

        [Fact]
        public void ResolveDnsValidator_FactoryThrows_ReturnsNullRatherThanPropagating()
        {
            var factory = new Mock<IDomainValidatorFactory>();
            factory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()))
                .Throws(new InvalidOperationException("plugin directory unreadable"));
            var plugin = MakePluginWithDnsFactory(null, factory.Object);

            Assert.Null(plugin.ResolveDnsValidator(NewFlow(), "example.com"));
        }

        [Fact]
        public void ResolveDnsValidator_TriesEachLookupNameInOrder()
        {
            var validator = StubDnsValidator().Object;
            var factory = StubDnsFactoryForDomain(validator, "host.example.com");
            var plugin = MakePluginWithDnsFactory(null, factory.Object);

            // Base domain first, then the requested name -- only the latter is registered.
            var resolved = plugin.ResolveDnsValidator(NewFlow(), "example.com", "host.example.com");

            Assert.Same(validator, resolved);
            factory.Verify(f => f.ResolveDomainValidator("example.com", HydrantIdCAPlugin.DnsValidationType), Times.Once);
            factory.Verify(f => f.ResolveDomainValidator("host.example.com", HydrantIdCAPlugin.DnsValidationType), Times.Once);
        }

        [Fact]
        public void ResolveDnsValidator_FirstLookupNameWins_DoesNotQueryTheRest()
        {
            var validator = StubDnsValidator().Object;
            var factory = StubDnsFactoryForDomain(validator, "example.com");
            var plugin = MakePluginWithDnsFactory(null, factory.Object);

            Assert.Same(validator, plugin.ResolveDnsValidator(NewFlow(), "example.com", "host.example.com"));
            factory.Verify(f => f.ResolveDomainValidator("host.example.com", It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public void ResolveDnsValidator_DuplicateAndBlankLookupNames_AreCollapsed()
        {
            var factory = new Mock<IDomainValidatorFactory>();
            factory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((IDomainValidator)null);
            var plugin = MakePluginWithDnsFactory(null, factory.Object);

            Assert.Null(plugin.ResolveDnsValidator(NewFlow(), "example.com", "example.com", null, "  "));

            factory.Verify(f => f.ResolveDomainValidator("example.com", HydrantIdCAPlugin.DnsValidationType), Times.Once);
        }

        [Fact]
        public void ResolveDnsValidator_NoLookupNames_ReturnsNull()
        {
            var plugin = MakePluginWithDnsFactory(null, Mock.Of<IDomainValidatorFactory>());

            Assert.Null(plugin.ResolveDnsValidator(NewFlow()));
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_PluginRegisteredOnRequestedNameOnly_StillStagesOnTheBaseDomain()
        {
            // Regression: base-domain targeting must not break a Gateway domain validation
            // configuration that is registered against the requested hostname rather than the
            // zone apex. The plugin is found via the hostname; the record still goes on the apex,
            // which the DNS plugin's own zone discovery resolves.
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            var factory = StubDnsFactoryForDomain(validator.Object, "www.keyfactorluadns.com");
            var plugin = MakePluginWithDnsFactory(mockClient, factory.Object);

            var result = await plugin.EnsureDomainsValidatedAsync(mockClient.Object, NewFlow(),
                new List<string> { "www.keyfactorluadns.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            validator.Verify(v => v.StageValidation("keyfactorluadns.com", "identrust_validate=abc123", It.IsAny<CancellationToken>()), Times.Once);
            validator.Verify(v => v.CleanupValidation("keyfactorluadns.com", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_StagedRecordValidates_ReturnsAllValidatedAndCleansUp()
        {
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "auto-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            Assert.Null(result.PendingMessage);
            // Record name is the domain itself, value is HydrantID's whole code string.
            validator.Verify(v => v.StageValidation("auto-example.com", "identrust_validate=abc123", It.IsAny<CancellationToken>()), Times.Once);
            validator.Verify(v => v.CleanupValidation("auto-example.com", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_StageFails_FallsBackToManualWithoutPollingOrCleanup()
        {
            var validator = StubDnsValidator(stageSucceeds: false);
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "auto-example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("publish TXT", result.PendingMessage);
            mockClient.Verify(c => c.GetSubmitCheckDomainValidationAsync(It.IsAny<string>()), Times.Never);
            validator.Verify(v => v.CleanupValidation(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_ValidationNeverCompletes_TimesOutToManualAndStillCleansUp()
        {
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Pending });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "slow-example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("publish TXT", result.PendingMessage);
            validator.Verify(v => v.CleanupValidation("slow-example.com", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_StatusCheckThrows_TreatedAsPendingNotFatal()
        {
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ThrowsAsync(new InvalidOperationException("HTTP 500"));
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "flaky-example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            validator.Verify(v => v.CleanupValidation("flaky-example.com", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_CleanupThrows_DoesNotFailAnOtherwiseValidEnrollment()
        {
            var validator = StubDnsValidator();
            validator.Setup(v => v.CleanupValidation(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("DNS API rejected the delete"));
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "auto-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_NoCodeReturned_FallsBackToManualWithoutStaging()
        {
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Pending, CodeInstructions = "publish TXT" });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "nocode-example.com" }, "IdenTrust");

            Assert.False(result.AllValidated);
            Assert.Contains("publish TXT", result.PendingMessage);
            validator.Verify(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task EnsureDomainsValidatedAsync_DomainAlreadyValidated_NeverResolvesADnsPlugin()
        {
            var factory = StubDnsFactory(StubDnsValidator().Object);
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>
            {
                new Domain { Id = "d1", DomainName = "done-example.com", Status = DomainStatusEnum.Validated }
            });
            var plugin = MakePluginWithDnsFactory(mockClient, factory.Object);

            var result = await plugin.EnsureDomainsValidatedAsync(
                mockClient.Object, NewFlow(), new List<string> { "done-example.com" }, "IdenTrust");

            Assert.True(result.AllValidated);
            factory.Verify(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public void DnsTimingAccessors_Unconfigured_UseAnnotationDefaults()
        {
            var plugin = MakePlugin();

            Assert.Equal(HydrantIdCAPlugin.DefaultDnsPropagationDelaySeconds, plugin.DnsPropagationDelaySeconds);
            Assert.Equal(HydrantIdCAPlugin.DefaultDomainValidationTimeoutSeconds, plugin.DomainValidationTimeoutSeconds);
            Assert.Equal(HydrantIdCAPlugin.DefaultDomainValidationPollIntervalSeconds, plugin.DomainValidationPollIntervalSeconds);
        }

        [Fact]
        public void DnsPropagationDelaySeconds_ExplicitZero_IsHonouredRatherThanDefaulted()
        {
            var plugin = MakePluginWithDnsFactory(null, Mock.Of<IDomainValidatorFactory>());

            Assert.Equal(0, plugin.DnsPropagationDelaySeconds);
        }

        [Fact]
        public void DomainValidationTimeoutSeconds_ExplicitZero_FallsBackToDefault()
        {
            var data = ValidConnectionData();
            data[HydrantIdCAPluginConfig.ConfigConstants.DomainValidationTimeoutSeconds] = 0;
            var plugin = new HydrantIdCAPlugin();
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());

            Assert.Equal(HydrantIdCAPlugin.DefaultDomainValidationTimeoutSeconds, plugin.DomainValidationTimeoutSeconds);
        }

        [Fact]
        public async Task Enroll_New_DnsAutomationValidatesDomain_ProceedsToIssueInTheSameCall()
        {
            var (_, pem, _) = MakeSelfSignedCert();
            var trackingId = Guid.NewGuid();
            var validator = StubDnsValidator();
            var mockClient = new Mock<IHydrantIdClient>();
            mockClient.Setup(c => c.GetPolicyList()).ReturnsAsync(new List<Policy>
            {
                new Policy { Id = Guid.NewGuid(), Name = "Test Policy", Details = new PolicyDetails { Validator = "IdenTrust" } }
            });
            mockClient.Setup(c => c.GetDomainListAsync()).ReturnsAsync(new List<Domain>());
            mockClient.Setup(c => c.GetSubmitCreateDomainValidationAsync(It.IsAny<CreateDomainValidationPayload>()))
                .ReturnsAsync(new Domain
                {
                    Id = "d1",
                    Status = DomainStatusEnum.Pending,
                    Code = "identrust_validate=abc123",
                    CodeInstructions = "publish TXT"
                });
            mockClient.Setup(c => c.GetSubmitCheckDomainValidationAsync("d1"))
                .ReturnsAsync(new Domain { Id = "d1", Status = DomainStatusEnum.Validated });
            mockClient.Setup(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>())).ReturnsAsync(new CertRequestResult
            {
                RequestStatus = new CertRequestStatus { Id = trackingId.ToString() }
            });
            mockClient.Setup(c => c.GetSubmitGetCertificateByCsrAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Id = trackingId });
            mockClient.Setup(c => c.GetSubmitGetCertificateAsync(trackingId.ToString()))
                .ReturnsAsync(new Certificate { Pem = pem, RevocationStatus = RevocationStatusEnum.Valid });
            var plugin = MakePluginWithDnsFactory(mockClient, StubDnsFactory(validator.Object).Object);

            var result = await plugin.Enroll(SampleCsr, "subj", null, ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            // The whole cycle -- stage TXT, wait for DCV, submit the CSR, wait for the cert --
            // completes inside one Enroll call, with no EXTERNALVALIDATION round trip.
            Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
            Assert.False(string.IsNullOrEmpty(result.Certificate));
            validator.Verify(v => v.StageValidation(It.IsAny<string>(), "identrust_validate=abc123", It.IsAny<CancellationToken>()), Times.Once);
            validator.Verify(v => v.CleanupValidation(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
            mockClient.Verify(c => c.GetSubmitEnrollmentAsync(It.IsAny<CertRequestBody>()), Times.Once);
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
