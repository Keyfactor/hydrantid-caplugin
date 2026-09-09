// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.  You may obtain a
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

using System;
using System.Collections.Generic;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.HydrantId;
using Keyfactor.HydrantId;
using Keyfactor.HydrantId.Client.Models;
using Keyfactor.HydrantId.Client.Models.Enums;
using Keyfactor.HydrantId.Exceptions;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;

namespace HydrantCAProxy.Tests
{
    public class RequestManagerTests
    {
        private readonly RequestManager _sut = new RequestManager();

        // A valid PEM CSR (CN=unit.test.hydrantid.local) used to exercise the
        // enrollment/DN-parsing paths without contacting a live CA.
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

        private static EnrollmentProductInfo ProductInfo(Dictionary<string, string> parameters) =>
            new EnrollmentProductInfo { ProductID = "test-policy", ProductParameters = parameters };

        // ---------------------------------------------------------------------
        // ResolveTemplateParameter — the ADO 84076 / 81803 fix.
        // Command does not populate a template's parameter collection with the
        // annotation defaults until the template is saved. The resolver must fall
        // back to the declared DefaultValue so enrollment still works.
        // ---------------------------------------------------------------------

        [Theory]
        [InlineData("ValidityPeriod", "Years")]
        [InlineData("ValidityUnits", "1")]
        [InlineData("RenewalDays", "30")]
        public void ResolveTemplateParameter_KeyMissing_ReturnsAnnotationDefault(string key, string expected)
        {
            // Unsaved template: Command supplies an empty parameter collection.
            var productInfo = ProductInfo(new Dictionary<string, string>());

            var result = RequestManager.ResolveTemplateParameter(productInfo, key);

            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void ResolveTemplateParameter_BlankValue_ReturnsAnnotationDefault(string blank)
        {
            var productInfo = ProductInfo(new Dictionary<string, string> { ["ValidityPeriod"] = blank });

            var result = RequestManager.ResolveTemplateParameter(productInfo, "ValidityPeriod");

            Assert.Equal("Years", result);
        }

        [Fact]
        public void ResolveTemplateParameter_ValueSupplied_ReturnsSuppliedValue()
        {
            var productInfo = ProductInfo(new Dictionary<string, string> { ["ValidityPeriod"] = "Days" });

            var result = RequestManager.ResolveTemplateParameter(productInfo, "ValidityPeriod");

            Assert.Equal("Days", result);
        }

        [Fact]
        public void ResolveTemplateParameter_NullProductParameters_ReturnsAnnotationDefault()
        {
            var productInfo = ProductInfo(null);

            var result = RequestManager.ResolveTemplateParameter(productInfo, "RenewalDays");

            Assert.Equal("30", result);
        }

        [Fact]
        public void ResolveTemplateParameter_NullProductInfo_ReturnsAnnotationDefault()
        {
            var result = RequestManager.ResolveTemplateParameter(null, "ValidityUnits");

            Assert.Equal("1", result);
        }

        [Fact]
        public void ResolveTemplateParameter_UnknownKeyWithNoDefault_ReturnsNull()
        {
            var productInfo = ProductInfo(new Dictionary<string, string>());

            var result = RequestManager.ResolveTemplateParameter(productInfo, "NotADeclaredParameter");

            Assert.Null(result);
        }

        // ---------------------------------------------------------------------
        // GetEnrollmentRequest — proves the resolver is actually wired into
        // enrollment: an unsaved template (no parameters) still produces a valid
        // request using the annotation defaults instead of throwing.
        // ---------------------------------------------------------------------

        [Fact]
        public void GetEnrollmentRequest_UnsavedTemplate_UsesDefaultValidity()
        {
            var productInfo = ProductInfo(new Dictionary<string, string>());

            var request = _sut.GetEnrollmentRequest(Guid.NewGuid(), productInfo, SampleCsr, null);

            // Defaults are ValidityPeriod=Years, ValidityUnits=1.
            Assert.NotNull(request);
            Assert.Equal(1, request.Validity.Years);
            Assert.Null(request.Validity.Months);
            Assert.Null(request.Validity.Days);
        }

        [Fact]
        public void GetEnrollmentRequest_SuppliedValidity_HonorsSuppliedValues()
        {
            var productInfo = ProductInfo(new Dictionary<string, string>
            {
                ["ValidityPeriod"] = "Months",
                ["ValidityUnits"] = "6"
            });

            var request = _sut.GetEnrollmentRequest(Guid.NewGuid(), productInfo, SampleCsr, null);

            Assert.Equal(6, request.Validity.Months);
            Assert.Null(request.Validity.Years);
        }

        [Fact]
        public void GetEnrollmentRequest_NullCsr_Throws()
        {
            var productInfo = ProductInfo(new Dictionary<string, string>());

            Assert.Throws<ArgumentNullException>(() => _sut.GetEnrollmentRequest(Guid.NewGuid(), productInfo, null, null));
        }

        [Fact]
        public void GetEnrollmentRequest_NullProductInfo_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _sut.GetEnrollmentRequest(Guid.NewGuid(), null, SampleCsr, null));
        }

        [Fact]
        public void GetEnrollmentRequest_UnrecognizedValidityPeriod_Throws()
        {
            var productInfo = ProductInfo(new Dictionary<string, string>
            {
                ["ValidityPeriod"] = "Fortnights",
                ["ValidityUnits"] = "2"
            });

            Assert.Throws<ArgumentException>(() => _sut.GetEnrollmentRequest(Guid.NewGuid(), productInfo, SampleCsr, null));
        }

        [Fact]
        public void GetEnrollmentRequest_WithSans_PopulatesSubjectAltNames()
        {
            var productInfo = ProductInfo(new Dictionary<string, string>());
            var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "a.example.com", "b.example.com" } };

            var request = _sut.GetEnrollmentRequest(Guid.NewGuid(), productInfo, SampleCsr, sans);

            Assert.NotNull(request.SubjectAltNames);
            Assert.Equal(2, request.SubjectAltNames.Dnsname.Count);
        }

        // ---------------------------------------------------------------------
        // GetMapRevokeReasons — revocation reason mapping (incl. ADO 86120
        // reason 0 = Unspecified).
        // ---------------------------------------------------------------------

        [Theory]
        [InlineData(0u, RevocationReasons.Unspecified)]
        [InlineData(1u, RevocationReasons.KeyCompromise)]
        [InlineData(3u, RevocationReasons.AffiliationChanged)]
        [InlineData(4u, RevocationReasons.Superseded)]
        [InlineData(5u, RevocationReasons.CessationOfOperation)]
        public void GetMapRevokeReasons_SupportedReason_MapsCorrectly(uint input, RevocationReasons expected)
        {
            Assert.Equal(expected, _sut.GetMapRevokeReasons(input));
        }

        [Theory]
        [InlineData(2u)]   // certificateHold — not supported
        [InlineData(6u)]
        [InlineData(99u)]
        public void GetMapRevokeReasons_UnsupportedReason_Throws(uint input)
        {
            Assert.Throws<RevokeReasonNotSupportedException>(() => _sut.GetMapRevokeReasons(input));
        }

        [Fact]
        public void GetRevokeRequest_SetsReason()
        {
            var result = _sut.GetRevokeRequest(RevocationReasons.KeyCompromise);

            Assert.Equal(RevocationReasons.KeyCompromise, result.Reason);
        }

        // ---------------------------------------------------------------------
        // GetMapReturnStatus — HydrantId status -> Keyfactor EndEntityStatus.
        // ---------------------------------------------------------------------

        [Theory]
        [InlineData(RevocationStatusEnum.Valid, EndEntityStatus.GENERATED)]
        [InlineData(RevocationStatusEnum.Pending, EndEntityStatus.INPROCESS)]
        [InlineData(RevocationStatusEnum.Revoked, EndEntityStatus.REVOKED)]
        [InlineData(RevocationStatusEnum.Failed, EndEntityStatus.FAILED)]
        [InlineData(RevocationStatusEnum.Expired, EndEntityStatus.FAILED)] // default branch
        public void GetMapReturnStatus_MapsToExpectedEndEntityStatus(RevocationStatusEnum input, EndEntityStatus expected)
        {
            Assert.Equal((int)expected, _sut.GetMapReturnStatus(input));
        }

        // ---------------------------------------------------------------------
        // GetRenewalRequest
        // ---------------------------------------------------------------------

        [Fact]
        public void GetRenewalRequest_WithCsr_SetsCsrAndReuseFlag()
        {
            var result = _sut.GetRenewalRequest("some-csr", reuseCsr: false);

            Assert.Equal("some-csr", result.Csr);
            Assert.False(result.ReuseCsr);
        }

        [Fact]
        public void GetRenewalRequest_ReuseCsrWithoutCsr_DoesNotThrow()
        {
            var result = _sut.GetRenewalRequest(null, reuseCsr: true);

            Assert.True(result.ReuseCsr);
        }

        [Fact]
        public void GetRenewalRequest_NoCsrAndNoReuse_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _sut.GetRenewalRequest(null, reuseCsr: false));
        }

        // ---------------------------------------------------------------------
        // GetSansRequest
        // ---------------------------------------------------------------------

        [Fact]
        public void GetSansRequest_Null_ReturnsEmptySans()
        {
            var result = _sut.GetSansRequest(null);

            Assert.NotNull(result);
        }

        [Fact]
        public void GetSansRequest_AllTypes_Populated()
        {
            var sans = new Dictionary<string, string[]>
            {
                ["dnsname"] = new[] { "example.com" },
                ["ipaddress"] = new[] { "10.0.0.1", "10.0.0.2" },
                ["rfc822name"] = new[] { "user@example.com" },
                ["upn"] = new[] { "user@corp.local" }
            };

            var result = _sut.GetSansRequest(sans);

            Assert.Single(result.Dnsname);
            Assert.Equal(2, result.Ipaddress.Count);
            Assert.Single(result.Rfc822Name);
            Assert.Single(result.Upn);
        }

        // ---------------------------------------------------------------------
        // GetDomainsToValidate
        // ---------------------------------------------------------------------

        [Fact]
        public void GetDomainsToValidate_CnOnly_ReturnsSingleDomain()
        {
            var result = _sut.GetDomainsToValidate(SampleCsr, null);

            Assert.Single(result);
            Assert.Equal("unit.test.hydrantid.local", result[0]);
        }

        [Fact]
        public void GetDomainsToValidate_CnPlusDnsSans_ReturnsDeduped()
        {
            var sans = new Dictionary<string, string[]>
            {
                ["dnsname"] = new[] { "unit.test.hydrantid.local", "www.example.com" }
            };

            var result = _sut.GetDomainsToValidate(SampleCsr, sans);

            Assert.Equal(2, result.Count);
            Assert.Contains("unit.test.hydrantid.local", result);
            Assert.Contains("www.example.com", result);
        }

        [Fact]
        public void GetDomainsToValidate_SansCaseVariant_DedupedAgainstCn()
        {
            var sans = new Dictionary<string, string[]>
            {
                ["dnsname"] = new[] { "UNIT.TEST.HYDRANTID.LOCAL" }
            };

            var result = _sut.GetDomainsToValidate(SampleCsr, sans);

            Assert.Single(result);
        }

        [Fact]
        public void GetDomainsToValidate_NullCsr_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => _sut.GetDomainsToValidate(null, null));
        }

        // ---------------------------------------------------------------------
        // GetCreateDomainValidationRequest
        // ---------------------------------------------------------------------

        [Fact]
        public void GetCreateDomainValidationRequest_Valid_SetsDnsMethodAndOmitsAccountId()
        {
            var result = _sut.GetCreateDomainValidationRequest("example.com", "validator-1");

            Assert.Equal("example.com", result.DomainName);
            Assert.Equal("validator-1", result.Validator);
            Assert.Equal(ValidationMethod.Dns, result.Method);
            Assert.Null(result.AccountId);
        }

        [Fact]
        public void GetCreateDomainValidationRequest_AccountIdSupplied_SetsAccountId()
        {
            var result = _sut.GetCreateDomainValidationRequest("example.com", "validator-1", "account-123");

            Assert.Equal("account-123", result.AccountId);
        }

        [Fact]
        public void GetCreateDomainValidationRequest_OrgPayloadSupplied_SetsPayload()
        {
            var orgPayload = new DomainValidationOrgPayload { OrgName = "Acme Corp", EmailAddress = "admin@acme.com" };

            var result = _sut.GetCreateDomainValidationRequest("example.com", "validator-1", orgPayload: orgPayload);

            Assert.Same(orgPayload, result.Payload);
        }

        [Fact]
        public void GetCreateDomainValidationRequest_NoOrgPayload_PayloadRemainsNull()
        {
            var result = _sut.GetCreateDomainValidationRequest("example.com", "validator-1");

            Assert.Null(result.Payload);
        }

        [Fact]
        public void GetCreateDomainValidationRequest_NullDomain_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => _sut.GetCreateDomainValidationRequest(null, "validator-1"));
        }

        [Fact]
        public void GetCreateDomainValidationRequest_NullValidatorId_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => _sut.GetCreateDomainValidationRequest("example.com", null));
        }

        // ---------------------------------------------------------------------
        // GetCertificatesListRequest
        // ---------------------------------------------------------------------

        [Fact]
        public void GetCertificatesListRequest_SetsOffsetAndLimit()
        {
            var result = _sut.GetCertificatesListRequest(offset: 100, limit: 50);

            Assert.Equal(100, result.Offset);
            Assert.Equal(50, result.Limit);
            Assert.True(result.Expired);
        }

        // ---------------------------------------------------------------------
        // GetEnrollmentResult
        // ---------------------------------------------------------------------

        [Fact]
        public void GetEnrollmentResult_NullEnrollmentResult_ReturnsFailed()
        {
            var result = _sut.GetEnrollmentResult(null, new AnyCAPluginCertificate { Certificate = "cert" });

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public void GetEnrollmentResult_MissingId_ReturnsFailed()
        {
            var cert = new Certificate { Id = null };

            var result = _sut.GetEnrollmentResult(cert, new AnyCAPluginCertificate { Certificate = "cert" });

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public void GetEnrollmentResult_MissingCertificateContent_ReturnsFailed()
        {
            var cert = new Certificate { Id = Guid.NewGuid() };

            var result = _sut.GetEnrollmentResult(cert, new AnyCAPluginCertificate { Certificate = "" });

            Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public void GetEnrollmentResult_Valid_ReturnsGenerated()
        {
            var id = Guid.NewGuid();
            var cert = new Certificate { Id = id };
            var pluginCert = new AnyCAPluginCertificate { Certificate = "BASE64CERT" };

            var result = _sut.GetEnrollmentResult(cert, pluginCert);

            Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
            Assert.Equal(id.ToString(), result.CARequestID);
            Assert.Equal("BASE64CERT", result.Certificate);
        }
    }
}
