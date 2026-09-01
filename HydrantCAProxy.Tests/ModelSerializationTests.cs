// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.

using System;
using System.Collections.Generic;
using Keyfactor.HydrantId.Client.Models;
using Keyfactor.HydrantId.Client.Models.Enums;
using Newtonsoft.Json;
using Xunit;

namespace HydrantCAProxy.Tests
{
    // Covers plain data-model classes that carry no logic of their own but are part of the
    // public model surface (deserialized from HydrantID API responses even where the plugin's
    // business logic doesn't currently read every field) plus the one custom JsonConverter,
    // TagEnumConverter, which does carry real behavior worth testing directly.
    public class ModelSerializationTests
    {
        [Fact]
        public void Validator_PropertiesRoundTrip()
        {
            var v = new Validator { Id = "IdenTrust", Name = "IdenTrust", Capabilities = new List<string> { "create", "validate" } };

            Assert.Equal("IdenTrust", v.Id);
            Assert.Equal("IdenTrust", v.Name);
            Assert.Equal(2, v.Capabilities.Count);
        }

        [Fact]
        public void PolicyEnabled_PropertiesRoundTrip()
        {
            var e = new PolicyEnabled { Ui = true, Rest = true, Acme = false, Scep = false, Est = true };

            Assert.True(e.Ui);
            Assert.True(e.Rest);
            Assert.False(e.Acme);
            Assert.False(e.Scep);
            Assert.True(e.Est);
        }

        [Fact]
        public void PolicyDetailsValidity_PropertiesRoundTrip()
        {
            var v = new PolicyDetailsValidity
            {
                Years = new List<string> { "1-5" },
                Months = new List<string> { "1-12" },
                Days = new List<string> { "1-31" },
                Required = true,
                Modifiable = true
            };

            Assert.Single(v.Years);
            Assert.Single(v.Months);
            Assert.Single(v.Days);
            Assert.True(v.Required);
            Assert.True(v.Modifiable);
        }

        [Fact]
        public void PolicyDetailsExpiryEmails_PropertiesRoundTrip()
        {
            var e = new PolicyDetailsExpiryEmails
            {
                Tag = PolicyDetailsExpiryEmails.TagEnum.ExpiryEmails,
                Label = "Expiration Emails",
                Required = false,
                Modifiable = true,
                DefaultValue = "${Requestor}"
            };

            Assert.Equal(PolicyDetailsExpiryEmails.TagEnum.ExpiryEmails, e.Tag);
            Assert.Equal("Expiration Emails", e.Label);
            Assert.Equal("${Requestor}", e.DefaultValue);
        }

        [Fact]
        public void PolicyDetailsDnComponents_PropertiesRoundTrip()
        {
            var d = new PolicyDetailsDnComponents
            {
                Tag = PolicyDetailsDnComponents.TagEnum.Cn,
                Label = "Common Name",
                Required = true,
                Modifiable = true,
                DefaultValue = "example.com",
                CopyAsFirstSan = true
            };

            Assert.Equal(PolicyDetailsDnComponents.TagEnum.Cn, d.Tag);
            Assert.True(d.CopyAsFirstSan);
        }

        [Fact]
        public void PolicyDetailsCustomFields_PropertiesRoundTrip()
        {
            var f = new PolicyDetailsCustomFields
            {
                Tag = "contract",
                Label = "Contract #",
                Required = true,
                Modifiable = true,
                DefaultValue = "<Contract #>"
            };

            Assert.Equal("contract", f.Tag);
            Assert.Equal("<Contract #>", f.DefaultValue);
        }

        [Fact]
        public void PolicyDetailsCustomExtensions_PropertiesRoundTrip()
        {
            var x = new PolicyDetailsCustomExtensions
            {
                Oid = "1.3.6.1.4.1.311.21.7",
                Label = "Template Info",
                Required = true,
                Modifiable = true,
                DefaultValue = "302f"
            };

            Assert.Equal("1.3.6.1.4.1.311.21.7", x.Oid);
        }

        [Fact]
        public void CertRequestUser_PropertiesRoundTrip()
        {
            var u = new CertRequestUser { Id = Guid.NewGuid(), FirstName = "Jane", LastName = "Doe" };

            Assert.Equal("Jane", u.FirstName);
            Assert.Equal("Doe", u.LastName);
        }

        [Fact]
        public void CertRequestPolicy_PropertiesRoundTrip()
        {
            var p = new CertRequestPolicy { Id = Guid.NewGuid(), Name = "Test Policy" };

            Assert.Equal("Test Policy", p.Name);
        }

        [Fact]
        public void CertificateUser_PropertiesRoundTrip()
        {
            var u = new CertificateUser { Id = Guid.NewGuid(), Email = "jane@example.com" };

            Assert.Equal("jane@example.com", u.Email);
        }

        [Fact]
        public void CertRequest_PropertiesRoundTrip()
        {
            var r = new CertRequest
            {
                Source = CertRequest.SourceEnum.Acm,
                Id = Guid.NewGuid(),
                Fingerprint = "abc123",
                Csr = "csr-data",
                CommonName = "test.example.com",
                Details = new Dictionary<string, object>(),
                IssuanceStatus = IssuanceStatus.Issued,
                CreateAt = DateTime.UtcNow,
                Policy = new CertRequestPolicy { Name = "P" },
                User = new CertRequestUser { FirstName = "Jane" }
            };

            Assert.Equal(CertRequest.SourceEnum.Acm, r.Source);
            Assert.Equal("test.example.com", r.CommonName);
            Assert.Equal(IssuanceStatus.Issued, r.IssuanceStatus);
            Assert.Equal("P", r.Policy.Name);
            Assert.Equal("Jane", r.User.FirstName);
        }

        [Fact]
        public void RevokeCertificateReasonIssuerDn_PropertiesRoundTrip()
        {
            var r = new RevokeCertificateReasonIssuerDn { Reason = RevocationReasons.Superseded, IssuerDn = "CN=Test CA" };

            Assert.Equal(RevocationReasons.Superseded, r.Reason);
            Assert.Equal("CN=Test CA", r.IssuerDn);
        }

        [Fact]
        public void CertificatesResponseItem_PropertiesRoundTrip()
        {
            var item = new CertificatesResponseItem
            {
                Id = "c1",
                CommonName = "test.example.com",
                Serial = "01",
                NotBefore = DateTime.UtcNow,
                NotAfter = DateTime.UtcNow.AddYears(1),
                RevocationStatus = RevocationStatusEnum.Valid,
                SaNs = new List<string> { "a.example.com" },
                Policy = new NameObject { Name = "Policy A" }
            };

            Assert.NotNull(item.NotBefore);
            Assert.NotNull(item.NotAfter);
            Assert.Single(item.SaNs);
            Assert.Equal("Policy A", item.Policy.Name);
        }

        // ---------------------------------------------------------------------
        // TagEnumConverter -- real converter logic, exercised via actual (de)serialization.
        // ---------------------------------------------------------------------

        [Theory]
        [InlineData("DNSNAME", PolicyDetailsSubjectAltNames.TagEnum.DnsName)]
        [InlineData("IPADDRESS", PolicyDetailsSubjectAltNames.TagEnum.IpAddress)]
        [InlineData("RFC822NAME", PolicyDetailsSubjectAltNames.TagEnum.Rfc822Name)]
        [InlineData("RFS822NAME", PolicyDetailsSubjectAltNames.TagEnum.Rfc822Name)]
        [InlineData("UPN", PolicyDetailsSubjectAltNames.TagEnum.Upn)]
        public void TagEnumConverter_ReadJson_MapsKnownValues(string json, PolicyDetailsSubjectAltNames.TagEnum expected)
        {
            var result = JsonConvert.DeserializeObject<PolicyDetailsSubjectAltNames>($"{{\"tag\":\"{json}\"}}");

            Assert.Equal(expected, result.Tag);
        }

        [Fact]
        public void TagEnumConverter_ReadJson_UnknownValue_Throws()
        {
            Assert.Throws<JsonSerializationException>(() =>
                JsonConvert.DeserializeObject<PolicyDetailsSubjectAltNames>("{\"tag\":\"BOGUS\"}"));
        }

        [Theory]
        [InlineData(PolicyDetailsSubjectAltNames.TagEnum.DnsName, "DNSNAME")]
        [InlineData(PolicyDetailsSubjectAltNames.TagEnum.IpAddress, "IPADDRESS")]
        [InlineData(PolicyDetailsSubjectAltNames.TagEnum.Rfc822Name, "RFC822NAME")]
        [InlineData(PolicyDetailsSubjectAltNames.TagEnum.Upn, "UPN")]
        public void TagEnumConverter_WriteJson_MapsKnownValues(PolicyDetailsSubjectAltNames.TagEnum tag, string expected)
        {
            var model = new PolicyDetailsSubjectAltNames { Tag = tag };

            var json = JsonConvert.SerializeObject(model);

            Assert.Contains($"\"tag\":\"{expected}\"", json);
        }

        [Fact]
        public void TagEnumConverter_WriteJson_UnknownValue_Throws()
        {
            var model = new PolicyDetailsSubjectAltNames { Tag = (PolicyDetailsSubjectAltNames.TagEnum)999 };

            Assert.Throws<JsonSerializationException>(() => JsonConvert.SerializeObject(model));
        }
    }
}
