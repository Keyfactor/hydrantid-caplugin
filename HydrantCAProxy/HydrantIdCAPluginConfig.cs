/*
Copyright © 2025 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
using Keyfactor.AnyGateway.Extensions;
using System.Collections.Generic;

namespace Keyfactor.Extensions.CAPlugin.HydrantId
{
    public class HydrantIdCAPluginConfig
    {
        public const int DefaultPageSize = 100;

        public class ConfigConstants
        {
            public static string HydrantIdBaseUrl = "HydrantIdBaseUrl";
            public static string HydrantIdAuthId = "HydrantIdAuthId";
            public static string HydrantIdAuthKey = "HydrantIdAuthKey";
            public static string HydrantIdAccountId = "HydrantIdAccountId";
            public static string HydrantIdOrgName = "HydrantIdOrgName";
            public static string HydrantIdOrgPrimaryContactFullName = "HydrantIdOrgPrimaryContactFullName";
            public static string HydrantIdOrgStreetAddress = "HydrantIdOrgStreetAddress";
            public static string HydrantIdOrgCityProvPostalCodeCountry = "HydrantIdOrgCityProvPostalCodeCountry";
            public static string HydrantIdEmailAddress = "HydrantIdEmailAddress";
            public static string HydrantIdPhoneNumber = "HydrantIdPhoneNumber";
            public static string DnsPropagationDelaySeconds = "DnsPropagationDelaySeconds";
            public static string DomainValidationTimeoutSeconds = "DomainValidationTimeoutSeconds";
            public static string DomainValidationPollIntervalSeconds = "DomainValidationPollIntervalSeconds";
            public static string DefaultPageSize = "DefaultPageSize";
            public static string Enabled = "Enabled";
        }

        public class Config
        {
            public string HydrantIdBaseUrl { get; set; }
            public string HydrantIdAuthId { get; set; }
            public string HydrantIdAuthKey { get; set; }
            public string HydrantIdAccountId { get; set; }
            public string HydrantIdOrgName { get; set; }
            public string HydrantIdOrgPrimaryContactFullName { get; set; }
            public string HydrantIdOrgStreetAddress { get; set; }
            public string HydrantIdOrgCityProvPostalCodeCountry { get; set; }
            public string HydrantIdEmailAddress { get; set; }
            public string HydrantIdPhoneNumber { get; set; }
            // Nullable so an absent connector field (null) stays distinguishable from an
            // operator explicitly setting 0, which disables the propagation delay.
            public int? DnsPropagationDelaySeconds { get; set; }
            public int? DomainValidationTimeoutSeconds { get; set; }
            public int? DomainValidationPollIntervalSeconds { get; set; }
            public bool Enabled { get; set; }
        }

        public static class EnrollmentParametersConstants
        {
            public const string ValidityPeriod = "ValidityPeriod";
            public const string ValidityUnits = "ValidityUnits";
            public const string RenewalDays = "RenewalDays";
        }

        public static Dictionary<string, PropertyConfigInfo> GetPluginAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                [ConfigConstants.HydrantIdBaseUrl] = new PropertyConfigInfo()
                {
                    Comments = "The Base URL For the HydrantId Endpoint similar to https://acm-stage.hydrantid.com.  Get this from HydrantId.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdAuthId] = new PropertyConfigInfo()
                {
                    Comments = "The AuthId Obtained from HydrantId.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                [ConfigConstants.HydrantIdAuthKey] = new PropertyConfigInfo()
                {
                    Comments = "The AuthKey Obtained from HydrantId.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                [ConfigConstants.HydrantIdAccountId] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Some HydrantId tenants require the account id to be included when creating a domain validation request (POST /domains/); leave blank if domain validation already works without it. Obtain from the HydrantId portal's account settings, HydrantId support, or the 'account.id' field on any existing certificate returned by the API.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdOrgName] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Organization name required by some HydrantId validators (e.g. IdenTrust) on domain validation requests. Leave blank if not required by your validator -- omitted from the request entirely when blank.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdOrgPrimaryContactFullName] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Organization primary contact full name required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdOrgStreetAddress] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Organization street address required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdOrgCityProvPostalCodeCountry] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Organization city/province/postal code/country required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdEmailAddress] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Organization contact email address required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.HydrantIdPhoneNumber] = new PropertyConfigInfo()
                {
                    Comments = "Optional. Organization contact phone number required by some HydrantId validators (e.g. IdenTrust) on domain validation requests.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.DnsPropagationDelaySeconds] = new PropertyConfigInfo()
                {
                    Comments = "Seconds to wait after a DNS provider plugin writes the validation TXT record before asking HydrantId to check it, allowing the record to propagate to the authoritative nameservers. Only used when a DNS provider plugin is handling the record; ignored on the manual validation path. Set to 0 to skip the delay and start polling immediately.",
                    Hidden = false,
                    DefaultValue = 30,
                    Type = "Number"
                },
                [ConfigConstants.DomainValidationTimeoutSeconds] = new PropertyConfigInfo()
                {
                    Comments = "Maximum seconds to hold the enrollment open while polling HydrantId for domain validation to complete after a DNS provider plugin has staged the TXT record. On timeout the enrollment falls back to external validation (manual DNS publish and resubmit) rather than failing.",
                    Hidden = false,
                    DefaultValue = 300,
                    Type = "Number"
                },
                [ConfigConstants.DomainValidationPollIntervalSeconds] = new PropertyConfigInfo()
                {
                    Comments = "Seconds between HydrantId domain validation status checks while waiting for a staged DNS record to be validated.",
                    Hidden = false,
                    DefaultValue = 10,
                    Type = "Number"
                },
                [ConfigConstants.Enabled] = new PropertyConfigInfo()
                {
                    Comments = "Flag to Enable or Disable the CA connector.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Bool"
                }
            };
        }

        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                [EnrollmentParametersConstants.ValidityPeriod] = new PropertyConfigInfo()
                {
                    Comments = $"The desired lifetime time period could be Days, Months or Years.",
                    Hidden = false,
                    DefaultValue = "Years",
                    Type = "String"
                },
                [EnrollmentParametersConstants.ValidityUnits] = new PropertyConfigInfo()
                {
                    Comments = $"The desired lifetime time value some number indicating days, months or years.",
                    Hidden = false,
                    DefaultValue = 1,
                    Type = "Number"
                },
                [EnrollmentParametersConstants.RenewalDays] = new PropertyConfigInfo()
                {
                    Comments = $"The window that determines whether it is a renewal vs a re-issue.",
                    Hidden = false,
                    DefaultValue = 30,
                    Type = "Number"
                }
            };
        }
    }
}
