// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.  You may obtain a
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
// required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for
// thespecific language governing permissions and limitations under the
// License.
using Keyfactor.HydrantId.Interfaces;
using Newtonsoft.Json;

namespace Keyfactor.HydrantId.Client.Models
{
    // Matches the "requiredPayload" fields some HydrantId domain validators (e.g. IdenTrust)
    // report via GET /api/v2/domains/validators, and require on POST /api/v2/domains/ --
    // without this, IdenTrust rejects the request with "The domain request is missing the
    // organization name".
    public class DomainValidationOrgPayload : IDomainValidationOrgPayload
    {
        [JsonProperty("orgName", NullValueHandling = NullValueHandling.Ignore)]
        public string OrgName { get; set; }

        [JsonProperty("orgPrimaryContactFullName", NullValueHandling = NullValueHandling.Ignore)]
        public string OrgPrimaryContactFullName { get; set; }

        [JsonProperty("orgStreetAddress", NullValueHandling = NullValueHandling.Ignore)]
        public string OrgStreetAddress { get; set; }

        [JsonProperty("orgCityProvPostalCodeCountry", NullValueHandling = NullValueHandling.Ignore)]
        public string OrgCityProvPostalCodeCountry { get; set; }

        [JsonProperty("emailAddress", NullValueHandling = NullValueHandling.Ignore)]
        public string EmailAddress { get; set; }

        [JsonProperty("phoneNumber", NullValueHandling = NullValueHandling.Ignore)]
        public string PhoneNumber { get; set; }
    }
}
