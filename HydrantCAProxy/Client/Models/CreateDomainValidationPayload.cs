// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.  You may obtain a
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
// required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for
// thespecific language governing permissions and limitations under the
// License.
using Keyfactor.HydrantId.Client.Models.Enums;
using Keyfactor.HydrantId.Interfaces;
using Newtonsoft.Json;

namespace Keyfactor.HydrantId.Client.Models
{
    public class CreateDomainValidationPayload : ICreateDomainValidationPayload
    {
        [JsonProperty("accountId", NullValueHandling = NullValueHandling.Ignore)]
        public string AccountId { get;set; }

        [JsonProperty("domain", NullValueHandling = NullValueHandling.Ignore)]
        public string DomainName { get;set; }

        [JsonProperty("validator", NullValueHandling = NullValueHandling.Ignore)]
        public string Validator { get;set; }

        // The organization the domain should be associated with, taken from the enrolling
        // policy's organizationId. HydrantID policies issue under an organization and
        // POST /api/v2/csr rejects an enrollment whose domains are not associated with it
        // ("No valid domains associated with organization for <validator> policy"), so this
        // has to be supplied when the validation record is created.
        [JsonProperty("organizationIds", NullValueHandling = NullValueHandling.Ignore)]
        public string OrganizationIds { get;set; }

        [JsonProperty("method", NullValueHandling = NullValueHandling.Ignore)]
        public ValidationMethod? Method { get;set; }

        [JsonProperty("payload", NullValueHandling = NullValueHandling.Ignore)]
        public object Payload { get;set; }

    }
}
