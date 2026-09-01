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
    public class Domain : IDomain
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public string Id { get;set; }

        [JsonProperty("validator", NullValueHandling = NullValueHandling.Ignore)]
        public string Validator { get;set; }

        [JsonProperty("accountId", NullValueHandling = NullValueHandling.Ignore)]
        public string AccountId { get;set; }

        [JsonProperty("organizationIds", NullValueHandling = NullValueHandling.Ignore)]
        public string OrganizationIds { get;set; }

        [JsonProperty("domain", NullValueHandling = NullValueHandling.Ignore)]
        public string DomainName { get;set; }

        [JsonProperty("method", NullValueHandling = NullValueHandling.Ignore)]
        public ValidationMethod? Method { get;set; }

        [JsonProperty("code", NullValueHandling = NullValueHandling.Ignore)]
        public string Code { get;set; }

        [JsonProperty("codeInstructions", NullValueHandling = NullValueHandling.Ignore)]
        public string CodeInstructions { get;set; }

        [JsonProperty("message", NullValueHandling = NullValueHandling.Ignore)]
        public string Message { get;set; }

        [JsonProperty("payload", NullValueHandling = NullValueHandling.Ignore)]
        public object Payload { get;set; }

        [JsonProperty("status", NullValueHandling = NullValueHandling.Ignore)]
        public DomainStatusEnum? Status { get;set; }

        [JsonProperty("domainValidUntil", NullValueHandling = NullValueHandling.Ignore)]
        public string DomainValidUntil { get;set; }

        [JsonProperty("codeValidUntil", NullValueHandling = NullValueHandling.Ignore)]
        public string CodeValidUntil { get;set; }

        [JsonProperty("createdAt", NullValueHandling = NullValueHandling.Ignore)]
        public string CreatedAt { get;set; }

        [JsonProperty("updatedAt", NullValueHandling = NullValueHandling.Ignore)]
        public string UpdatedAt { get;set; }

    }
}
