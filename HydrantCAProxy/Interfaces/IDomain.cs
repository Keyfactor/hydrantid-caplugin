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

namespace Keyfactor.HydrantId.Interfaces
{
    public interface IDomain
    {
        string Id { get;set; }
        string Validator { get;set; }
        string AccountId { get;set; }
        string OrganizationIds { get;set; }
        string DomainName { get;set; }
        ValidationMethod? Method { get;set; }
        string Code { get;set; }
        string CodeInstructions { get;set; }
        string Message { get;set; }
        object Payload { get;set; }
        DomainStatusEnum? Status { get;set; }
        string DomainValidUntil { get;set; }
        string CodeValidUntil { get;set; }
        string CreatedAt { get;set; }
        string UpdatedAt { get;set; }
        string DeletedAt { get;set; }
    }
}
