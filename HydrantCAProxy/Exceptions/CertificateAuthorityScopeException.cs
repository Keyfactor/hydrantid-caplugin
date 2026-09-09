// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.  You may obtain a
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
// required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for
// thespecific language governing permissions and limitations under the
// License.
using System;

namespace Keyfactor.HydrantId.Exceptions
{
    /// <summary>
    /// An operation was requested against a certificate or policy that belongs to a different
    /// certificate authority within the same HydrantId tenant than the one this logical CA is
    /// scoped to by CertificateAuthorityId. Distinct from a generic failure so the scoping
    /// message reaches the caller intact instead of being reported as an unexpected error.
    /// </summary>
    public class CertificateAuthorityScopeException : Exception
    {
        public CertificateAuthorityScopeException(string message) : base(message)
        {
        }
    }
}
