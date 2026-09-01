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
using System.Collections.Generic;
using System.IO;
using Keyfactor.HydrantId.Client.Models;
using Keyfactor.HydrantId.Client.Models.Enums;
using Keyfactor.HydrantId.Interfaces;
using Keyfactor.HydrantId.Exceptions;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Microsoft.Extensions.Logging;
using Keyfactor.Logging;
using LogHandler = Keyfactor.Logging.LogHandler;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.Extensions.CAPlugin.HydrantId;
using System.Linq;

namespace Keyfactor.HydrantId
{
    public class RequestManager
    {
        private static readonly ILogger Log = LogHandler.GetClassLogger<RequestManager>();

        // Default values for the template parameters declared in
        // GetTemplateParameterAnnotations(). Keyfactor Command does not populate a
        // template's parameter collection with these annotation defaults until the
        // template has been saved, so an enrollment against a template that was added
        // but never saved arrives with the keys absent. Falling back to these defaults
        // keeps enrollment working in that state instead of throwing
        // ("The given key ... was not present in the dictionary"). See ADO 81803 / 84076.
        private static readonly Dictionary<string, object> TemplateParameterDefaults =
            HydrantIdCAPluginConfig.GetTemplateParameterAnnotations()
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value.DefaultValue);

        /// <summary>
        /// Returns the enrollment parameter value supplied by Command, falling back to the
        /// default declared in <see cref="HydrantIdCAPluginConfig.GetTemplateParameterAnnotations"/>
        /// when the key is absent or blank. Returns null only when neither a supplied value
        /// nor an annotation default exists.
        /// </summary>
        public static string ResolveTemplateParameter(EnrollmentProductInfo productInfo, string key)
        {
            if (productInfo?.ProductParameters != null &&
                productInfo.ProductParameters.TryGetValue(key, out var supplied) &&
                !string.IsNullOrWhiteSpace(supplied))
            {
                return supplied;
            }

            if (TemplateParameterDefaults.TryGetValue(key, out var def) && def != null)
            {
                Log.LogTrace("ResolveTemplateParameter: '{Key}' not supplied by Command; using annotation default '{Default}'", key, def);
                return Convert.ToString(def);
            }

            return null;
        }

        public int GetMapReturnStatus(RevocationStatusEnum hydrantIdStatus)
        {
            try
            {
                Log.MethodEntry();
                int returnStatus;
                Log.LogTrace("GetMapReturnStatus: hydrantIdStatus={Status}", hydrantIdStatus);

                switch (hydrantIdStatus)
                {
                    case RevocationStatusEnum.Valid:
                        returnStatus = (int)EndEntityStatus.GENERATED;
                        break;
                    case RevocationStatusEnum.Pending:
                        returnStatus = (int)EndEntityStatus.INPROCESS;
                        break;
                    case RevocationStatusEnum.Revoked:
                        returnStatus = (int)EndEntityStatus.REVOKED;
                        break;
                    case RevocationStatusEnum.Failed:
                        returnStatus = (int)EndEntityStatus.FAILED;
                        break;
                    default:
                        Log.LogWarning("GetMapReturnStatus: unrecognized status '{Status}', defaulting to FAILED", hydrantIdStatus);
                        returnStatus = (int)EndEntityStatus.FAILED;
                        break;
                }

                Log.LogTrace("GetMapReturnStatus: {HydrantStatus} -> {MappedStatus}", hydrantIdStatus, returnStatus);
                Log.MethodExit();
                return returnStatus;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetMapReturnStatus: {Message}", e.Message);
                throw;
            }
        }

        public RevocationReasons GetMapRevokeReasons(uint keyfactorRevokeReason)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetMapRevokeReasons: keyfactorRevokeReason={Reason}", keyfactorRevokeReason);

                RevocationReasons returnStatus;
                switch (keyfactorRevokeReason)
                {
                    case 0:
                        returnStatus = RevocationReasons.Unspecified;
                        break;
                    case 1:
                        returnStatus = RevocationReasons.KeyCompromise;
                        break;
                    case 3:
                        returnStatus = RevocationReasons.AffiliationChanged;
                        break;
                    case 4:
                        returnStatus = RevocationReasons.Superseded;
                        break;
                    case 5:
                        returnStatus = RevocationReasons.CessationOfOperation;
                        break;
                    default:
                        Log.LogError("GetMapRevokeReasons: unsupported revoke reason {Reason}", keyfactorRevokeReason);
                        throw new RevokeReasonNotSupportedException($"Revoke reason {keyfactorRevokeReason} is not supported. Supported values: 0 (Unspecified), 1 (KeyCompromise), 3 (AffiliationChanged), 4 (Superseded), 5 (CessationOfOperation).");
                }

                Log.LogTrace("GetMapRevokeReasons: {Input} -> {Mapped}", keyfactorRevokeReason, returnStatus);
                Log.MethodExit();
                return returnStatus;
            }
            catch (RevokeReasonNotSupportedException)
            {
                throw;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetMapRevokeReasons: {Message}", e.Message);
                throw;
            }
        }

        public RevokeCertificateReason GetRevokeRequest(RevocationReasons reason)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetRevokeRequest: reason={Reason}", reason);
                return new RevokeCertificateReason
                {
                    Reason = reason
                };
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetRevokeRequest: {Message}", e.Message);
                throw;
            }
        }

        public CertificatesPayload GetCertificatesListRequest(int offset, int limit)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetCertificatesListRequest: offset={Offset}, limit={Limit}", offset, limit);
                return new CertificatesPayload
                {
                    Limit = limit,
                    Offset = offset,
                    Status = 0,
                    Expired = true
                };
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetCertificatesListRequest: {Message}", e.Message);
                throw;
            }
        }

        public CertRequestBody GetEnrollmentRequest(Guid? policyId, EnrollmentProductInfo productInfo, string csr, Dictionary<string, string[]> san)
        {
            Log.MethodEntry();
            Log.LogTrace("GetEnrollmentRequest: policyId={PolicyId}, productID='{ProductId}', csr length={CsrLen}",
                policyId?.ToString() ?? "(null)", productInfo?.ProductID ?? "(null)", csr?.Length ?? 0);

            if (productInfo == null)
                throw new ArgumentNullException(nameof(productInfo), "productInfo cannot be null.");
            if (string.IsNullOrEmpty(csr))
                throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");

            // Resolve validity from the supplied parameters, falling back to annotation
            // defaults when Command has not yet populated them (unsaved template — ADO 81803).
            var validityPeriod = ResolveTemplateParameter(productInfo, HydrantIdCAPluginConfig.EnrollmentParametersConstants.ValidityPeriod);
            var validityUnits = ResolveTemplateParameter(productInfo, HydrantIdCAPluginConfig.EnrollmentParametersConstants.ValidityUnits);

            if (string.IsNullOrWhiteSpace(validityPeriod))
                throw new ArgumentException("ValidityPeriod was not supplied and no annotation default is defined.", nameof(productInfo));
            if (string.IsNullOrWhiteSpace(validityUnits))
                throw new ArgumentException("ValidityUnits was not supplied and no annotation default is defined.", nameof(productInfo));

            var request = new CertRequestBody
            {
                Policy = policyId,
                Csr = csr,
                DnComponents = GetDnComponentsRequest(csr),
                Validity = GetValidity(validityPeriod, Convert.ToInt16(validityUnits))
            };

            if (san != null && san.Count > 0)
            {
                request.SubjectAltNames = GetSansRequest(san);
            }

            Log.MethodExit();
            return request;
        }


        public RenewalRequest GetRenewalRequest(string csr, bool reuseCsr)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetRenewalRequest: csr length={CsrLen}, reuseCsr={ReuseCsr}", csr?.Length ?? 0, reuseCsr);

                if (string.IsNullOrEmpty(csr) && !reuseCsr)
                    throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty when reuseCsr is false.");

                return new RenewalRequest
                {
                    Csr = csr,
                    ReuseCsr = reuseCsr
                };
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetRenewalRequest: {Message}", e.Message);
                throw;
            }
        }

        private CertRequestBodyValidity GetValidity(string period, int units)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetValidity: period='{Period}', units={Units}", period ?? "(null)", units);

                if (string.IsNullOrEmpty(period))
                    throw new ArgumentNullException(nameof(period), "Validity period cannot be null or empty.");

                CertRequestBodyValidity validity = new CertRequestBodyValidity();
                switch (period)
                {
                    case "Years":
                        validity.Years = units;
                        break;
                    case "Months":
                        validity.Months = units;
                        break;
                    case "Days":
                        validity.Days = units;
                        break;
                    default:
                        throw new ArgumentException($"Unrecognized validity period '{period}'; expected 'Years', 'Months', or 'Days'.", nameof(period));
                }

                return validity;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetValidity: {Message}", e.Message);
                throw;
            }
        }

        public CertRequestBodySubjectAltNames GetSansRequest(Dictionary<string, string[]> sans)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetSansRequest: sans is {Null}, count={Count}",
                    sans == null ? "NULL" : "present", sans?.Count ?? 0);

                if (sans == null)
                    return new CertRequestBodySubjectAltNames();

                var san = new CertRequestBodySubjectAltNames();

                if (sans.TryGetValue("dnsname", out var dnsNames))
                {
                    san.Dnsname = dnsNames?.ToList() ?? new List<string>();
                    Log.LogTrace("GetSansRequest: dnsname count={Count}", san.Dnsname.Count);
                }

                if (sans.TryGetValue("ipaddress", out var ipAddresses))
                {
                    san.Ipaddress = ipAddresses?.ToList() ?? new List<string>();
                    Log.LogTrace("GetSansRequest: ipaddress count={Count}", san.Ipaddress.Count);
                }

                if (sans.TryGetValue("rfc822name", out var rfcNames))
                {
                    san.Rfc822Name = rfcNames?.ToList() ?? new List<string>();
                    Log.LogTrace("GetSansRequest: rfc822name count={Count}", san.Rfc822Name.Count);
                }

                if (sans.TryGetValue("upn", out var upns))
                {
                    san.Upn = upns?.ToList() ?? new List<string>();
                    Log.LogTrace("GetSansRequest: upn count={Count}", san.Upn.Count);
                }

                return san;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetSansRequest: {Message}", e.Message);
                throw;
            }
        }


        public List<string> GetDomainsToValidate(string csr, Dictionary<string, string[]> san)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetDomainsToValidate: csr length={CsrLen}, san count={Count}", csr?.Length ?? 0, san?.Count ?? 0);

                if (string.IsNullOrEmpty(csr))
                    throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");

                var domains = new List<string>();

                var cn = GetDnComponentsRequest(csr)?.Cn;
                if (!string.IsNullOrWhiteSpace(cn))
                    domains.Add(cn.Trim());

                var sanNames = GetSansRequest(san)?.Dnsname;
                if (sanNames != null)
                    domains.AddRange(sanNames.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()));

                var deduped = domains
                    .GroupBy(d => d, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .ToList();

                Log.LogTrace("GetDomainsToValidate: {Count} unique domain(s): {Domains}", deduped.Count, string.Join(", ", deduped));
                Log.MethodExit();
                return deduped;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetDomainsToValidate: {Message}", e.Message);
                throw;
            }
        }

        public CreateDomainValidationPayload GetCreateDomainValidationRequest(
            string domain, string validatorId, string accountId = null, DomainValidationOrgPayload orgPayload = null)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetCreateDomainValidationRequest: domain='{Domain}', validatorId='{ValidatorId}', accountId='{AccountId}', orgPayload is {OrgPayloadNull}",
                    domain ?? "(null)", validatorId ?? "(null)", accountId ?? "(null)", orgPayload == null ? "NULL" : "present");

                if (string.IsNullOrEmpty(domain))
                    throw new ArgumentNullException(nameof(domain), "domain cannot be null or empty.");
                if (string.IsNullOrEmpty(validatorId))
                    throw new ArgumentNullException(nameof(validatorId), "validatorId cannot be null or empty.");

                var payload = new CreateDomainValidationPayload
                {
                    DomainName = domain,
                    Validator = validatorId,
                    Method = ValidationMethod.Dns,
                    // Some HydrantId tenants require accountId on this call despite Hawk auth
                    // already scoping the account -- omitted (not just blank) when not configured,
                    // since CreateDomainValidationPayload.AccountId ignores null on serialization.
                    AccountId = string.IsNullOrEmpty(accountId) ? null : accountId,
                    // Some validators (e.g. IdenTrust) additionally require organization/contact
                    // details in "payload" -- omitted entirely when the caller has none configured.
                    Payload = orgPayload
                };

                Log.MethodExit();
                return payload;
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetCreateDomainValidationRequest: {Message}", e.Message);
                throw;
            }
        }

        public EnrollmentResult GetEnrollmentResult(ICertificate enrollmentResult, AnyCAPluginCertificate cert)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetEnrollmentResult: enrollmentResult is {Null}, cert is {CertNull}",
                    enrollmentResult == null ? "NULL" : "present",
                    cert == null ? "NULL" : "present");

                if (enrollmentResult == null)
                {
                    Log.LogError("GetEnrollmentResult: enrollmentResult is null.");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Enrollment failed: could not get the certificate from the request tracking id."
                    };
                }

                if (!enrollmentResult.Id.HasValue)
                {
                    Log.LogError("GetEnrollmentResult: enrollmentResult.Id has no value.");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Enrollment failed: certificate response has no ID."
                    };
                }

                if (cert == null || string.IsNullOrEmpty(cert.Certificate))
                {
                    Log.LogWarning("GetEnrollmentResult: cert is null or has empty Certificate for ID={Id}", enrollmentResult.Id);
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Enrollment failed: could not retrieve certificate content."
                    };
                }

                Log.LogTrace("GetEnrollmentResult: success - ID={Id}, certificate length={Len}",
                    enrollmentResult.Id, cert.Certificate?.Length ?? 0);

                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.GENERATED,
                    CARequestID = enrollmentResult.Id.ToString(),
                    Certificate = cert.Certificate,
                    StatusMessage = "Order Successfully Created"
                };
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetEnrollmentResult: {Message}", e.Message);
                throw;
            }
        }

        public static Func<string, string> Pemify = ss =>
    ss.Length <= 64 ? ss : ss.Substring(0, 64) + "\n" + Pemify(ss.Substring(64));

        public CertRequestBodyDnComponents GetDnComponentsRequest(string csr)
        {
            try
            {
                Log.MethodEntry();
                Log.LogTrace("GetDnComponentsRequest: csr length={CsrLen}", csr?.Length ?? 0);

                if (string.IsNullOrEmpty(csr))
                    throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");

                var c = String.Empty;
                var o = String.Empty;
                var cn = string.Empty;
                var l = string.Empty;
                var st = string.Empty;
                var ou = string.Empty;

                var cert = csr;
                Log.LogTrace("GetDnComponentsRequest: parsing CSR");

                var reader = new PemReader(new StringReader(cert));
                var pemObject = reader.ReadObject();
                if (pemObject == null)
                {
                    Log.LogWarning("GetDnComponentsRequest: PemReader returned null object");
                    return new CertRequestBodyDnComponents { Cn = cn, Ou = new List<string> { ou }, O = o, L = l, St = st, C = c };
                }

                if (pemObject is Pkcs10CertificationRequest req)
                {
                    var info = req.GetCertificationRequestInfo();
                    Log.LogTrace("GetDnComponentsRequest: subject='{Subject}'", info?.Subject?.ToString() ?? "(null)");

                    if (info?.Subject != null)
                    {
                        var array1 = info.Subject.ToString().Split(',');
                        foreach (var x in array1)
                        {
                            if (string.IsNullOrWhiteSpace(x))
                                continue;

                            var itemArray = x.Split('=');
                            if (itemArray.Length < 2)
                            {
                                Log.LogTrace("GetDnComponentsRequest: skipping malformed DN component '{Component}'", x);
                                continue;
                            }

                            switch (itemArray[0].Trim().ToUpper())
                            {
                                case "C":
                                    c = itemArray[1].Trim();
                                    break;
                                case "O":
                                    o = itemArray[1].Trim();
                                    break;
                                case "CN":
                                    cn = itemArray[1].Trim();
                                    break;
                                case "OU":
                                    ou = itemArray[1].Trim();
                                    break;
                                case "ST":
                                    st = itemArray[1].Trim();
                                    break;
                                case "L":
                                    l = itemArray[1].Trim();
                                    break;
                            }
                        }
                    }
                }
                else
                {
                    Log.LogWarning("GetDnComponentsRequest: PEM object is not a PKCS10 request, type={Type}", pemObject.GetType().Name);
                }

                Log.LogTrace("GetDnComponentsRequest: CN='{Cn}', O='{O}', OU='{Ou}', C='{C}', ST='{St}', L='{L}'",
                    cn, o, ou, c, st, l);

                return new CertRequestBodyDnComponents
                {
                    Cn = cn,
                    Ou = new List<string> { ou },
                    O = o,
                    L = l,
                    St = st,
                    C = c
                };
            }
            catch (Exception e)
            {
                Log.LogError(e, "Error occurred in RequestManager.GetDnComponentsRequest: {Message}", e.Message);
                throw;
            }
        }
    }
}
