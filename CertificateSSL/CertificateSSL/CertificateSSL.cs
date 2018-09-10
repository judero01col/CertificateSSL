using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertificateSSLClass
{
    public class CertificateSSL
    {
        string strAlgorithmName;       
        string IssuerFriendly;
        string IssuerName;
        int ExpirationLengthInYear = 3;
        CX509PrivateKey PrivateKey;

        public CertificateSSL(string strAlgorithmName, string IssuerFriendly, string IssuerName, int ExpirationLengthInYear, CX509PrivateKey PrivateKey = null)
        {
            this.strAlgorithmName = strAlgorithmName;
            this.IssuerFriendly = IssuerFriendly;
            this.IssuerName = IssuerName;
            this.ExpirationLengthInYear = ExpirationLengthInYear;
            this.PrivateKey = PrivateKey;

            if (this.PrivateKey == null)
                this.PrivateKey = GeneratePrivateKey(4096);
        }

        public CX509PrivateKey GeneratePrivateKey (int KeyLength)
        {
            try
            {
                CCspInformations objCSPs = new CCspInformations();
                objCSPs.AddAvailableCsps();

                // create a new private key for the certificate
                CX509PrivateKey privateKey = new CX509PrivateKey();
                privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
                privateKey.MachineContext = true;
                privateKey.Length = KeyLength;
                privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE;
                privateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
                privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
                privateKey.CspInformations = objCSPs;

                privateKey.ExportPolicy =
                X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_ARCHIVING_FLAG |
                X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG |
                X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG |
                X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

                privateKey.Create();

                return privateKey;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public bool GenSelfSignedCert()
        {
            try
            {
                X509Certificate2 cert1 = CreateSelfSignedCertificate(IssuerFriendly, IssuerName);
                InstalCertificate(cert1);

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public bool GenSelfSignedCert(string FriendlyName, string SubjectName)
        {
            try
            {
                X509Certificate2 cert1 = CreateSelfSignedCertificate(FriendlyName, SubjectName);
                InstalCertificate(cert1);

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public void Import(string Key)
        {
            CX509PrivateKey PrivateKey = new CX509PrivateKey();
            PrivateKey.Import("PRIVATEBLOB", Key, EncodingType.XCN_CRYPT_STRING_BASE64);
        }

        public string Export()
        {
            return PrivateKey.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64);
        }

        public X509Certificate2 CreateSelfSignedCertificate(string FriendlyName, string SubjectName)
        {
            try
            {
                // Create DN for Subject
                CX500DistinguishedName dnSubject = new CX500DistinguishedName();
                dnSubject.Encode(String.Format(@"CN={0}", SubjectName), X500NameFlags.XCN_CERT_NAME_STR_NONE);

                // Create DN for Issuer
                CX500DistinguishedName dnIssuer = new CX500DistinguishedName();
                dnIssuer.Encode(String.Format(@"CN={0}", IssuerName), X500NameFlags.XCN_CERT_NAME_STR_NONE);

                // Use the stronger SHA512 hashing algorithm
                CObjectId HashAlgorithm = new CObjectId();

                HashAlgorithm.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY, AlgorithmFlags.AlgorithmFlagsNone, strAlgorithmName);

                // add extended key usage if you want - look at MSDN for a list of possible OIDs
                CObjectId oid1 = new CObjectId();
                oid1.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // SSL Server

                CObjectId oid2 = new CObjectId();
                oid2.InitializeFromValue("1.3.6.1.5.5.7.3.2"); // SSL Client

                CObjectIds oidlist = new CObjectIds();
                oidlist.Add(oid1);
                oidlist.Add(oid2);

                CX509ExtensionEnhancedKeyUsage eku = new CX509ExtensionEnhancedKeyUsage();
                eku.InitializeEncode(oidlist);

                CX509ExtensionAlternativeNames objExtensionAlternativeNames = new CX509ExtensionAlternativeNames();
                {
                    CAlternativeNames altNames = new CAlternativeNames();

                    CAlternativeName dnsLocalHost = new CAlternativeName();
                    dnsLocalHost.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, "LOCALHOST");
                    altNames.Add(dnsLocalHost);

                    CAlternativeName dnsHostname = new CAlternativeName();
                    dnsHostname.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, Environment.MachineName);
                    altNames.Add(dnsHostname);

                    foreach (var ipAddress in Dns.GetHostAddresses(Dns.GetHostName()))
                    {
                        if ((ipAddress.AddressFamily == AddressFamily.InterNetwork) && !IPAddress.IsLoopback(ipAddress))
                        {
                            CAlternativeName dns = new CAlternativeName();
                            dns.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, ipAddress.ToString());
                            altNames.Add(dns);
                        }
                    }

                    objExtensionAlternativeNames.InitializeEncode(altNames);
                }

                //CX509ExtensionSmimeCapabilities smimeCapabilities = new CX509ExtensionSmimeCapabilities();
                //smimeCapabilities.SmimeCapabilities.AddAvailableSmimeCapabilities(false);

                CX509ExtensionBasicConstraints basicConst = new CX509ExtensionBasicConstraints();
                basicConst.InitializeEncode(dnSubject.Name == dnIssuer.Name ? true : false, 1);

                // Key Usage Extension 
                CX509ExtensionKeyUsage objExtensionKeyUsage = new CX509ExtensionKeyUsage();
                objExtensionKeyUsage.InitializeEncode(
                   CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                   CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
                   CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
                   CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE |
                   CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE
                );

                // Create the self signing request
                CX509CertificateRequestCertificate cert = new CX509CertificateRequestCertificate();
                cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, PrivateKey, "");
                cert.Subject = dnSubject;
                cert.Issuer = dnIssuer;
                cert.NotBefore = DateTime.Today.AddDays(-1);
                cert.NotAfter = DateTime.Today.AddYears(ExpirationLengthInYear);

                cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
                cert.X509Extensions.Add((CX509Extension)objExtensionAlternativeNames);
                cert.X509Extensions.Add((CX509Extension)objExtensionKeyUsage);
                cert.X509Extensions.Add((CX509Extension)basicConst);
                //cert.X509Extensions.Add((CX509Extension)smimeCapabilities);
                cert.HashAlgorithm = HashAlgorithm; // Specify the hashing algorithm
                cert.Encode(); // encode the certificate

                // Do the final enrollment process
                CX509Enrollment enroll = new CX509Enrollment();
                enroll.InitializeFromRequest(cert); // load the certificate
                enroll.CertificateFriendlyName = FriendlyName; // Optional: add a friendly name

                string csr = enroll.CreateRequest(); // Output the request in base64 and install it back as the response

                // no password output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
                enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate, csr, EncodingType.XCN_CRYPT_STRING_BASE64, "");

                // no password, this is for internal consumption
                var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

                // instantiate the target class with the PKCS#12 data (and the empty password)
                // mark the private key as exportable (this is usually what you want to do)
                return new X509Certificate2(Convert.FromBase64String(base64encoded), "", X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public bool InstalCertificate(X509Certificate2 cert)
        {
            try
            {
                if (null != cert)
                {
                    byte[] pfx = cert.Export(X509ContentType.Pfx);
                    cert = new X509Certificate2(pfx, (string)null, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);

                    bool Resp = false;

                    using (X509Store Store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                    {
                        Store.Open(OpenFlags.ReadWrite);

                        foreach (var item in Store.Certificates)
                        {
                            if (item.FriendlyName.ToUpper() == cert.FriendlyName.ToUpper())
                            {
                                Store.Remove(item);
                            }
                        }

                        Store.Add(cert);
                        Store.Close();
                    }

                    using (X509Store Store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                    {
                        Store.Open(OpenFlags.ReadWrite);

                        foreach (var item in Store.Certificates)
                        {
                            if (item.FriendlyName.ToUpper() == cert.FriendlyName.ToUpper())
                            {
                                Store.Remove(item);
                            }
                        }

                        Store.Add(cert);
                        Store.Close();
                    }

                    //ClsMensajes.MensajeInformacionGeneral(string.Concat("Self-Signed certificate created successfully"));

                    return true;
                }
                else
                {
                    //ClsMensajes.ExceptionMessage("An error occurred while trying to generate the Self-Generated certificate", new Exception("Error generating certificate"));
                    return false;
                }
            }
            catch (Exception ex)
            {
                //ClsMensajes.ExceptionMessage("An error occurred while trying to generate the Self-Generated certificate", new Exception("Error generating certificate"));
                return false;
            }
        }
    }
}
