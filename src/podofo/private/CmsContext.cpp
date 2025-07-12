/**
 * SPDX-FileCopyrightText: (C) 2023 Francesco Pretto <ceztko@gmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 * SPDX-License-Identifier: MPL-2.0
 */

#include <podofo/private/PdfDeclarationsPrivate.h>
#include "CmsContext.h"

#include <date/date.h>

#include <podofo/private/OpenSSLInternal.h>
#include <openssl/ts.h>  // Add timestamp headers
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>

using namespace std;
using namespace PoDoFo;

// The following flags allow for streaming and editing of the attributes
#define CMS_FLAGS CMS_DETACHED | CMS_BINARY | CMS_PARTIAL | CMS_STREAM

static void addAttribute(CMS_SignerInfo* si, int(*addAttributeFun)(CMS_SignerInfo*, const char*, int, const void*, int),
    const string_view& nid, const bufferview& attr, bool octet);

CmsContext::CmsContext() :
    m_status(CmsContextStatus::Uninitialized),
    m_cert(nullptr),
    m_chain(nullptr),
    m_cms(nullptr),
    m_signer(nullptr),
    m_databio(nullptr),
    m_out(nullptr)
{
}

void CmsContext::Reset(const bufferview& cert, const std::vector<charbuff>& chain, const CmsContextParams& parameters)
{
    clear();

    m_parameters = parameters,

    loadX509Certificate(cert);
    loadX509Chain(chain);
    computeCertificateHash();

    reset();
    m_status = CmsContextStatus::Initialized;
}

CmsContext::~CmsContext()
{
    clear();
}

void CmsContext::AppendData(const bufferview& data)
{
    checkAppendStarted();

    if (m_out != nullptr)
    {
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidHandle,
            "The signer must be reset before appening new data");
    }

    auto mem = BIO_new_mem_buf(data.data(), (int)data.size());
    if (mem == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OutOfMemory, "BIO_new_mem_buf");

    // Append data to the internal CMS buffer and elaborate
    // See also CMS_final implementation for reference
    if (!SMIME_crlf_copy(mem, m_databio, CMS_FLAGS))
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError, "SMIME_crlf_copy");

    (void)BIO_flush(m_databio);
    BIO_free(mem);
}

void CmsContext::ComputeHashToSign(charbuff& hashToSign)
{
    checkAppendStarted();
    if (!m_parameters.SkipWriteSigningTime)
    {
        date::sys_seconds seconds;
        if (m_parameters.SigningTimeUTC.has_value())
            seconds = (date::sys_seconds)*m_parameters.SigningTimeUTC;
        else
            seconds = chrono::time_point_cast<chrono::seconds>(chrono::system_clock::now());

        ssl::cmsAddSigningTime(m_signer, seconds);
    }

    // Sign with external encryption
    // NOTE: Using openssl code would be CMS_dataFinal(m_cms, m_databio),
    // but we can't do that since in OpenSSL 1.1 there's not truly
    // easy way to plug an external encrypion, so we just ripped much
    // OpenSSL code to accomplish the task
    ssl::ComputeHashToSign(m_signer, m_databio, m_parameters.DoWrapDigest, hashToSign);
    m_status = CmsContextStatus::ComputedHash;
}

void CmsContext::ComputeSignature(const bufferview& signedHash, charbuff& signature)
{
    if (m_status != CmsContextStatus::ComputedHash)
    {
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic,
            "The signature can't be computed at this moment");
    }

    auto buf = (unsigned char*)OPENSSL_malloc(signedHash.size());
    if (buf == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError, "Error while setting encrypted hash");

    std::memcpy(buf, signedHash.data(), signedHash.size());
    auto signatuerAsn1 = CMS_SignerInfo_get0_signature(m_signer);

    ASN1_STRING_set0(signatuerAsn1, buf, (int)signedHash.size());

    m_out = BIO_new(BIO_s_mem());
    if (m_out == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OutOfMemory, "BIO_new");

    i2d_CMS_bio(m_out, m_cms);

    char* signatureData;
    size_t length = (size_t)BIO_get_mem_data(m_out, &signatureData);
    signature.assign(signatureData, signatureData + length);
    m_status = CmsContextStatus::ComputedSignature;
}


void CmsContext::AddAttribute(const string_view& nid, const bufferview& attr, bool signedAttr, bool asOctetString)
{
    if (signedAttr)
    {
        checkEnabledAddSignedAttributes();
        addAttribute(m_signer, CMS_signed_add1_attr_by_txt, nid, attr, asOctetString);
    }
    else
    {
        checkEnabledAddUnsignedAttributes();
        addAttribute(m_signer, CMS_unsigned_add1_attr_by_txt, nid, attr, asOctetString);
    }
}


void CmsContext::loadX509Certificate(const bufferview& cert)
{
    auto in = (const unsigned char*)cert.data();
    m_cert = d2i_X509(nullptr, &in, (int)cert.size());
    if (m_cert == nullptr)
    {
        string err("Certificate loading failed. Internal OpenSSL error:\n");
        ssl::GetOpenSSLError(err);
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError, err);
    }
}

void CmsContext::loadX509Chain(const std::vector<charbuff>& chain)
{
    m_chain = sk_X509_new_null();
    if (m_chain == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OutOfMemory, "sk_X509_new_null");

    for (const auto& certbuff : chain)
    {
        auto in = (const unsigned char*)certbuff.data();
        auto cert = d2i_X509(nullptr, &in, (int)certbuff.size());
        if (cert == nullptr)
        {
            string err("Certificate loading failed. Internal OpenSSL error:\n");
            ssl::GetOpenSSLError(err);
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError, err);
        }

        // sk_X509_push will increment the reference count of the certificate
        if (sk_X509_push(m_chain, cert) == 0)
        {
            X509_free(cert);
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError, "sk_X509_push");
        }
    }
}

void CmsContext::computeCertificateHash()
{
    int len;
    unsigned char* buf = nullptr;

    len = i2d_X509(m_cert, &buf);
    if (len < 0)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OutOfMemory, "i2d_X509");

    auto clean = [&]() {
        OPENSSL_free(buf);
    };

    try
    {
        m_certHash = ssl::ComputeHash({(const char*) buf, (size_t)len }, m_parameters.Hashing);
    }
    catch (...)
    {
        clean();
        throw;
    }
    clean();
}

void CmsContext::clear()
{
    if (m_cert != nullptr)
    {
        X509_free(m_cert);
        m_cert = nullptr;
    }

    if (m_chain != nullptr)
    {
        sk_X509_pop_free(m_chain, X509_free);
        m_chain = nullptr;
    }

    if (m_cms != nullptr)
    {
        CMS_ContentInfo_free(m_cms);
        m_cms = nullptr;
    }

    if (m_databio != nullptr)
    {
        BIO_free(m_databio);
        m_databio = nullptr;
    }

    if (m_out != nullptr)
    {
        BIO_free(m_out);
        m_out = nullptr;
    }
}

void CmsContext::reset()
{
    // By default CMS_sign uses SHA1, so create a partial context with streaming enabled
    m_cms = CMS_sign(nullptr, nullptr, m_chain, nullptr, CMS_FLAGS);
    if (m_cms == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OutOfMemory, "CMS_sign");

    // Set a signer with a SHA56 digest. Since CMS_PARTIAL is *not* passed,
    // the CMS structure is sealed
    auto sign_md = ssl::GetEVP_MD(m_parameters.Hashing);

    // Fake private key using public key from certificate
    // This allows to pass internal checks of CMS_add1_signer
    // since parameter "pk" can't be nullptr
    auto fakePrivKey = X509_get0_pubkey(m_cert);

    // NOTE: CAdES signatures don't want unneeded attributes
    m_signer = CMS_add1_signer(m_cms, m_cert, fakePrivKey, sign_md,
        m_parameters.SkipWriteMIMECapabilities ? CMS_NOSMIMECAP : 0);
    if (m_signer == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError, "CMS_add1_signer");

    if (m_parameters.AddSigningCertificateV2)
        ssl::AddSigningCertificateV2(m_signer, m_certHash, m_parameters.Hashing);
}

void CmsContext::checkAppendStarted()
{
    switch (m_status)
    {
        case CmsContextStatus::Initialized:
        {
            // Initialize the internal cms buffer for streaming
            // See also CMS_final implementation for reference
            m_databio = CMS_dataInit(m_cms, nullptr);
            if (m_databio == nullptr)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OutOfMemory, "CMS_dataInit");

            m_status = CmsContextStatus::AppendingData;
            break;
        }
        case CmsContextStatus::AppendingData:
        {
            // Do nothing
            break;
        }
        default:
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic,
                "The cms context is not initialized or signature was already computed");
        }
    }
}

void CmsContext::checkEnabledAddSignedAttributes()
{
    if (m_status != CmsContextStatus::Initialized)
    {
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic,
            "Signed attributes can be added only before data adding is started");
    }
}

void CmsContext::checkEnabledAddUnsignedAttributes()
{
    switch (m_status)
    {
        case CmsContextStatus::Initialized:
        case CmsContextStatus::AppendingData:
        case CmsContextStatus::ComputedHash:
            break;
        default:
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic,
                "Unsigned attributes can be added only after initialization and before signature computation");
    }
}

// CHECK-ME: Untested!
void addAttribute(CMS_SignerInfo* si, int(*addAttributeFun)(CMS_SignerInfo*, const char*, int, const void*, int),
    const string_view& nid, const bufferview& attr, bool octet)
{
    int type;
    const void* bytes;
    int len;
    ASN1_TYPE* asn1type = nullptr;

    if (nid == "1.2.840.113549.1.9.16.2.14") // id-aa-timeStampToken
    {
        // For timestamp token, we need to parse it as DER first
        const unsigned char* p = reinterpret_cast<const unsigned char*>(attr.data());
        TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(attr.size()));
        if (!response) {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError,
                "Failed to parse timestamp response");
        }

        // Get the TimeStampToken from TS_RESP
        PKCS7* token = TS_RESP_get_token(response);
        if (!token) {
            TS_RESP_free(response);
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError,
                "Failed to get timestamp token from response");
        }

        // Convert TimeStampToken to DER
        unsigned char* der = nullptr;
        int der_len = i2d_PKCS7(token, &der);
        if (der_len < 0) {
            TS_RESP_free(response);
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError,
                "Failed to convert timestamp token to DER");
        }

        // Add the DER-encoded token as an unsigned attribute
        int rc = addAttributeFun(si, nid.data(), V_ASN1_SEQUENCE, der, der_len);

        OPENSSL_free(der);
        TS_RESP_free(response);

        if (rc < 0) {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError,
                "Failed to add timestamp token as unsigned attribute");
        }
        return;
    }

    if (octet)
    {
        type = V_ASN1_OCTET_STRING;
        bytes = attr.data();
        len = (int)attr.size();
    }
    else
    {
        auto data = (const unsigned char*)attr.data();
        asn1type = d2i_ASN1_TYPE(nullptr, &data, (long)attr.size());
        if (asn1type == nullptr)
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError,
                "Unable to parse an ASN.1 object");
        }

        type = asn1type->type;
        bytes = asn1type->value.ptr;
        len = -1;
    }

    int rc = addAttributeFun(si, nid.data(), type, bytes, len);
    if (asn1type != nullptr)
        ASN1_TYPE_free(asn1type);

    if (rc < 0)
    {
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::OpenSSLError,
            "Unable to insert an attribute to the signer");
    }
}
