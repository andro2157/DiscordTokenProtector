#include "FileCert.h"

//https://docs.microsoft.com/fr-FR/troubleshoot/windows/win32/get-information-authenticode-signed-executables
BOOL VerifySignatureIssuer(std::wstring sourceFile, std::wstring subject) {
    DWORD dwEncoding, dwContentType, dwFormatType, dwSignerInfo;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;

    PCMSG_SIGNER_INFO pSignerInfo = nullptr;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        sourceFile.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL)) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed CryptQueryObject : " << GetLastError());
        return false;
    }

    if (!CryptMsgGetParam(hMsg,
        CMSG_SIGNER_INFO_PARAM,
        0,
        NULL,
        &dwSignerInfo)) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed CryptMsgGetParam : " << GetLastError());
        return false;
    }

    pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(LocalAlloc(LPTR, dwSignerInfo));
    if (!pSignerInfo) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed to allocate memory for Signer Info.");
        return false;
    }

    if (!CryptMsgGetParam(hMsg,
        CMSG_SIGNER_INFO_PARAM,
        0,
        (PVOID)pSignerInfo,
        &dwSignerInfo)) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed CryptMsgGetParam : " << GetLastError());
        return false;
    }

    CERT_INFO CertInfo;
    CertInfo.Issuer = pSignerInfo->Issuer;
    CertInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        (PVOID)&CertInfo,
        NULL);

    if (!pCertContext) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed CertFindCertificateInStore : " << GetLastError());
        return false;
    }

    DWORD dwData = pCertContext->pCertInfo->Subject.cbData;
    LPTSTR szName = reinterpret_cast<LPTSTR>(LocalAlloc(LPTR, dwData * sizeof(TCHAR)));
    if (!szName) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed to allocate memory for the subject name.");
        return false;
    }

    if (!CertGetNameString(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        szName,
        dwData)) {
        g_logger.error(sf() << __FUNCSIG__ " : Failed CertGetNameString : " << GetLastError());
        return false;
    }

    bool match = false;
    if (std::wstring(szName) == subject) match = true;

    LocalFree(szName);

    if (pSignerInfo != NULL) LocalFree(pSignerInfo);
    if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
    if (hStore != NULL) CertCloseStore(hStore, 0);
    if (hMsg != NULL) CryptMsgClose(hMsg);

    return match;
}

//https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);


    bool trusted = false;

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        //wprintf_s(L"The file \"%s\" is signed and the signature "
        //    L"was verified.\n",
        //    pwszSourceFile);
        trusted = true;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            g_logger.warning(sf() << __FUNCSIG__ " : The file \"" << ws2s(pwszSourceFile) << "\" is not signed.");
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            g_logger.warning(sf() << __FUNCSIG__ " : An unknown error occurred trying to verify the signature of the \"" << ws2s(pwszSourceFile) << "\" file.");
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        g_logger.warning(sf() << __FUNCSIG__ " : The signature is present, but specifically disallowed. " << ws2s(pwszSourceFile));
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        g_logger.warning(sf() << __FUNCSIG__ " : The signature is present, but not trusted." << ws2s(pwszSourceFile));
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        g_logger.warning(sf() << 
            "CRYPT_E_SECURITY_SETTINGS - The hash representing the subject or"
            "the publisher wasn't explicitly trusted by the admin and admin"
            "policy has disabled user trust. No signature, publisher or timestamp errors." << ws2s(pwszSourceFile));
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        g_logger.warning(sf() << __FUNCSIG__ " : Error is: " << lStatus << " " << ws2s(pwszSourceFile));

        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return true;
}