#pragma once
#include "../Includes.h"
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32.lib")

//https://docs.microsoft.com/fr-FR/troubleshoot/windows/win32/get-information-authenticode-signed-executables
BOOL VerifySignatureIssuer(std::wstring sourceFile, std::wstring subject);
//https://docs.microsoft.com/fr-fr/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);