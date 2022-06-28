#pragma once
#define CURL_STATICLIB
#include <curl/curl.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "advapi32.lib")
//#pragma comment(lib, "libcurl.lib")

#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <iostream>
#include "../Crypto/Crypto.h"

class curl_exception : public std::runtime_error {
public:
	curl_exception(const std::string& cause) : std::runtime_error(cause) {}
};

inline std::wstring getWindowsProxy(const std::wstring& url = L"") {
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieProxy;
	auto freeProxyData = [&ieProxy]() {
		if (ieProxy.lpszAutoConfigUrl != nullptr)	GlobalFree(ieProxy.lpszAutoConfigUrl);
		if (ieProxy.lpszProxy != nullptr)			GlobalFree(ieProxy.lpszProxy);
		if (ieProxy.lpszProxyBypass != nullptr)		GlobalFree(ieProxy.lpszProxyBypass);
	};

	if (!WinHttpGetIEProxyConfigForCurrentUser(&ieProxy)) {
		g_logger.warning(sf() << "getWindowsProxy : Failed WinHttpGetIEProxyConfigForCurrentUser : " << GetLastError());
		freeProxyData();
		return L"";
	}

	if (ieProxy.lpszProxy == nullptr) {
		freeProxyData();
		return L"";
	}

	if (ieProxy.lpszProxyBypass != nullptr && !url.empty()) {
		std::wstringstream url_ss(ieProxy.lpszProxyBypass);
		std::wstring domain;
		while (std::getline(url_ss, domain, L';')) {
			if (url.rfind(domain.c_str(), 0) == 0) {
				freeProxyData();
				return L"";
			}
		}
	}

	std::wstring out(ieProxy.lpszProxy);
	freeProxyData();

	return out;
}

//https://stackoverflow.com/a/36401787/13544464
inline size_t CurlWrite_CallbackFunc_SecureString(void* contents, size_t size, size_t nmemb, secure_string* s) {
	size_t newLength = size * nmemb;
	try {
		s->append((char*)contents, newLength);
	}
	catch (std::bad_alloc& e) {
		//handle memory problem
		return 0;
	}
	return newLength;
}

//Pretty much the same code as curl_slist_free_all
//https://github.com/curl/curl/blob/master/lib/slist.c#L129
inline void curl_slist_secure_zero(struct curl_slist* list) {
	struct curl_slist* next;
	struct curl_slist* item;

	if (!list)
		return;

	item = list;
	do {
		next = item->next;
		SecureZeroMemory(item->data, strlen(item->data));
		item = next;
	} while (next);
}

inline void cURL_post(std::string url, curl_slist* header, const secure_string& postData, secure_string& output, const std::string& customRequest = "") {
	CURL* curl = curl_easy_init();
	if (!curl) throw std::runtime_error("Failed to initialize cURL");

	CURLcode res;

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	if (header != nullptr)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);

	if (!postData.empty())
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

	if (!customRequest.empty())//PATCH, PUT, ...
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, customRequest.c_str());

	//Let's just hope that no one uses proxies with unicode chars
	std::string proxy = ws2s(getWindowsProxy(s2ws(url)));
	if (!proxy.empty()) {
		curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
		//curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTPS); //Doesn't work with it for some reason
	}

	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_SecureString);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

	//curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
	curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST | CURLSSLOPT_NATIVE_CA);

	char errbuf[CURL_ERROR_SIZE];
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	errbuf[0] = 0;

	res = curl_easy_perform(curl);

	curl_slist_secure_zero(header);//Avoid leaving the auth token in the memory
	curl_slist_free_all(header);

	if (errbuf[0]) {
		g_logger.warning(sf() << "Failed req to " << url
			<< (proxy.empty() ? " (No proxy) " : std::string(sf() << " (Proxy : " << proxy << ") "))
			<< "Code : " << res << " Error Buffer : " << errbuf);
	}

	if (res != CURLE_OK) throw curl_exception(curl_easy_strerror(res));

	curl_easy_cleanup(curl);
}

inline void cURL_get(std::string url, curl_slist* header, secure_string& output) {
	cURL_post(url, header, "", output);
}