#pragma once
#define CURL_STATICLIB
#include <curl/curl.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "advapi32.lib")

#include <iostream>
#include "../Crypto/Crypto.h"

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

	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_SecureString);

	res = curl_easy_perform(curl);

	curl_slist_secure_zero(header);//Avoid leaving the auth token in the memory
	curl_slist_free_all(header);

	if (res != CURLE_OK) throw std::exception(curl_easy_strerror(res));

	curl_easy_cleanup(curl);
}

inline void cURL_get(std::string url, curl_slist* header, secure_string& output) {
	cURL_post(url, header, "", output);
}