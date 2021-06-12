#pragma once
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <fstream>
#include <random>
#include <Windows.h>
#include "shlobj.h"

inline std::string ws2s(const std::wstring& wstr, int codePage = GetACP()) {
	if (wstr.empty()) return std::string();
	int size_needed = WideCharToMultiByte(codePage, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(codePage, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

inline std::wstring getAppDataPathW() {
    TCHAR szPath[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath)) || wcsstr(szPath, L"AppData") == nullptr) {
        size_t required_size;
        _wgetenv_s(&required_size, szPath, L"APPDATA");//backup method
    }
    return std::wstring(szPath);
}

//https://stackoverflow.com/a/12468109/13544464
inline std::string randomString(size_t length) {
    auto randchar = []() -> char {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}

template<typename String, typename Stream>
class StringFormat {
public:
    StringFormat() {}

    operator String() {
        return m_ss.str();
    }

    template <class T>
    StringFormat& operator<< (const T& data) {
        m_ss << data;
        return *this;
    }

private:
    Stream m_ss;
};

typedef StringFormat<std::string, std::stringstream> sf;
typedef StringFormat<std::wstring, std::wstringstream> wsf;