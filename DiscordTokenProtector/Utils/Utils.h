#pragma once
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <random>
#include <future>
#include <fstream>
#include <string>
#include <Windows.h>
#include "shlobj.h"

class EasyAsync {
public:
    EasyAsync(std::function<void()> fn, bool startOnInit = false) : m_fn(fn) {
        if (startOnInit) start();
    }

    void start() {
        if (m_isRunning) return;

        m_async = std::async(std::launch::async, m_fn);
        m_isRunning = true;
    }

    bool isRunning() {
        if (m_isRunning)
            m_isRunning = m_async.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;

        return m_isRunning;
    }

    void wait() {
        m_async.wait();
    }

private:
    std::function<void()> m_fn;
    std::future<void> m_async;
    bool m_isRunning = false;
};

inline std::string getFileContent(const std::string& filename) {
    std::ifstream fileStream(filename);
    if (fileStream.is_open()) {
        return std::string((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
    }
    return std::string();
}

template<class T>
inline void removeTaillingNulls(T& data) {
    if (auto pos = data.find('\000'); pos != T::npos)
        data.erase(pos);
}

inline std::wstring getAppDataPathW() {
    TCHAR szPath[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath)) || wcsstr(szPath, L"AppData") == nullptr) {
        size_t required_size;
        _wgetenv_s(&required_size, szPath, L"APPDATA");//backup method
    }
    return std::wstring(szPath);
}

#ifndef DISABLE_AUTOSTART
inline std::wstring getStartupPath() {
    TCHAR szPath[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, szPath))) {
        g_logger.error("Failed SHGetFolderPathW CSIDL_STARTUP");
        return std::wstring();
    }
    return std::wstring(szPath);
}

//https://docs.microsoft.com/fr-fr/windows/win32/shell/links?redirectedfrom=MSDN#Shellink_Creating_Shortcut
inline HRESULT CreateLink(LPCWSTR lpszPathObj, LPCWSTR lpszPathLink, LPCWSTR pszDir, LPCWSTR lpszDesc) {
    HRESULT hres;
    IShellLink* psl;

    // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
    // has already been called.
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
    if (SUCCEEDED(hres))
    {
        IPersistFile* ppf;

        // Set the path to the shortcut target and add the description. 
        psl->SetPath(lpszPathObj);
        psl->SetWorkingDirectory(pszDir);
        psl->SetDescription(lpszDesc);

        // Query IShellLink for the IPersistFile interface, used for saving the 
        // shortcut in persistent storage. 
        hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

        if (SUCCEEDED(hres))
        {
            // Save the link by calling IPersistFile::Save. 
            hres = ppf->Save(lpszPathLink, TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    return hres;
}
#endif

//https://stackoverflow.com/a/58467162/13544464
inline std::string getRandomUUID() {
    static std::random_device dev;
    static std::mt19937 rng(dev());

    std::uniform_int_distribution<int> dist(0, 15);

    const char* v = "0123456789abcdef";
    const bool dash[] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 };

    std::string res;
    for (int i = 0; i < 16; i++) {
        if (dash[i]) res += "-";
        res += v[dist(rng)];
        res += v[dist(rng)];
    }
    return res;
}