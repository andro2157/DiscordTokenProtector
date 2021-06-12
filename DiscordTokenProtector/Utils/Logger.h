#pragma once
#include <iostream>
#include <string>
#include <sstream>
#ifdef _PROD
#include <fstream>
#endif
#include <vector>
#include <mutex>

#include <Windows.h>
inline std::wstring s2ws(const std::string& str, int codePage = GetACP()) {
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(codePage, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(codePage, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

inline std::string ws2s(const std::wstring& wstr, int codePage = GetACP()) {
	if (wstr.empty()) return std::string();
	int size_needed = WideCharToMultiByte(codePage, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(codePage, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

constexpr auto MAX_LOGGER_BUFFER = 500;

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

class logger {
public:
	logger() {}

	void info(std::string message);
	void warning(std::string message);
	void error(std::string message);

	//Copy to avoid non-thread-safe operations
	std::vector<std::string> getBuffer() { return m_buffer; }

#ifdef _PROD
	void setOutFile(const std::wstring& fileDir) {
		m_outfileDir = fileDir;
		m_outfile.open(m_outfileDir, std::ios::app);
		if (!m_outfile.is_open())
			throw std::runtime_error("Failed to open log file.");
	}
#endif

private:
	std::string getCurrentTime();
	void pushBufferAndStream(std::string str, std::ostream& stream = std::cout);
	void pushBuffer(std::string str);
	void popBufferExcess(bool lock = false);

	std::mutex m_buffer_mutex;
	std::vector<std::string> m_buffer;
#ifdef _PROD
	std::ofstream m_outfile;
	std::wstring m_outfileDir;
#endif
};

extern logger g_logger;