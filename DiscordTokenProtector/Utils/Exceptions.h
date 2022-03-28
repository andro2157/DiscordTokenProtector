#pragma once
#include <stdexcept>

class user_info_exception : public std::runtime_error {
public:
	user_info_exception(const std::string& message) : std::runtime_error(message) {}
};

class invalid_token_exception : public std::runtime_error {
public:
	invalid_token_exception() : std::runtime_error("Invalid token") {}
};

class discord_not_running_exception : public std::runtime_error {
public:
	discord_not_running_exception() : std::runtime_error("Discord is not running") {}
};

class windows_api_exception : public std::runtime_error {
public:
	windows_api_exception(const std::string function_name, DWORD error_code)
		: std::runtime_error(sf() << "Failed " << function_name << " ! Error code : " << error_code),
			m_function_name(function_name), m_error_code(error_code) {}

	std::string getFunctionName() const { return m_function_name; }
	DWORD getErrorCode() const { return m_error_code; }

private:
	std::string m_function_name;
	DWORD m_error_code;
};

class no_token_exception : public std::runtime_error {
public:
	no_token_exception() : std::runtime_error("Failed to get token") {}
};