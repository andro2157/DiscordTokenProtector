#pragma once
#include "../Includes.h"
#include "../Utils/Utils.h"

#include <nlohmann/json.hpp>

constexpr auto CONFIG_PATH = /*%APPDATA%*/L"\\DiscordTokenProtector\\";
constexpr auto CONFIG_FILENAME = L"config.json";

class Config {
public:
	Config();
	~Config();

	template<typename T>
	void write(const std::string& key, T value) {
		m_cache[key] = value;
		save();
	}

	template<typename T>
	T read(const std::string& key) {
		load();
		return m_cache[key].get<T>();
	}

	bool save();
	bool load();

	static std::wstring getConfigPath();

private:
	void openFile();
	void reopenFile(bool remove = false);

	std::fstream m_file;
	nlohmann::json m_cache;
	std::mutex m_mutex;
};

inline std::unique_ptr<Config> g_config;