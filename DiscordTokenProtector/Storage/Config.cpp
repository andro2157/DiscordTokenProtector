#include "Config.h"

using nlohmann::json;

static json getDefaultConfig() {
	json config;

	config["version"] = 1;
	config["auto_start"] = true;
	config["auto_start_discord"] = false;
	config["integrity"] = true;
	config["integrity_checkhash"] = true;
	config["integrity_checkexecutable"] = true;
	config["integrity_checkmodule"] = true;
	config["integrity_checkresource"] = true;
	config["integrity_checkscripts"] = true;
	config["integrity_allowbetterdiscord"] = false;
	config["integrity_redownloadhashes"] = false;
	config["iterations_key"] = 0;//TODO move to SecureKV?
	config["iterations_iv"] = 0;//TODO move to SecureKV?

	return config;
}

Config::Config() {
	if (!std::filesystem::exists(getConfigPath()))
		std::filesystem::create_directory(getConfigPath());
	openFile();
	load();
}

Config::~Config() {
	m_file.close();
}

void Config::openFile() {
	if (!std::filesystem::exists(getConfigPath() + CONFIG_FILENAME)) {
		//create an empty file so that openFile doesn't fail (due to the std::ios::in flag)
		std::ofstream(getConfigPath() + CONFIG_FILENAME).close();
	}
	m_file.open(getConfigPath() + CONFIG_FILENAME,
		std::ios::in | std::ios::out,
		_SH_DENYRW
	);
	if (!m_file.is_open())
		throw std::runtime_error("Failed to open config file!");
}

void Config::reopenFile(bool remove) {
	if (m_file.is_open()) m_file.close();
	if (remove) {
		try {
			std::filesystem::remove(getConfigPath() + CONFIG_FILENAME);
		}
		catch (std::exception& e) {
			g_logger.warning(sf() << "Failed to remove config file :" << e.what());
		}
	}
	openFile();
}

std::wstring Config::getConfigPath() {
	return getAppDataPathW() + CONFIG_PATH;
}

bool Config::save() {
	const std::lock_guard<std::mutex> lock(m_mutex);
	reopenFile(true);

	try {
		m_file << m_cache.dump(4) << std::flush;
	}
	catch (std::exception& e) {
		g_logger.error(sf() << "Failed to save config : " << e.what());
		return false;
	}

	return true;
}

bool Config::load() {
	bool saveWhenComplete = false;

	m_mutex.lock();

	m_file.seekg(0);
	std::string file_str((std::istreambuf_iterator<char>(m_file)), std::istreambuf_iterator<char>());

	json loadedConfig;
	try {
		loadedConfig = json::parse(file_str);
	}
	catch (std::exception& e) {
		g_logger.error(sf() << "Failed to load config : invalid JSON. " << e.what());
		g_logger.warning("Using default config!");

		m_cache = getDefaultConfig();
		m_mutex.unlock();
		save();
		return false;
	}

	const json defaultConfig = getDefaultConfig();
	json patch = json::diff(loadedConfig, defaultConfig);

	//Only add missing stuff
	patch.erase(std::remove_if(patch.begin(), patch.end(), [](const json& p) {
		return p["op"] != "add";
	}), patch.end());

	if (!patch.empty()) {
		g_logger.warning(sf() << "Incomplete config file. Adding " << patch.size() << " missing entries.");
		loadedConfig = loadedConfig.patch(patch);
		saveWhenComplete = true;
	}

	m_cache = loadedConfig;

	g_logger.info(sf() << "Loaded config");

	if (saveWhenComplete) {
		m_mutex.unlock();
		return save();
	}

	m_mutex.unlock();
	return true;
}