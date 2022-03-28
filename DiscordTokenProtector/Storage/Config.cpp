#include "Config.h"
#include "../Crypto/CryptoUtils.h"
#include "../Context.h"

using nlohmann::json;

static json getDefaultConfig() {
	json config;

	config["version"] = 1;
	config["auto_start"] = true;
	config["auto_start_discord"] = false;

	//Integrity settings have been moved to SecureKV
	//config["integrity"] = true;
	//config["integrity_checkhash"] = true;
	//config["integrity_checkexecutable"] = true;
	//config["integrity_checkmodule"] = true;
	//config["integrity_checkresource"] = true;
	//config["integrity_checkscripts"] = true;
	//config["integrity_allowbetterdiscord"] = false;
	//config["integrity_redownloadhashes"] = false;

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
		std::string fileContent = m_cache.dump(4);
		m_file << fileContent << std::flush;

		if (g_context.state == State::TokenSecure)
			g_secureKV->write("config_hash", secure_string(CryptoUtils::SimpleSHA256(fileContent)), g_context.kd);
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

	if (g_context.state == State::TokenSecure) {
		secure_string fileHash(CryptoUtils::SimpleSHA256(file_str));

		secure_string savedHash = g_secureKV->read("config_hash", g_context.kd);

		if (savedHash.empty()) {
			g_secureKV->write("config_hash", fileHash, g_context.kd);
		}
		else if (savedHash != fileHash) {
			MessageBoxA(NULL, "Warning : config file tampered. Please double check your settings.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
			g_secureKV->write("config_hash", fileHash, g_context.kd);
		}
	}

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