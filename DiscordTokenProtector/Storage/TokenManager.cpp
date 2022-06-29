#include "TokenManager.h"
#include "../Context.h"

TokenManager g_tokenManager;

void TokenManager::init() {
	load();
	if (m_encryptedTokens.size() == 0) {
		g_logger.info("TokenManager : no tokens! Trying to migrate the old token.");
		if (migrateOldToken()) {
			setIndex(0);
			g_logger.info("TokenManager : Migration successfull !");
		}
		else {
			g_logger.error("TokenManager : Failed to migrate token...");
			throw empty_securekv_data_exception("tokens");
		}
	}
	else {
		m_idx = static_cast<size_t>(g_secureKV->read_int("tokens_idx", g_context.kd));
	}
}

void TokenManager::firstSetup(secure_string token, DiscordUserInfo info) {
	TokenManager::addToken(token, info);
	setIndex(0);
}

DiscordUserInfo TokenManager::getCachedInfo(const size_t idx) {
	std::lock_guard<std::mutex> lock(m_mutex);
	if (idx >= m_encryptedTokens.size()) {
		g_logger.warning(__FUNCSIG__ " : idx out of range");
		return DiscordUserInfo();
	}

	return m_cachedInfos[idx];
}

void TokenManager::updateCachedInfo(const size_t idx, DiscordUserInfo info) {
	std::lock_guard<std::mutex> lock(m_mutex);

	if (idx >= m_encryptedTokens.size()) {
		g_logger.warning(__FUNCSIG__ " : idx out of range");
		return;
	}

	m_cachedInfos[idx] = info;
}

secure_string TokenManager::getToken(const size_t idx) {
	std::lock_guard<std::mutex> lock(m_mutex);
	if (idx >= m_encryptedTokens.size()) {
		g_logger.warning(__FUNCSIG__ " : idx out of range");
		return secure_string();
	}

	return CryptoUtils::KD_decrypt(m_encryptedTokens[idx], g_context.kd);
}

void TokenManager::updateCurrentToken(const secure_string new_token) {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_encryptedTokens[m_idx] = CryptoUtils::KD_encrypt(new_token, g_context.kd);
}

void TokenManager::setIndex(const size_t idx) {
	if (idx >= m_encryptedTokens.size()) {
		g_logger.warning(__FUNCSIG__ " : idx out of range");
		return;
	}

	m_idx = idx;
	g_secureKV->write_int("tokens_idx", static_cast<int>(m_idx), g_context.kd);
}

bool TokenManager::migrateOldToken() {
	secure_string token;
	try {
		token = g_secureKV->read("token", g_context.kd);
	}
	catch (...) {
		return false;
	}

	if (token.empty()) return false;

	try {
		TokenManager::addToken(token, Discord::getUserInfo(token));
		g_secureKV->write("token", "", g_context.kd);
	}
	catch (std::exception& e) {
		g_logger.warning(sf() << __FUNCSIG__ " : Failed to add token : " << e.what());
		return false;
	}
	return true;
}

size_t TokenManager::addToken(const secure_string token, const DiscordUserInfo info) {
	m_mutex.lock();

	secure_string encrypted_token = CryptoUtils::KD_encrypt(token, g_context.kd);

	//If not already in the vect
	if (std::find(m_encryptedTokens.begin(), m_encryptedTokens.end(), encrypted_token) == m_encryptedTokens.end()) {
		m_encryptedTokens.push_back(encrypted_token);
		m_cachedInfos.push_back(info);

		m_mutex.unlock();

		flush();
	}
	else {
		m_mutex.unlock();
	}
}

void TokenManager::removeToken(size_t idx) {
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		if (idx >= m_encryptedTokens.size()) return;

		m_encryptedTokens.erase(m_encryptedTokens.begin() + idx);
		m_cachedInfos.erase(m_cachedInfos.begin() + idx);
	}
	flush();
}

void TokenManager::removeToken(const secure_string token) {
	secure_string encrypted_token = CryptoUtils::KD_encrypt(token, g_context.kd);

	m_mutex.lock();
	auto pos = std::find(m_encryptedTokens.begin(), m_encryptedTokens.end(), encrypted_token);
	m_mutex.unlock();

	if (pos == m_encryptedTokens.end()) return;

	removeToken(std::distance(m_encryptedTokens.begin(), pos));
}

void TokenManager::updateKD(KeyData& newKeyData, KeyData& oldKeyData) {
	std::lock_guard<std::mutex> lock(m_mutex);

	for (size_t i = 0; i < m_encryptedTokens.size(); i++) {
		m_encryptedTokens[i] = CryptoUtils::KD_encrypt(CryptoUtils::KD_decrypt(m_encryptedTokens[i], oldKeyData), newKeyData);
	}
}

std::string TokenManager::dumpUserDataToJson(const DiscordUserInfo info) {
	using nlohmann::json;

	json out;
	out["fullUsername"] = info.fullUsername;
	out["username"] = info.username;
	out["discriminator"] = info.discriminator;
	out["id"] = info.id;
	out["mfa"] = info.mfa;

	return out.dump();
}

DiscordUserInfo TokenManager::loadUserDataFromJson(std::string data) {
	using nlohmann::json;

	DiscordUserInfo info;

	try {
		json jdata = json::parse(data);

		info.fullUsername = jdata["fullUsername"].get<std::string>();
		info.username = jdata["username"].get<std::string>();
		info.discriminator = jdata["discriminator"].get<std::string>();
		info.id = jdata["id"].get<std::string>();
		info.mfa = jdata["mfa"].get<bool>();
	}
	catch (std::exception& e) {
		g_logger.warning(sf() << __FUNCSIG__ " : " << e.what());
	}
	return info;
}

//TODO better way...
void TokenManager::serializeData(const secure_string token, DiscordUserInfo cached_info, secure_string& out) {
	secure_string tmp;

	tmp += CryptoUtils::toBase64(token);
	tmp.push_back(TOKENMANAGER_SEP);
	tmp += CryptoUtils::toBase64(secure_string(dumpUserDataToJson(cached_info)));

	out = CryptoUtils::toBase64(tmp);
}

void TokenManager::deserializeData(const secure_string data, secure_string& token, DiscordUserInfo& info) {
	secure_string tmp = CryptoUtils::fromBase64(data);

	auto pos = tmp.find(TOKENMANAGER_SEP);
	if (pos == secure_string::npos) {//Should not happen
		token.clear();
		g_logger.warning(__FUNCSIG__ " : Failed to find delim");
		return;
	}

	token = CryptoUtils::fromBase64(tmp.substr(0, pos));
	info = loadUserDataFromJson(std::string(CryptoUtils::fromBase64(tmp.substr(pos))));
}

void TokenManager::flush() {
	std::lock_guard<std::mutex> lock(m_mutex);

	secure_string serialized_data;
	for (size_t i = 0; i < m_encryptedTokens.size(); i++) {
		secure_string tmp;
		serializeData(CryptoUtils::KD_decrypt(m_encryptedTokens[i], g_context.kd), m_cachedInfos[i], tmp);
		serialized_data += tmp;

		serialized_data.push_back(TOKENMANAGER_SEP);
	}
	
	g_secureKV->write("tokens", serialized_data, g_context.kd);
}

void TokenManager::load() {
	std::lock_guard<std::mutex> lock(m_mutex);

	m_encryptedTokens.clear();
	m_cachedInfos.clear();

	secure_string serialized_data = g_secureKV->read("tokens", g_context.kd);
	if (serialized_data.empty())
		return;
	
	auto pos = serialized_data.find(TOKENMANAGER_SEP);
	while (pos != secure_string::npos) {
		secure_string token;
		DiscordUserInfo info;

		deserializeData(serialized_data.substr(0, pos), token, info);

		m_encryptedTokens.push_back(CryptoUtils::KD_encrypt(token, g_context.kd));
		m_cachedInfos.push_back(info);

		serialized_data = serialized_data.substr(pos + 1);
		pos = serialized_data.find(TOKENMANAGER_SEP);
	}
}