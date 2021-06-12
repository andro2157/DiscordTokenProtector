#include "logger.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

logger g_logger;

void logger::info(std::string message) {
	pushBufferAndStream(sf() << getCurrentTime() << " [INFO] " << message << "\n", std::cout);
}

void logger::warning(std::string message) {
	pushBufferAndStream(sf() << getCurrentTime() << " [WARNING] " << message << "\n", std::cerr);
}

void logger::error(std::string message) {
	pushBufferAndStream(sf() << getCurrentTime() << " [ERROR] " << message << "\n", std::cerr);
}

//https://stackoverflow.com/a/35157784/13544464
std::string logger::getCurrentTime() {
	auto now = std::chrono::system_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

	auto timer = std::chrono::system_clock::to_time_t(now);

	std::tm bt = *std::localtime(&timer);//C4996
	std::ostringstream oss;
	oss << std::put_time(&bt, "%H:%M:%S");
	oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

	return oss.str();
}

void logger::pushBufferAndStream(std::string str, std::ostream& stream) {
	stream << str;
	pushBuffer(str);

}

void logger::pushBuffer(std::string str) {
	const std::lock_guard<std::mutex> lock(m_buffer_mutex);
	m_buffer.push_back(str);
	popBufferExcess(false);
#ifdef _PROD
	if (m_outfile.is_open())
		m_outfile << str << std::flush;
#endif
}

void logger::popBufferExcess(bool lock) {
	if (lock)
		const std::lock_guard<std::mutex> lock(m_buffer_mutex);
	if (m_buffer.size() > MAX_LOGGER_BUFFER) m_buffer.erase(m_buffer.begin(), m_buffer.begin() + m_buffer.size() - MAX_LOGGER_BUFFER);
}