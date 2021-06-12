#pragma once
#include "../Includes.h"

constexpr auto FPS_MAX = 60;
constexpr auto FPS_IDLE_MAX = 4;

class FrameRateLimiter {
public:
	FrameRateLimiter(uint64_t frameRate) : m_frameRate(frameRate) {
		calcFrameTime();
		m_frameEndTime = std::chrono::steady_clock::now();
	}

	inline void frameStart() {
		double timeDelta = std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now() - m_frameEndTime).count();

		if (timeDelta < m_frameTime) {
			std::this_thread::sleep_for(std::chrono::microseconds(static_cast<uint64_t>(m_frameTime - timeDelta)));
		}
	}

	inline void frameEnd() {
		m_frameEndTime = std::chrono::steady_clock::now();
	}

	inline void setFrameRate(uint64_t frameRate) {
		m_frameRate = frameRate;
		calcFrameTime();
	}

private:
	inline void calcFrameTime() {
		m_frameTime = 1.0 / static_cast<double>(m_frameRate) * 1e6;//in µs
	}

	uint64_t m_frameRate;
	double m_frameTime;
	std::chrono::steady_clock::time_point m_frameEndTime;
};