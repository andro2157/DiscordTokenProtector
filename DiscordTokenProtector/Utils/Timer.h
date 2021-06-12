#pragma once
#include <chrono>

typedef std::chrono::high_resolution_clock Clock;

class Timer {
public:
	Timer() { time = Clock::now(); }

	template<class T>
	uint64_t getElapsed() { return std::chrono::duration_cast<T>(Clock::now() - time).count(); }
	void reset() { time = Clock::now(); }
private:
	std::chrono::time_point<std::chrono::steady_clock> time;
};