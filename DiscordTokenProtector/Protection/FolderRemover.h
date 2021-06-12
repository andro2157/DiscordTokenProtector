#pragma once
#include <iostream>
#include <filesystem>
#include <chrono>
#include <thread>

constexpr auto UPDATE_DELAY = 1500;//ms

class FolderRemover {
public:
	FolderRemover(std::wstring path) : m_path(path) {}
	~FolderRemover();

	void Start();
	void Stop();
	void Remove();

private:
	void RemoverThread();

	std::wstring m_path;
	bool m_running = false;
	std::thread m_thread;
};