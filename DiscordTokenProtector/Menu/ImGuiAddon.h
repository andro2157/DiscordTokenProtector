#pragma once
#include "../Includes.h"
#include <imgui.h>
#include <imgui_internal.h>

namespace ImGui {
	//https://github.com/ocornut/imgui/blob/master/imgui_demo.cpp#L158
	void TextTooltip(const char* text, const char* tooltip);
	void StyleColorDiscord();

	//https://github.com/flutter/flutter/blob/f82046b150ad9d54962ad8098df2babdad34c596/packages/flutter/lib/src/animation/curves.dart
	class CubicCurve {
	public:
		CubicCurve(float begin, float end, float a, float b, float c, float d);
		float transform(float t);
	private:
		const float _cubicErrorBound = 0.001f;

		float _evaluateCubic(float a, float b, float m);

		float m_begin;
		float m_end;

		float a, b, c, d;
	};

	//Inspired from https://github.com/ocornut/imgui/issues/1901
	void LinearIndeterminateBar(const char* label, const ImVec2& size_arg);
}