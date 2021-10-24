#include "ImGuiAddon.h"
#include "Colors.h"

namespace ImGui {
	//https://github.com/ocornut/imgui/blob/master/imgui_demo.cpp#L158
	void TextTooltip(const char* text, const char* tooltip) {
		ImGui::Text(text);
		if (ImGui::IsItemHovered()) {
			ImGui::BeginTooltip();
			ImGui::PushTextWrapPos(450.0f);
			ImGui::TextUnformatted(tooltip);
			ImGui::PopTextWrapPos();
			ImGui::EndTooltip();
		}
	}

	void StyleColorDiscord() {
		ImVec4* colors = (&GetStyle())->Colors;

		colors[ImGuiCol_Text] = Colors::White;
		colors[ImGuiCol_TextDisabled] = Colors::GrayPurple;
		colors[ImGuiCol_WindowBg] = Colors::NearlyBlack;
		colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
		colors[ImGuiCol_Border] = Colors::BorderBlack;
		colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_FrameBg] = Colors::DarkButNotBlack;
		colors[ImGuiCol_FrameBgHovered] = Colors::HoverBlack;
		colors[ImGuiCol_FrameBgActive] = Colors::ActiveBlack;
		//colors[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);//No title bar anyway
		//colors[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.29f, 0.48f, 1.00f);
		//colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
		colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
		colors[ImGuiCol_ScrollbarBg] = Colors::Transparent;
		colors[ImGuiCol_ScrollbarGrab] = Colors::ScrollBar;
		colors[ImGuiCol_ScrollbarGrabHovered] = Colors::ScrollBar;
		colors[ImGuiCol_ScrollbarGrabActive] = Colors::ScrollBar;
		colors[ImGuiCol_CheckMark] = Colors::Blurple;
		colors[ImGuiCol_SliderGrab] = Colors::Blurple;
		colors[ImGuiCol_SliderGrabActive] = Colors::BlurpleActive;
		colors[ImGuiCol_Button] = Colors::Blurple;
		colors[ImGuiCol_ButtonHovered] = Colors::BlurpleHover;
		colors[ImGuiCol_ButtonActive] = Colors::BlurpleActive;
		colors[ImGuiCol_Header] = Colors::Blurple;
		colors[ImGuiCol_HeaderHovered] = Colors::BlurpleHover;
		colors[ImGuiCol_HeaderActive] = Colors::BlurpleActive;
		colors[ImGuiCol_Separator] = Colors::Separator;
		colors[ImGuiCol_SeparatorHovered] = Colors::Separator;
		colors[ImGuiCol_SeparatorActive] = Colors::Separator;
		//colors[ImGuiCol_ResizeGrip] = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);//Unused
		//colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
		//colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
		colors[ImGuiCol_Tab] = Colors::Blurple;
		colors[ImGuiCol_TabHovered] = Colors::BlurpleHover;
		colors[ImGuiCol_TabActive] = Colors::BlurpleActive;
		colors[ImGuiCol_TabUnfocused] = Colors::DarkButNotBlack;
		colors[ImGuiCol_TabUnfocusedActive] = Colors::ActiveBlack;
		//colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);//Unused
		//colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
		//colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
		//colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
		colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
		colors[ImGuiCol_DragDropTarget] = Colors::NearlyBlack;
		colors[ImGuiCol_NavHighlight] = Colors::NearlyBlack;
		colors[ImGuiCol_NavWindowingHighlight] = Colors::Blurple;
		colors[ImGuiCol_NavWindowingDimBg] = Colors::BlurpleActive;
		colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
	}

	//https://github.com/flutter/flutter/blob/f82046b150ad9d54962ad8098df2babdad34c596/packages/flutter/lib/src/animation/curves.dart
	CubicCurve::CubicCurve(float begin, float end, float a, float b, float c, float d)
		: m_begin(begin), m_end(end), a(a), b(b), c(c), d(d) {
		if (begin > 1.0 || begin < 0.0)//TODO maybe throw an exception?
			g_logger.error(sf() << "CubicCurve::CubicCurve begin was outside the [0; 1] bound.");
		if (end > 1.0 || end < 0.0)
			g_logger.error(sf() << "CubicCurve::CubicCurve end was outside the [0; 1] bound.");
		if (end < begin)
			g_logger.error(sf() << "CubicCurve::CubicCurve end < begin");
	}

	float CubicCurve::transform(float t) {
		t = std::clamp((t - m_begin) / (m_end - m_begin), 0.0f, 1.0f);

		if (t > 1.0 || t < 0.0) {
			g_logger.error(sf() << "CubicCurve::transform t was outside the [0; 1] bound.");
			return 0.0;
		}

		if (t == 0.0 || t == 1.0) return t;

		float start = 0.0;
		float end = 1.0;
		while (true) {
			const float midpoint = (start + end) / 2;
			const float estimate = _evaluateCubic(a, c, midpoint);
			if (abs(t - estimate) < _cubicErrorBound)
				return _evaluateCubic(b, d, midpoint);
			if (estimate < t)
				start = midpoint;
			else
				end = midpoint;
		}
	}

	float CubicCurve::_evaluateCubic(float a, float b, float m) {
		return 3 * a * (1 - m) * (1 - m) * m +
			3 * b * (1 - m) * m * m +
			m * m * m;
	}

	//Inspired from https://github.com/ocornut/imgui/issues/1901
	void LinearIndeterminateBar(const char* label, const ImVec2& size_arg) {
		ImGuiWindow* window = GetCurrentWindow();
		if (window->SkipItems)
			return;

		ImGuiContext& g = *GImGui;
		const ImGuiStyle& style = g.Style;
		const ImGuiID id = window->GetID(label);

		ImVec2 pos = window->DC.CursorPos;
		ImVec2 size = size_arg;
		size.x -= style.FramePadding.x * 2;

		const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
		ItemSize(bb, style.FramePadding.y);
		if (!ItemAdd(bb, id))
			return;

		// Render
		// 
		// Background
		window->DrawList->AddRectFilled(
			bb.Min,
			ImVec2(pos.x + size.x, bb.Max.y),
			ImGui::ColorConvertFloat4ToU32(Colors::DarkButNotBlack), 3.0
		);

		// Indicator
		//https://github.com/flutter/flutter/blob/master/packages/flutter/lib/src/material/progress_indicator.dart
		const int _kIndeterminateLinearDuration = 1800;

		CubicCurve line1Head(
			0.f,
			750.f / _kIndeterminateLinearDuration,
			0.2f, 0.0f, 0.8f, 1.0f);

		CubicCurve line1Tail(
			333.0f / _kIndeterminateLinearDuration,
			(333.0f + 750.0f) / _kIndeterminateLinearDuration,
			0.4f, 0.0f, 1.0f, 1.0f);

		CubicCurve line2Head(
			1000.0f / _kIndeterminateLinearDuration,
			(1000.0f + 567.0f) / _kIndeterminateLinearDuration,
			0.0f, 0.0f, 0.65f, 1.0f);

		CubicCurve line2Tail(
			1267.0f / _kIndeterminateLinearDuration,
			(1267.0f + 533.0f) / _kIndeterminateLinearDuration,
			0.1f, 0.0f, 0.45f, 1.0f);

		const float t = static_cast<float>(g.Time);
		const float speed = 0.5f;
		const float animationValue = std::clamp(fmod(static_cast<float>(g.Time) * speed, 1.1f), 0.0f, 1.0f);

		const float x1 = size.x * line1Tail.transform(animationValue);
		const float width1 = size.x * line1Head.transform(animationValue);

		const float x2 = size.x * line2Tail.transform(animationValue);
		const float width2 = size.x * line2Head.transform(animationValue);

		if (abs(x1 - width1) > 1) {
			window->DrawList->AddRectFilled(
				ImVec2(pos.x + x1, bb.Min.y),
				ImVec2(pos.x + width1, bb.Max.y),
				ImGui::ColorConvertFloat4ToU32(Colors::Blurple), 3.0
			);
		}
		if (abs(x2 - width2) > 1) {
			window->DrawList->AddRectFilled(
				ImVec2(pos.x + x2, bb.Min.y),
				ImVec2(pos.x + width2, bb.Max.y),
				ImGui::ColorConvertFloat4ToU32(Colors::Blurple), 3.0
			);
		}
	}
}