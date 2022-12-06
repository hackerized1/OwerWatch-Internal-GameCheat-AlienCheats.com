#pragma once
#include "singleton.h"
#include <d3d11.h>
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_dx11.h"
#include "renderer.h"
#include "config.h"

class Menu : public Singleton<Menu>
{
	friend class Singleton<Menu>;

public:
	void Initialize(ID3D11Device *pDev, ID3D11DeviceContext *pCont);
	void Shutdown();
	void Render();
	void CreateStyle();
	void DrawRender();
	ImFont* pFont;

private:
	ID3D11Device *pDevice = NULL;
	ID3D11DeviceContext *pContext = NULL;
	ImGuiStyle _style;
};