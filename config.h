#pragma once

#include <Windows.h>
#include <vector>
#include "imgui.h"
#include "menu.h"
#include "singleton.h"
#pragma warning(disable : 4244 4996 ) 

using namespace std;

class Config
	: public Singleton<Config>
{
	friend class Singleton<Config>;

public:

	string CODE, ID, PW, Key, Key2;
	BOOL IsLogin = FALSE;
	/* Memory Access */
	HANDLE hProcess;
	DWORD64 BaseAddress;
	int Result;
		
	uint64_t m_retSpoof{};

	template <typename RPMType>
	RPMType RPM(DWORD64 Address)
	{
		RPMType Buffer;
		ReadProcessMemory(hProcess, LPVOID(Address), &Buffer, sizeof(Buffer), NULL);
		return Buffer;
	}

	template <typename WPMType>
	BOOL WPM(DWORD64 Address, WPMType value)
	{
		return WriteProcessMemory(hProcess, LPVOID(Address), &value, sizeof(value), NULL);
	}

	bool UseAim = false;
	bool UseA1mb0t = false;
	bool UseAIMBOT = false;
	bool UseBox2SP = false;
	bool UseGlowESP = false;
	bool UseHP = false;
	bool Fov360 = false;
	bool UsePredict = false;
	bool UseGenjiBB = false;
	bool UseAutoMelee = false;
	bool °ÕÁö¿ë°Ë = false;
	bool °ÕÁö½ä±â = false;
	bool ESkill = false;
	bool ÀÚµ¿ÆòÅ¸ = false;
	bool UseAutoShot = false;
	bool UseNoRecoil = false;
	bool AnaSkill = false;
	bool DogSkill = false;
	bool TrQSkill = false;
	bool LESkill = false;
	bool PlayerTag = false;
	bool DomPredit = false;
	bool GravityBool = false;
	bool DrawDist = false;
	bool DrawHeroName = false;
	bool BoneESP = false;
	bool Korean = true;
	bool English = false;
	//bool UseAllChamp = false;
	ImVec4 E2SPColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
	ImVec4 E2SPColor1 = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
	ImVec4 ESPColor2 = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
	ImVec4 ESPColor3 = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
	float AimFOV = 0.150f;
	float Fov = 150.f;
	float GenjiFOV = 9.5f;
	float GenjiSpeed = 1.0f;
	float DomGunBulletSpeed = 80.0f;
	float DomBulletSpeed = 40.0f;
	float TriggerFOV = 0.1f;
	float TRIGGER = 0.02f;
	float AimSpeed = 0.090f;
	float PredictVal = 24.0f;
	float PredictDistance = 10.0f;
	float YPITCH = 0.27f;
	float Humanize = 0.100f;
	float PreditLevel = 110.f;
	bool TriggerBot = false;
	bool UseYAxis = false;
	bool GENJISHIFT = false;
	bool GENJIQ = false;
	bool TPAimbot = false;
	bool HanzoAimbot = false;
	bool SAimbot = false;
	bool TAimbot = false;
	bool FAimbot = false;
	bool RFLICK = false;
	bool Predict = false;
	bool SombraESP = false;
	bool FovDraw = false;
	bool Genyata = false;
	bool Reinhardt = false;
	bool Roadhog = false;
	bool Mccree = false;
	bool NameESP = false;
	bool HanzoFlick = false;
	bool Mouse1 = false;
	bool Mouse2 = false;
	bool AutoShot = false;
	bool AlltoShot = false;
	bool Silent = false;
	DWORD Mouse5 = 0x05;
	DWORD Mouse6 = 0x06;
	float BulletSpeed = 105.0f;
	float HanzoSpeed = 110.f;
	float Ana_BulletSpeed = 125.0f;
	float BulletSpeed2 = 110.0f;
	float AnaBulletSpeed = 60.0f;
	float DogBulletSpeed = 35.0f;
	float GenjiBulletSpeed = 50.0f;
	float TracerBombSpeed = 15.0f;
	float Genji_BulletSpeed = 60.0f;
	float TorBulletSpeed = 70.0f;
	float SigmaBulletSpeed = 37.5;
	float ZenBulletSpeed = 90.0f;
	float EcoBulletSpeed = 75.0f;
	float OrisaBulletSpeed = 90.0f;
	float Sigma_BulletSpeed = 50.0f;
	float PHARAH_BulletSpeed = 35.0f;
	float Lucio_BulletSpeed = 50.0f;
	float m_TriggerScale = 188.f;
	DWORD AimKey;
	uint32_t Color = 0xFF;
	HWND hWindow;

	// Menu
	bool menuEnabled = true;
};
