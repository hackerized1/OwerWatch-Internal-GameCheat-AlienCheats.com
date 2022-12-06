#include "menu.h"
#include <urlmon.h>
#include <winhttp.h>
#include <iostream>
#include<stdio.h>
#include <time.h>
#include "Vector3.h"
#include "Skin/Heroes.h"

#define DEG2RAD(x) x * M_PI / 180.0
#define M_PI       3.14159265358979323846

BYTE GlowOFF = 0x40;
BYTE GlowON = 0xFF;
static int TabCount = 0;
const char* hotkeylist[] = { u8"좌클릭", (u8"휠클릭"), (u8"우클릭"), (u8"쉬프트") };
static const char* current_hotkey = (u8"좌클릭");

const char* bonelist[] = { ("머리"), ("목"), ("몸통") };
static const char* current_bonepos = ("HEAD");

const char* PredictList[] = { u8"좌클릭 예측", (u8"쉬프트 예측"), (u8"E키 예측"), (u8"R키 예측")	 };
static const char* current_predict = (u8"좌클릭 예측");


float NeckVal = 0.85f;
float BodyVal = 0.50f;


void Menu::Initialize(ID3D11Device *pDev, ID3D11DeviceContext *pCont) {

	pDevice = pDev;
	pContext = pCont;
	HWND hWindow = FindWindow("TankWindowClass", NULL);


	ImGui_ImplDX11_Init(hWindow, pDevice, pContext);
	ImGui_ImplDX11_CreateDeviceObjects();

	CreateStyle();
}

//
//ULONG KeyState(UINT VKey)
//{
//	VK_LBUTTON
//	if (GetAsyncKeyState(VKey) & 0x8000)
//		return 0x8000;
//	else
//		return 0;
//}
//
//void a()
//{
//	KeyState();
//
//
//	return;
//}
bool onkey;

#pragma region Project

static const int B64index[256] =
{
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
	0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
	0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

const string b64decode(const void* data, const size_t& len)
{
	//VMProtectBeginUltra("B64DECODE");
	if (len == 0) return "";

	unsigned char* p = (unsigned char*)data;
	size_t j = 0,
		pad1 = len % 4 || p[len - 1] == '=',
		pad2 = pad1 && (len % 4 > 2 || p[len - 2] != '=');
	const size_t last = (len - pad1) / 4 << 2;
	string result(last / 4 * 3 + pad1 + pad2, '\0');
	unsigned char* str = (unsigned char*)&result[0];

	for (size_t i = 0; i < last; i += 4)
	{
		int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}
	if (pad1)
	{
		int n = B64index[p[last]] << 18 | B64index[p[last + 1]] << 12;
		str[j++] = n >> 16;
		if (pad2)
		{
			n |= B64index[p[last + 2]] << 6;
			str[j++] = n >> 8 & 0xFF;
		}
	}
	return result;
	//VMProtectEnd();
}

string b64decode(const string& str64)
{
	//VMProtectBeginUltra("B64FUNC");
	return b64decode(str64.c_str(), str64.size());
	//VMProtectEnd();
}

string encryptDecrypt(string toEncrypt) {
	//VMProtectBeginUltra("Xor");
	char key = 'K';
	string output = toEncrypt;
	for (int i = 0; i < toEncrypt.size(); i++)
		output[i] = toEncrypt[i] ^ key;
	return output;
	//VMProtectEnd();
}

string getBoolString(bool Bool, string A, string B) {
	if (Bool)
		return A;
	else
		return B;// 
}

///<summary>
///BOOL의 상태에 따라서 참일경우 ON를, 거짓일경우 OFF를 반환합니다.
///</summary>
///<param name="Bool">비교할 BOOL</param>
string getOnOff(bool Bool) {
	if (Bool)
		return "ON";
	else
		return "OFF";
}

#pragma endregion

std::wstring get_utf16(const std::string& str, int codepage)
{
	if (str.empty()) return std::wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
	std::wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
	return res;
}

string WebWinhttp(string details) {
	DWORD dwSize = 0, dwDownloaded;
	LPSTR source;
	source = (char*)"";
	string responsed = "";

	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
	BOOL bResults = FALSE;

	hSession = WinHttpOpen(L"Winhttp API", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
		hConnect = WinHttpConnect(hSession, get_utf16("core24.dothome.co.kr", CP_UTF8).c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);

	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", get_utf16(details, CP_UTF8).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (hRequest)
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	if (bResults) {
		do {
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				printf("Error %u", GetLastError());

			source = (char*)malloc(dwSize + 1);
			if (!source) {
				printf("Out of memory\n");
				dwSize = 0;
			}
			else {
				ZeroMemory(source, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)source, dwSize, &dwDownloaded))
					printf("Error %u", GetLastError());
				else
					responsed = responsed + source;
				free(source);
			}
		} while (dwSize > 0);
	}

	if (!bResults) {
		exit(0);
	}

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	return responsed;
}

std::string get_system_uuid()
{
	if (std::system("wmic csproduct get uuid > HWID.txt") == 0)
	{
		auto file = ::fopen("HWID.txt", "rt, ccs=UNICODE"); // open the file for unicode input

		enum { BUFFSZ = 1000, UUID_SZ = 36 };
		wchar_t wbuffer[BUFFSZ]; // buffer to hold unicode characters

		if (file && // file was succesffully opened
			::fgetws(wbuffer, BUFFSZ, file) && // successfully read (and discarded) the first line
			::fgetws(wbuffer, BUFFSZ, file)) // yfully read the second line
		{
			char cstr[BUFFSZ]; // buffer to hold the converted c-style string
			if (::wcstombs(cstr, wbuffer, BUFFSZ) > UUID_SZ) // convert unicode to utf-8
			{
				std::string uuid = cstr;
				while (!uuid.empty() && std::isspace(uuid.back())) uuid.pop_back(); // discard trailing white space
				return uuid;
			}
		}
	}
	return {}; // failed, return empty string
}

void SaveSetting(const char* HeroName)
{
	LPCSTR binPath = (LPCSTR)(u8"C:\\Settings\\" + (std::string)HeroName + u8".ini").c_str();
	WritePrivateProfileString(u8"Setting", u8"AimSpeed", (LPCSTR)to_string(Config::Get().AimSpeed).c_str(), binPath);
	WritePrivateProfileString(u8"Setting", u8"AimFov", (LPCSTR)to_string(Config::Get().Fov).c_str(), binPath);
	WritePrivateProfileString(u8"Setting", u8"Aimbot HotKey", (LPCSTR)to_string(Config::Get().AimKey).c_str(), binPath);
}


void LoadSetting(const char* HeroName)
{
	LPCSTR binPath = (LPCSTR)(u8"C:\\Settings\\" + (std::string)HeroName + u8".ini").c_str();

	char Strs[MAX_PATH] = { NULL };
	GetPrivateProfileString(u8"Setting", u8"AimSpeed", "", Strs, MAX_PATH, binPath);
	Config::Get().AimSpeed = atof(Strs);

	*Strs = { NULL };
	GetPrivateProfileString(u8"Setting", u8"Fov", "", Strs, MAX_PATH, binPath);
	Config::Get().Fov = atof(Strs);

	*Strs = { NULL };
	GetPrivateProfileString(u8"Setting", u8"Aimbot HotKey", "0x", Strs, MAX_PATH, binPath);
	Config::Get().AimKey = strtoul(Strs, NULL, 16);
}


const char* SettingItemList_English[] = { u8"D.va", u8"Reinhardt", u8"Wrecking Ball", u8"Roadhog", u8"Sigma", u8"Orisa", u8"Winston", u8"Zarya", u8"Tracer", u8"Mei", u8"Reaper", u8"Doomfist", u8"Symmetra", u8"Junkrat", u8"Pharah", u8"Torbjorn", u8"McCree", u8"Widowmaker", u8"Genji", u8"Hanzo", u8"Eco", u8"Soldier: 76", u8"Ashe", u8"Sombra", u8"Zenyatta", u8"Ana", u8"Bastion", u8"Moira", u8"Baptiste", u8"Mercy", u8"Brigitte", u8"Lucio" };
static const char* CurrentSettingItem_English = u8"Genji";

const string currentDateTime() {
	time_t     now = time(0); //현재 시간을 time_t 타입으로 저장
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct); // YYYY-MM-DD.HH:mm:ss 형태의 스트링

	return buf;
}

const char* Time;
void esp();

void Menu::Render() {
	ImGui_ImplDX11_NewFrame();
	Renderer::GetInstance()->BeginScene();
	Renderer::GetInstance()->DrawScene();
	Renderer::GetInstance()->EndScene();

	if (Config::Get().menuEnabled) {
		ImGui::SetNextWindowPos(ImVec2{ 50, 30 }, ImGuiSetCond_Once);
		ImGui::SetNextWindowSize(ImVec2{ 430, 420 }, ImGuiSetCond_Once);
		bool _visible = true;
		if (ImGui::Begin(u8"                         THE REACH", &_visible, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar))
		{
			if (!Config::Get().IsLogin)
			{
				string codeStr = (char*)Config::Get().CODE.c_str();
				ImGui::InputText(u8"Code", (char*)Config::Get().CODE.c_str(), 40);
				if (ImGui::Button(u8"Login", ImVec2(115, 25)))
				{
					Config::Get().AimKey = 0x01;
					Config::Get().IsLogin = true;

					/*if ((char*)Config::Get().CODE.c_str() != "")
					{
						string CodeVal = WebWinhttp("/SKY/CoreLand.php?mode=login&Code=" + codeStr + "&COM=" + get_system_uuid());
						if (CodeVal.find(u8"CoreLand123") != string::npos)
						{
							Config::Get().AimKey = 0x01;
							Config::Get().IsLogin = true;
						}
					}*/
				}
			}
			else
			{
				if (ImGui::BeginCombo(u8"##setting", CurrentSettingItem_English))
				{
					for (auto i = 0; i < IM_ARRAYSIZE(SettingItemList_English); i++)
					{
						bool is_selected = (CurrentSettingItem_English == SettingItemList_English[i]);
						if (ImGui::Selectable(SettingItemList_English[i], is_selected))
						{
							CurrentSettingItem_English = SettingItemList_English[i];
						}
					}
					ImGui::EndCombo();
				}
				ImGui::Separator();

				if (ImGui::Button(u8"Save", ImVec2(90, 20)))
				{
					SaveSetting(CurrentSettingItem_English);
				}

				ImGui::SameLine();
				if (ImGui::Button(u8"Load", ImVec2(90, 20)))
				{
					LoadSetting(CurrentSettingItem_English);
				}
				ImGui::Separator();

				ImGui::Checkbox((u8"Outline WallHack"), &Config::Get().UseGlowESP);

				ImGui::Checkbox((u8"Smooth Aimbot"), &Config::Get().TAimbot);
				ImGui::Checkbox((u8"Smooth Flick Aimbot"), &Config::Get().FAimbot);
				ImGui::Checkbox((u8"Smooth Prediction Aimbot"), &Config::Get().Predict);
				ImGui::Checkbox((u8"Smooth Hanzo Aimbot"), &Config::Get().HanzoAimbot);
			    ImGui::Checkbox((u8"Trigger Bot"), &Config::Get().TriggerBot);
				ImGui::Checkbox((u8"FOV Draw"), &Config::Get().FovDraw);
				ImGui::SliderFloat((u8"Speed"), &Config::Get().AimSpeed, 1.5f, 0.00000f, "%.3f");
				ImGui::SliderFloat((u8"Prediction Level"), &Config::Get().PreditLevel, 115.f, 0.00000f, "%.3f");
				ImGui::SliderFloat((u8"FOV"), &Config::Get().Fov, 500.f, 0.f, "%.3f FOV");
				//ImGui::SliderFloat((u8"Y Axis"), &Config::Get().YPITCH, 1.0, 0.00000f, "%.2f");
				ImGui::Separator();

				ImGui::Checkbox((u8"Auto Punch"), &Config::Get().자동평타);
				ImGui::Checkbox((u8"Genji Q Auto Attack"), &Config::Get().GENJIQ);
				ImGui::Checkbox((u8"Genji Auto Shift"), &Config::Get().GENJISHIFT);
				ImGui::Checkbox((u8"Ana Sleep Prediction"), &Config::Get().AnaSkill);
				ImGui::Checkbox((u8"Roadhog Grap Prediction"), &Config::Get().Roadhog);
				ImGui::Checkbox((u8"Tracer Q Prediction"), &Config::Get().TrQSkill);
				ImGui::Checkbox((u8"Sigma E Prediction"), &Config::Get().ESkill);
				ImGui::Checkbox((u8"DoomFist Rocket Punch Prediction"), &Config::Get().DomPredit);
				ImGui::Separator();
			}
		}
		ImGui::End();
	}

	/*if (Config::Get().BoneESP)
	{
		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.16f, 0.15f, 0.17f, 0.00f));
		ImGuiWindow* window = ImGui::GetCurrentWindow();
		ImGui::SetNextWindowPos(ImVec2{ 0, 0 }, ImGuiSetCond_Once);
		ImGui::SetNextWindowSize(ImVec2{ 1920, 1080 }, ImGuiSetCond_Once);
		bool _visible = true;
		if (ImGui::Begin(u8"##ESP", &_visible, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoInputs))
		{
			esp();

		}
		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.16f, 0.15f, 0.17f, 1.00f));
		ImGui::End();
	}*/

	if (Config::Get().FovDraw)
	{
		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.16f, 0.15f, 0.17f, 0.00f));
		ImGuiWindow* window = ImGui::GetCurrentWindow();
		ImGui::SetNextWindowPos(ImVec2{ 0, 0 }, ImGuiSetCond_Once);
		ImGui::SetNextWindowSize(ImVec2{ 1920, 1080 }, ImGuiSetCond_Once);
		bool _visible = true;
		if (ImGui::Begin(u8"##Fov", &_visible, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoInputs))
		{
			ImGuiWindow* window = ImGui::GetCurrentWindow();
			window->DrawList->AddCircle(ImVec2(1920 / 2.0f, 1080 / 2.0f), Config::Get().Fov, ImGui::GetColorU32(ImVec4(1, 1, 1, 1)), 100, 1.0f);

		}

		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.16f, 0.15f, 0.17f, 1.00f));
		ImGui::End();
	}

	ImGui::Render();
}


void Menu::Shutdown() {
	ImGui_ImplDX11_Shutdown();
}

void Menu::CreateStyle()
{

}