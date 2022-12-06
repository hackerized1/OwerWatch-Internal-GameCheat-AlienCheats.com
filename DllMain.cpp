#pragma region include

/* D3D */
#include "D3dhook.h"
#include <DirectXMath.h>
#include "Vector3.h"
/* D3D */

/* Input */
#include "Input.h"
/* Input */

/* VC++ */
#include <iostream>
#include <fstream>
#include <string>
#include <winhttp.h>
#include <time.h>
#include <Windows.h>
#include <Tlhelp32.h>
#include <atlstr.h>
#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <vector>
#include <thread>
#include <string>
#include <ostream>
#include <bitset>
#include <tuple>
#include <mutex>
#include <array>
#include <algorithm>
/* VC++ */

/* BreakPoint */
#include "BreakPoint.h"
/* BreakPoint */

/* OFFSETS */
#include "Offset.h"
/* OFFSETS */

/* Kernel */
#include "communication.hpp"
#include "kernelinterface.hpp"
/* Kernel */

/* Config */
#include "config.h"
/* Config */

/* Utils */
#include "gamedata.hpp"
#include "Memory.h"
#include "Skin/Heroes.h"
#include "renderer.h"
#include "Skin/BotUtils.h"
#include "Memory.hpp"
#include "skCrypter.h"
#include "defs.h"
/* Utils */

#define M_PI       3.14159265358979323846
#define DEG2RAD(x) x * M_PI / 180.0
#pragma comment (lib, "urlmon.lib")
#pragma comment (lib, "winhttp.lib")
#include "Spoofcall.h"
#include "sha256.h"
#include "SendInput.h"
using namespace DirectX;
#pragma endregion

#pragma region Declare
HINSTANCE g_Module;

Heroes eSkinEnum;
Heroes mSkinEnum;

DWORD64 viewMatrixPtr;
Matrix viewMatrix;
MatrixTo viewMatrixTo;

#define GravityForce 9.81f * 0.5f * Distance / Hanzo_BulletSpeed * Distance / Hanzo_BulletSpeed

Vector3 MyAngle, TargetAngle, EnPos;

static Vector3 staticAngle;

std::string EnComponentHook, EnFovHook, EnAngleHook, EnWallHook;

DirectX::XMFLOAT3 MyXMAngle;

uint64_t AnglePTR;

struct Entity
{
	Vector3 Location, savedVelocity, Velocity, lastPos, rootPos, BonePos;
	bool Enemy, Alive;
	BYTE VisCheck;
	clock_t lastVelocityUpdate;
	float PlayerHealth;

	uint64_t HeroID, SkinID;
};

Entity Entitys[100];

vector<DWORD64>EntityPTR;

struct Color {
	int R, G, B, A;
};
#pragma endregion

#pragma region EncryptData
std::string encrypt(UINT64 ui64)
{
	return sha256(std::to_string(ui64));
}

void SaveEncrypted() // VMP 
{
	//EnComponentHook = encrypt(Config::Get().BaseAddress + offset::CompoenetHook);
	EnFovHook = encrypt(Config::Get().BaseAddress + offset::FovHook);
	EnAngleHook = encrypt(Config::Get().BaseAddress + offset::AngleHook);
	EnWallHook = encrypt(Config::Get().BaseAddress + offset::BorderLine);
}
#pragma endregion

#pragma region Angle

Vector3 CalcAngle(Vector3 MyPos, Vector3 EnPos, float Dis)
{
	Vector3 Result;

	Result.x = (EnPos.x - MyPos.x) / Dis;
	Result.y = (EnPos.y - MyPos.y) / Dis;
	Result.z = (EnPos.z - MyPos.z) / Dis;

	return Result;
}

Vector3 GetAngle(Vector3 RAngle, Vector3 MPos, Vector3 EPos)
{
	float Distance = MPos.Distance(EPos);

	Vector3 Result;

	Result.x = (EPos.x - MPos.x) / Distance;
	Result.y = (EPos.y - MPos.y) / Distance;
	Result.z = (EPos.z - MPos.z) / Distance;

	return Result;
}

Vector3 SmoothAngle(Vector3 LocalAngle, Vector3 TargetAngle, float X_Speed, float Y_Speed)
{
	Vector3 Result;
	Result.x = (TargetAngle.x - LocalAngle.x) * X_Speed + LocalAngle.x;
	Result.y = (TargetAngle.y - LocalAngle.y) * Y_Speed + LocalAngle.y;
	Result.z = (TargetAngle.z - LocalAngle.z) * X_Speed + LocalAngle.z;

	return Result;
}
#pragma endregion

#pragma region NAMETAG
vector<MEMORY_BASIC_INFORMATION> mbis;
bool UpdateMemoryQuery()
{
	MEMORY_BASIC_INFORMATION mbi = { 0, };
	MEMORY_BASIC_INFORMATION old = { 0, };
	ULONG64 current_address = 0x7ffe0000;
	vector<MEMORY_BASIC_INFORMATION> addresses;
	while (true)
	{
		if (!VirtualQueryEx(GetCurrentProcess(), (PVOID)current_address, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
			break;
		if ((mbi.State & 0x1000) != 0 && (mbi.Protect & 0x100) == 0)
		{
			addresses.push_back(mbi);

			old = mbi;
		}
		current_address = ULONG64(mbi.BaseAddress) + mbi.RegionSize;
	}

	mbis = addresses;


	return (mbis.size() > 0);
}


ULONG64 FindPattern2(BYTE* buffer, BYTE* pattern, string mask, int bufSize)
{
	int pattern_len = mask.length();

	for (int i = 0; i < bufSize - pattern_len; i++)
	{
		bool found = true;
		for (int j = 0; j < pattern_len; j++)
		{
			if (mask[j] != '?' && pattern[j] != buffer[(i + j)])
			{
				found = false;
				break;
			}
		}
		if (found)
			return i;
	}
	return -1;
}

vector<ULONG64> FindPatternEx(ULONG64 start, ULONG64 end, BYTE* pattern, string mask, MEMORY_BASIC_INFORMATION mbi, ULONG64 RgSize)
{
	ULONG64 current_chunk = start;
	vector<ULONG64> found;
	if ((end - current_chunk > RgSize && RgSize != 0) || (end - current_chunk < RgSize && RgSize != 0))
		return found;
	while (current_chunk < end)
	{
		int bufSize = (int)(end - start);
		BYTE* buffer = new BYTE[bufSize];
		if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)current_chunk, buffer, bufSize, nullptr))
		{
			current_chunk += bufSize;
			delete[] buffer;
			continue;
		}

		ULONG64 internal_address = FindPattern2(buffer, pattern, mask, bufSize);
		if (internal_address != -1)
		{
			found.push_back(current_chunk + internal_address);
		}
		current_chunk += bufSize;
		delete[] buffer;

	}
	return found;
}

vector<ULONG64> _FindPatterns(BYTE* buffer, BYTE* pattern, string mask, int bufSize)
{
	vector<ULONG64> ret;
	int pattern_len = mask.length();
	for (int i = 0; i < bufSize - pattern_len; i++)
	{
		bool found = true;
		for (int j = 0; j < pattern_len; j++)
		{
			if (mask[j] != '?' && pattern[j] != buffer[i + j])
			{
				found = false;
				break;
			}
		}
		if (found)
			ret.push_back(i);
	}
	return ret;
}

ULONG64 FindPattern(BYTE* pattern, string mask, ULONG64 RgSize)
{
	if (!UpdateMemoryQuery())
		return 0;

	for (int i = 0; i < mbis.size(); i++) {
		MEMORY_BASIC_INFORMATION info = mbis[i];

		vector<ULONG64> arr = FindPatternEx(ULONG64(info.BaseAddress), info.RegionSize + ULONG64(info.BaseAddress), pattern, mask, info, RgSize);
		if (arr.size() > 0)
			return arr[0];
	}

	return 0;
}

vector<ULONG64> FindPatterns(BYTE* pattern, string mask, ULONG64 RgSize)
{
	vector<ULONG64> Result;
	ULONG64 PatternStart = FindPattern(pattern, mask, RgSize);
	if (PatternStart)
	{
		for (int i = 0; i < mbis.size(); i++)
		{
			if (ULONG64(mbis[i].BaseAddress) < PatternStart && PatternStart - ULONG64(mbis[i].BaseAddress) < mbis[i].RegionSize)
			{
				PatternStart = ULONG64(mbis[i].BaseAddress);
			}
		}

		BYTE* buf = new BYTE[RgSize];
		memcpy_s(buf, RgSize, PVOID(PatternStart), RgSize);

		vector<ULONG64> Pointers = _FindPatterns(buf, pattern, mask, RgSize);
		delete[] buf;

		for (int i = 0; i < Pointers.size(); i++)
			Pointers[i] += PatternStart;

		Result = Pointers;
	}

	return Result;
}

void Pointer()
{
	while (true)
	{
		EntityPTR = FindPatterns((PBYTE)"\xFA\x42\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x1E\x00\x07", "xx????xxxxxxxxx", 0x16000);

		Sleep(5);
	}
}
#pragma endregion

#pragma region Thread

//unsigned __int64 __fastcall DecryptVis(__int64 a1)
//{
//	__int64 v1; // rbx
//	unsigned __int64 v2; // rdi
//	unsigned __int64 v3; // rax
//	__int64 v4; // rbx
//	unsigned __int64 v5; // rdx
//	unsigned __int64 v6; // rcx
//	__m128i v7; // xmm1
//	__m128i v8; // xmm2
//	__m128i v9; // xmm0
//	__m128i v10; // xmm1
//
//	v1 = a1;
//	v2 = Config::Get().BaseAddress + 0x5eec30; // 어레이검색후 첫번째
//
//	v3 = v2 + 0x8;
//
//	DWORD64* VisibleKeyPTR = (DWORD64*)(Config::Get().BaseAddress + 0x2bc4480); // 두번째 값
//	v4 = v2 ^ *(DWORD64*)((char*)&VisibleKeyPTR[((BYTE)v1 + 0x3C) & 0x7F]
//		+ (((unsigned __int64)(v1 - 0x6A0FD9FBE3F650C4i64) >> 7) & 7)) ^ (v1 - 0x6A0FD9FBE3F650C4i64);
//
//
//	v5 = (v3 - v2 + 7) >> 3;
//	v6 = 0i64;
//	if (v2 > v3)
//		v5 = 0i64;
//	if (v5)
//	{
//		if (v5 >= 4)
//		{
//			ZeroMemory(&v7, sizeof(v7));
//			ZeroMemory(&v8, sizeof(v8));
//			do
//			{
//				v6 += 4i64;
//				v7 = _mm_xor_si128(v7, _mm_loadu_si128((const __m128i*)v2));
//				v9 = _mm_loadu_si128((const __m128i*)(v2 + 16));
//				v2 += 0x20i64;
//				v8 = _mm_xor_si128(v8, v9);
//			} while (v6 < (v5 & 0xFFFFFFFFFFFFFFFCui64));
//			v10 = _mm_xor_si128(v7, v8);
//			v4 ^= *(DWORD64*)&_mm_xor_si128(v10, _mm_srli_si128(v10, 8));
//		}
//		for (; v6 < v5; ++v6)
//		{
//			v4 ^= *(DWORD64*)v2;
//			v2 += 8i64;
//		}
//	}
//	return v4 ^ ~v3 ^ 0x6A0FD9FBE3F650C4i64;
//}

#pragma endregion

#pragma region Function
void ReadView()
{
	GameData& data = GameData::Get();
	uint64_t viewMatrixVal = Config::Get().RPM<uint64_t>(Config::Get().BaseAddress + offset::ViewMatrixOffset);
	viewMatrixVal = Config::Get().RPM<uint64_t>(viewMatrixVal + 0x3D8);
	viewMatrixVal = Config::Get().RPM<uint64_t>(viewMatrixVal + 0x560);
	viewMatrixVal = Config::Get().RPM<uint64_t>(viewMatrixVal + 0x478);
	viewMatrixVal = Config::Get().RPM<uint64_t>(viewMatrixVal + 0x60);
	viewMatrixPtr = viewMatrixVal + 0x470;
	viewMatrix = Config::Get().RPM<Matrix>(viewMatrixPtr);
	viewMatrixTo = Config::Get().RPM<MatrixTo>(viewMatrixPtr);
}

void StructT()
{
	while (true)
	{
		vector<DWORD64>tempEntityPTR = EntityPTR;
		if (tempEntityPTR.size())
		{
			for (int i = 0; i < tempEntityPTR.size(); i++)
			{
				Entitys[i].Location = Config::Get().RPM<Vector3>(tempEntityPTR[i] + 0x5A);
				Entitys[i].Enemy = (Config::Get().RPM<BYTE>(tempEntityPTR[i] + 0x4) >= 0xA0) && (Config::Get().RPM<BYTE>(tempEntityPTR[i] + 0x4) < 0xB0) || (Config::Get().RPM<BYTE>(tempEntityPTR[i] + 0x4) == 0x80 || Config::Get().RPM<BYTE>(tempEntityPTR[i] + 0x4) == 0x99) ? true : false; // 팀구분	
				Entitys[i].Alive = (Config::Get().RPM<BYTE>(tempEntityPTR[i] + 0x4) != 0x80) && Config::Get().RPM<BYTE>(tempEntityPTR[i] + 0x4) != 0x10 ? true : false;
				ReadView();
			}
			this_thread::sleep_for(1ms);
			viewMatrix = Config::Get().RPM<Matrix>(viewMatrixPtr);
			viewMatrixTo = Config::Get().RPM<MatrixTo>(viewMatrixPtr);
		}
		else
		{
			this_thread::sleep_for(5ms);
		}
	}
}

void AimCorrection(Vector3* InVecArg, Vector3 currVelocity, float Distance, float Bulletspeed, float Gravity)
{
	if (Config::Get().GravityBool)
	{
		float m_time = (Distance / Bulletspeed);

		(*InVecArg).x = (*InVecArg).x + ((currVelocity.x) * (Distance / (Bulletspeed)));
		(*InVecArg).y = (*InVecArg).y + ((currVelocity.y) * (Distance / (Bulletspeed)));
		(*InVecArg).z = (*InVecArg).z + ((currVelocity.z) * (Distance / (Bulletspeed)));

		(*InVecArg).y += (0.5f * 9.81f * m_time * m_time);
	}
	else
	{
		(*InVecArg).x = (*InVecArg).x + ((currVelocity.x) * (Distance / (Bulletspeed)));
		(*InVecArg).y = (*InVecArg).y + ((currVelocity.y) * (Distance / (Bulletspeed)));
		(*InVecArg).z = (*InVecArg).z + ((currVelocity.z) * (Distance / (Bulletspeed)));
	}
}

float Rotations()
{
	uint64_t RotationVal = Config::Get().RPM<uint64_t>(Config::Get().BaseAddress + offset::PlayerController);
	RotationVal = Config::Get().RPM<uint64_t>(RotationVal + 0x10);
	RotationVal = Config::Get().RPM<uint64_t>(RotationVal + 0x8);
	RotationVal = Config::Get().RPM<uint64_t>(RotationVal + 0x10);
	RotationVal = Config::Get().RPM<uint64_t>(RotationVal + 0x28);
	RotationVal = Config::Get().RPM<uint64_t>(RotationVal + 0x20);
	return Config::Get().RPM<float>(RotationVal + 0x18);
}

//struct RaytraceIn
//{
//	D3DXQUATERNION Coord1 = { 0,0,0,0 }; //myCoord
//	D3DXQUATERNION Coord2 = { 0,0,0,0 }; //enemyCoord
//	float var20 = 1;
//	float var24 = 1;
//	unsigned long var28 = 0;
//	unsigned long var2C = 0;
//	D3DXQUATERNION unknownCoord = { 0,0,0,0 }; //0x30
//	uint64_t var40 = 0;
//	uint64_t var48 = 0;
//	uint64_t var50 = 0;
//	uint64_t var58 = 0;
//	uint64_t* var60 = &var70;
//	uint32_t var68 = 0;
//	uint32_t var6C = 0x80000004;
//	uint64_t var70 = 0;
//	uint64_t var78 = 0;
//	uint64_t var80;
//	uint64_t var88;
//	uint64_t* var90 = &varA0;
//	uint32_t var98 = 0;
//	uint32_t var9C = 0x80000004;
//	uint64_t varA0 = 0;
//	uint64_t varA8 = 0;
//	uint64_t varB0 = 0;
//	uint64_t varB8 = 0;
//	uint64_t varC0 = 0;
//	uint64_t varC8 = 0;
//	uint64_t* varD0 = &varE0;
//	uint32_t varD8 = 0;
//	uint32_t varDC = 0x80000008;
//	uint64_t varE0 = 0;
//	uint64_t* varE8 = &var100;
//	uint64_t varF0 = 0;
//	uint64_t varF8 = 0;
//	uint64_t var100 = 0;
//	uint64_t var108 = 0;
//	uint64_t var110 = 0;
//	uint64_t var118 = 0;
//	uint64_t var120;
//	uint64_t var128;
//	uint64_t var130;
//	uint64_t var138;
//	uint64_t var140;
//	uint64_t var148;
//	uint64_t var150;
//	uint64_t var158;
//	uint64_t var160 = 0;
//	uint64_t var168 = 0;
//	uint64_t var170 = 0;
//	uint64_t var178 = 0;
//	uint64_t var180 = 0;
//	uint64_t var188 = 0;
//	uint64_t var190 = 0;
//	uint32_t var198 = 0x10000;
//	uint32_t var19c = 0;
//	uint64_t var1A0 = 0;
//	uint64_t var1A8 = 0;
//	uint64_t var1B0 = 0;
//	uint64_t var1B8 = 0;
//	uint64_t var1C0 = 0;
//	uint64_t var1C8 = 0;
//	uint64_t var1D0 = 0;
//	uint64_t var1D8 = 0;
//	uint32_t var1E0 = 0;
//	uint32_t var1E4 = 0;
//	uint32_t var1E8 = 0;
//	uint64_t var1F0 = 0;
//	uint64_t var1F8 = 0;
//	uint64_t var200 = 0;
//	uint64_t var208 = 0;
//	uint64_t var210 = 0;
//	uint64_t var218 = 0;
//	uint64_t var220 = 0;
//	uint64_t var228 = 0;
//	uint64_t var230 = 0;
//	uint64_t var238 = 0;
//	uint32_t var240 = 0;
//	uint32_t var244 = 0;
//	uint64_t var248 = 0;
//	uint32_t var250 = 0;
//};
//
//struct RaytraceOut
//{
//	D3DXQUATERNION Coord1 = { 0,0,0,0 };
//	D3DXQUATERNION Coord2 = { 0,0,0,0 };
//	unsigned __int64 unknown0 = 0;
//	unsigned __int32 unknown1 = 0xFFFFFFFF;
//	unsigned __int32 unknown2 = 0xFFFF0000;
//	float unknown3 = 1;
//	unsigned long unknown4 = -1;
//	unsigned short unknown5 = -1;
//	unsigned short unknown6 = -1;
//	unsigned long unknown7 = 1;
//	unsigned __int64 unknown8 = 0;
//	unsigned __int64 unknown9 = 0;
//	unsigned __int64 unknown10 = 0;
//	unsigned __int64 unknown11 = 0;
//};
//
//typedef int(*pConstructSetting)(unsigned __int64** Parameter1, unsigned __int64* Parameter2);
//typedef int(*pRayForce)(RaytraceIn* Parameter1, RaytraceOut* Parameter2, DWORD a1);
//
//int RayForce(uint64_t target_player_address, D3DXVECTOR3 targetPos, uint64_t flag, RaytraceOut& RTOut)
//{
//	RaytraceIn RTIn;
//
//	pConstructSetting xSetting = (pConstructSetting)(Config::Get().BaseAddress + 0x1B8FCA0); //E8 ? ? ? ? 41 3B 7E 08
//	pRayForce Rayforce = (pRayForce)(Config::Get().BaseAddress + 0xBBA0A0); //E8 ? ? ? ? 8B F8 48 8B 76 20
//
//	RTIn.var1B8 = //get value for debugging "Overwatch.exe+BBA0A0" rcx+1B8
//		RTIn.var1C0 = //get value for debugging "Overwatch.exe+BBA0A0" rcx+1C0
//
//		uint64_t local = // you can get value
//
//		if (local == 0)
//			return -1;
//
//	xSetting(&RTIn.var60, &local);
//	xSetting(&RTIn.var60, &target_player_address);
//
//	D3DXVECTOR3 camera = getCameraLocation(); //camera location
//
//	RTIn.Coord1 = D3DXQUATERNION(camera.x, camera.y, camera.z, 0);
//	RTIn.Coord2 = D3DXQUATERNION(targetPos.x, targetPos.y, targetPos.z, 0);
//	RTIn.var58 = flag;
//
//	return Rayforce(&RTIn, &RTOut, 0);
//}
// 니 저거 제대로 쓰지도 못하잖아 ㅋㅋ 아 그냥저장해둔거엥ㅅ

void RemovePeHeader(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->FileHeader.SizeOfOptionalHeader)
	{
		DWORD Protect;
		WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
		VirtualProtect((void*)hModule, Size, PAGE_EXECUTE_READWRITE, &Protect);
		SecureZeroMemory((void*)hModule, Size);
		VirtualProtect((void*)hModule, Size, Protect, &Protect);
	}
}

//FnDecryptParnet(ParentPTR, ComponentID); // 이렇게하면된다 ㅇㅋ?  네 연동하는 방법은 알거고 네네 나머지 작업은 다 끝난상태 넵 니가 이거 패치 가능할거라 생각하노 ? 아니요 왜 한번 보지 그래 ㅋㅋ IDA

uint64_t Spoocall1(uint64_t* a1, uint64_t* a2)
{
	__try
	{
		return spoof_call((PVOID)(Config::Get().BaseAddress + 0x1DF7120), reinterpret_cast<uint64_t(__fastcall*)(uint64_t*, uint64_t*)>(Config::Get().BaseAddress + 0xB46CC), a2, a1); //48 8b 89 ? ? ? ? e9 ? ? ? ? 83 ff + D, 48 89 74 24 ? 57 48 8b f2 48 8b f9
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

uint64_t FnDecryptParnet(uint64_t Parent, uint64_t CompID)
{
	__try
	{
		if (Parent)
		{
			unsigned __int64 v1 = Parent;
			unsigned __int64 v2 = (uint64_t)1 << (uint64_t)(CompID & 0x3F);
			unsigned __int64 v3 = v2 - 1;
			unsigned __int64 v4 = CompID & 0x3F;
			unsigned __int64 v5 = CompID / 0x3F;
			unsigned __int64 v6 = *(uint64_t*)(v1 + 8 * (uint32_t)v5 + 0x88);
			__int64 v7 = (v2 & *(uint64_t*)(v1 + 8 * (uint32_t)v5 + 0x88)) >> v4;
			unsigned __int64 v8 = (v3 & v6) - (((v3 & v6) >> 1) & 0x5555555555555555);
			unsigned __int64* v9 = (uint64_t*)(*(uint64_t*)(v1 + 0x58) + 8 * (*(uint8_t*)((uint32_t)v5 + v1 + 0xA8) + ((0x101010101010101 * (((v8 & 0x3333333333333333) + ((v8 >> 2) & 0x3333333333333333) + (((v8 & 0x3333333333333333) + ((v8 >> 2) & 0x3333333333333333)) >> 4)) & 0xF0F0F0F0F0F0F0F)) >> 0x38)));
			uint64_t Key1 = 0xFFA596F0DAAEB76E;
			uint64_t Key2 = 0x2BA9343DD086C856;
			Spoocall1(&Key2, &Key1);
			uint64_t v10 = *v9; // v9 = *(uint64_t*)(*(uint64_t*)(ParentPTR + 0x58) + index * 0x8) = EncryptData;
			uint64_t v11 = (unsigned int)v10 | ((((unsigned int)v10 - *(int*)(Config::Get().BaseAddress + 0x2CB0290 + (Key1 & 0xFFF))) ^ (v10 >> 0x20)) << 0x20); //48 8d 35 ? ? ? ? 25 ? ? ? ? 4c 8b 04 30 49 c1 e8 ? 41 f7 d0 49 c1 e0 ? 0f 1f 40
			uint64_t v12 = Key2 ^ ((unsigned int)v11 | (((unsigned int)(v11 - 732509245) ^ (v11 >> 0x20)) << 0x20));
			uint64_t v13 = (unsigned int)v12 | (((unsigned int)(2 * __ROR4__(*(_QWORD*)(Config::Get().BaseAddress + 0x2CB0290 + (Key1 >> 52)), 3) - v12) ^ (v12 >> 0x20)) << 0x20);
			uint64_t v14 = -(int)v7 & ((unsigned int)v13 | (((unsigned int)v13 ^ (unsigned int)~(*(_QWORD*)(Config::Get().BaseAddress + 0x2CB0290 + (Key1 & 0xFFF)) >> 0x20) ^ (v13 >> 0x20)) << 0x20));
			return v14;

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	return 0;
}

unsigned long RGBA2ARGB(int r, int g, int b, int a)
{
	return ((a & 0xFF) << 24) + ((b & 0xFF) << 16) + ((g & 0xFF) << 8) + (r & 0xFF);
}

//void Hook(EXCEPTION_POINTERS* ExceptionInfo)
//{
//	auto ctx = ExceptionInfo->ContextRecord;
//	GameData& data = GameData::Get();
//	ctx->Rbp = ctx->Rax;
//	static DWORD64 count = NULL;
//	uint64_t ComponentBase = ctx->Rax;
//	uint64_t ComponentParent = ctx->Rsi;
//	byte ComponentIdx = LOBYTE(ctx->Rcx);
//	++count;
//
//	if (ComponentIdx == OFFSET_PLAYER_VISIBILITY)
//	{
//		//Utils::ConsolePrint("VISIBILITY[%d] : %p - %p\n", rcx, rbp, rdi);
//		OWCOMPONENT c = OWCOMPONENT();
//		c.componentBase = ComponentBase;
//		c.componentParentPtr = ComponentParent;
//		c.componentType = OFFSET_PLAYER_VISIBILITY;
//		data.visibilityComponentList.push_back(c);
//	}
//	else if (ComponentIdx == OFFSET_UNIT_HEALTH)
//	{
//		//Utils::ConsolePrint("HEALTH[%d] : %p - %p\n", rcx, rbp, rdi);
//		OWCOMPONENT c = OWCOMPONENT();
//		c.componentBase = ComponentBase;
//		c.componentParentPtr = ComponentParent;
//		c.componentType = OFFSET_UNIT_HEALTH;
//
//		data.healthComponentList.push_back(c);
//	}
//	// 이 2개만 있으면 됌 앗 넵 
//	// Health Parent 에서 종속되는 것들 : 0x4, 0x19(Health) 0x27, 0x2F, 0x33, 0x53 
//	// Vischeck Parent 에서 종속 되는 것들 0x19(Vischeck), 0x1D, 0x2C, 0x2D, 0x32, 0x4B 등등 있음 ㅇㅎ
//	// 나머진 알아서 하고 내가 다해줄순없잖음 너가 필요하다했던건 암호화 푸는거고 네네
//}

void GetPointers()
{
	GameData& data = GameData::Get();

	data.OwEntityList.clear();

	for (int i = 0; i < data.healthComponentList.size(); i++)
	{
		try
		{
			//check if current base is readable
			OWCOMPONENT current = data.healthComponentList[i];
			uint64_t currentBase = current.componentBase;
			uint64_t parentBase = current.componentParentPtr;

			uint64_t currentVelocityComponentPtr = 0;
			uint64_t currentOutlineComponentPtr = 0;
			uint64_t currentSkillComponentPtr = 0;
			uint64_t currentBoneBaseComponentPtr = 0;
			uint64_t currentRotationPtr = 0;
			uint64_t currentUnitComponentWithPlayerID = 0;
			uint64_t currentHeroIDPointer = 0;
			uint64_t currentVisibilityPtr = 0;

			DWORD64 currentTag;
			float playerHealth = 0.0f;
			DWORD playerID = 0;
			uint64_t playerComponentParentPtr = 0;

			if (IsBadReadPtr((void*)(currentBase), OFFSET_BADREADPTR_SIZEDEFAULT))
			{
				data.healthComponentList.erase(data.healthComponentList.begin() + i);
				continue;
			}
			playerHealth = *(float*)(currentBase + OFFSET_HEALTHPTR_HEALTH);
			if (playerHealth <= 0)
				continue;

			currentTag = *(DWORD64*)(currentBase + OFFSET_HEALTHPTR_TAG);

			// VELOCITYPTR
			for (int x = 0; x < data.velocityComponentList.size(); x++)
			{
				OWCOMPONENT velocityComponent = data.velocityComponentList[x];
				if (IsBadReadPtr((void*)(velocityComponent.componentBase), OFFSET_BADREADPTR_SIZEDEFAULT))
				{
					data.velocityComponentList.erase(data.velocityComponentList.begin() + x);
					continue;
				}

				if (velocityComponent.componentParentPtr == parentBase)
					currentVelocityComponentPtr = velocityComponent.componentBase;
			}
			if (!currentVelocityComponentPtr)
				continue;

			//UCWPIDPTR	
			for (int x = 0; x < data.unitComponentWithPlayerIDComponentList.size(); x++)
			{
				OWCOMPONENT unitComponentWithPlayerID = data.unitComponentWithPlayerIDComponentList[x];

				if (IsBadReadPtr((void*)unitComponentWithPlayerID.componentBase, OFFSET_BADREADPTR_SIZEDEFAULT))
				{
					data.unitComponentWithPlayerIDComponentList.erase(data.unitComponentWithPlayerIDComponentList.begin() + x);
					continue;
					// voir si c'est n?essaire de pas continue sur componentbase
				}

				if (unitComponentWithPlayerID.componentParentPtr == parentBase)
					currentUnitComponentWithPlayerID = unitComponentWithPlayerID.componentBase;
			}
			if (!currentUnitComponentWithPlayerID)
				continue;
			playerID = *(DWORD*)(currentUnitComponentWithPlayerID + OFFSET_UCWPIDPTR_COMPOID);

			//HEROIDPTR
			for (OWCOMPONENT heroIDPtr : data.heroIDComponentList)
			{
				DWORD componentPlayerID;
				//check the visibility component player ID
				if (IsBadReadPtr((void*)(heroIDPtr.componentBase), OFFSET_BADREADPTR_SIZEDEFAULT))
					continue;

				componentPlayerID = *(DWORD*)(heroIDPtr.componentParentPtr + OFFSET_HEROIDPTR_COMPOID);

				if (componentPlayerID == playerID)
				{
					currentHeroIDPointer = heroIDPtr.componentBase;
					playerComponentParentPtr = heroIDPtr.componentParentPtr;
				}

			}
			if (!playerComponentParentPtr
				|| !currentHeroIDPointer)
				continue;

			OWENTITY currentEntity;
			currentEntity.entityTag = currentTag;
			currentEntity.basePointers.entityHealthPtr = currentBase;
			currentEntity.basePointers.entityVelocityPtr = currentVelocityComponentPtr;
			currentEntity.basePointers.entityRotationPtr = currentRotationPtr;
			currentEntity.basePointers.entityVisPtr = currentVisibilityPtr;
			currentEntity.basePointers.entityHeroIDPtr = currentHeroIDPointer;

			currentEntity.valuesPointers.health = (float*)(currentBase + OFFSET_HEALTHPTR_HEALTH);
			currentEntity.valuesPointers.armor = (float*)(currentBase + OFFSET_HEALTHPTR_ARMOR);
			currentEntity.valuesPointers.barrier = (float*)(currentBase + OFFSET_HEALTHPTR_BARRIER);
			currentEntity.valuesPointers.isMyTeam = (BYTE*)(currentBase + OFFSET_HEALTHPTR_TEAM);
			currentEntity.valuesPointers.isVisible = (BYTE*)(currentVisibilityPtr + OFFSET_VISIBILITYPTR_ISVISIBLE);
			currentEntity.valuesPointers.heroID = (DWORD64*)(currentHeroIDPointer + OFFSET_HEROIDPTR_HEROID);
			currentEntity.valuesPointers.skinID = (DWORD64*)(currentHeroIDPointer + OFFSET_HEROIDPTR_SKINID);
			currentEntity.valuesPointers.location = (Vector3*)(currentVelocityComponentPtr + OFFSET_VELOCITYPTR_LOCATION);
			currentEntity.valuesPointers.velocity = (Vector3*)(currentVelocityComponentPtr + OFFSET_VELOCITYPTR_VELOCITY);
			DWORD64 skinID = *currentEntity.valuesPointers.skinID;
			DWORD64 heroID = *currentEntity.valuesPointers.heroID;

			int boneIndex = NULL;
			auto it = std::find_if(data.Head_SkinIDs.begin(), data.Head_SkinIDs.end(), [&](pair<DWORD64, int>& sk) {
				return sk.first == skinID; });
			if (it != data.Head_SkinIDs.end())
				boneIndex = it->second;
			else {
				auto it2 = std::find_if(data.Head_HeroIDs.begin(), data.Head_HeroIDs.end(), [&](HeroID_Bone& oh) {
					return oh.heroID == heroID; });
				if (it2 != data.Head_HeroIDs.end())
					boneIndex = it2->defaultHeadBoneIndex;
				else
					continue;
			}

			uint64_t pBoneData = *(uint64_t*)(currentVelocityComponentPtr + OFFSET_VELOCITYPTR_BONEDATA);
			if (IsBadReadPtr((void*)pBoneData, OFFSET_BADREADPTR_SIZEDEFAULT))
				continue;
			uint64_t bonesBase = *(uint64_t*)(pBoneData + OFFSET_BONEDATA_BONEBASE);
			WORD count = *(WORD*)(pBoneData + OFFSET_BONEDATA_BONESCOUNT);
			if (boneIndex >= count)
				continue;
			if (IsBadReadPtr((void*)bonesBase, OFFSET_BADREADPTR_SIZEDEFAULT))
				continue;
			uint64_t currentBone = bonesBase + OFFSET_BONE_SIZE * boneIndex;
			if (IsBadReadPtr((void*)(currentBone), OFFSET_BONE_SIZE))
				continue;
			//currentEntity.valuesPointers.bonesCount = count;
			currentEntity.valuesPointers.boneLocation = (Vector3*)(currentBone + OFFSET_BONE_LOCATION);

			data.OwEntityList.push_back(currentEntity);
		}

		catch (...)
		{
			continue;
		}
	}
}

void UpdateEntities() 
{
	clock_t currTime = clock();
	GameData& data = GameData::Get();
	if (data.entityListMutex.try_lock())
	{
		for (int i = 0; i < data.BoucEntityList.size(); i++)
		{
			try
			{
				BOUCENTITY& currEntity = data.BoucEntityList[i];

				if (i >= data.OwEntityList.size())
				{
					currEntity.isValid = FALSE;
					continue;
				}
				currEntity.isValid = TRUE;
				currEntity.entityTag = data.OwEntityList[i].entityTag;
				currEntity.pointer = data.OwEntityList[i].basePointers.entityHealthPtr;
				currEntity.health = *data.OwEntityList[i].valuesPointers.health;
				currEntity.armor = *data.OwEntityList[i].valuesPointers.armor;
				currEntity.barrier = *data.OwEntityList[i].valuesPointers.barrier;
				currEntity.isMyTeam = *data.OwEntityList[i].valuesPointers.isMyTeam;
				currEntity.isVisible = *data.OwEntityList[i].valuesPointers.isVisible;
				currEntity.heroID = *data.OwEntityList[i].valuesPointers.heroID;
				currEntity.skinID = *data.OwEntityList[i].valuesPointers.skinID;
				currEntity.location = *data.OwEntityList[i].valuesPointers.location;
				currEntity.stamina = currEntity.health + currEntity.armor + currEntity.barrier;
				currEntity.maxstamina = currEntity.maxhealth + currEntity.maxarmor + currEntity.maxbarrier;

				DirectX::XMMATRIX mtx = DirectX::XMMatrixRotationY(Rotations());
				DirectX::XMVECTOR vec3 = DirectX::XMVector3Transform(DirectX::XMVectorSet(currEntity.boneLocation.x, currEntity.boneLocation.y, currEntity.boneLocation.z, 0), mtx);
				DirectX::XMFLOAT3 posMath;
				DirectX::XMStoreFloat3(&posMath, vec3);
				currEntity.entityHeadLocationByBones.x = posMath.x;
				currEntity.entityHeadLocationByBones.y = posMath.y;
				currEntity.entityHeadLocationByBones.z = posMath.z;
				currEntity.entityHeadLocationByBones.x += currEntity.boneBaseLocation.x;
				currEntity.entityHeadLocationByBones.y += currEntity.boneBaseLocation.y;
				currEntity.entityHeadLocationByBones.z += currEntity.boneBaseLocation.z;
				currEntity.entityHeadLocationByBones.y += 0.01f;
			}
			catch (...)
			{
				//Utils::ConsolePrint("UpdateEntities BUG : %p\n", BoucEntityList[i].pointer);
				data.OwEntityList.erase(data.OwEntityList.begin() + i);
				continue;
			}

			sort(data.BoucEntityList.begin(), data.BoucEntityList.end(), [&](BOUCENTITY& be1, BOUCENTITY& be2) {
				float dist_1 = viewMatrix.GetCameraVec().Distance(be1.location);
				float dist_2 = viewMatrix.GetCameraVec().Distance(be2.location);
				return be1.isValid && (dist_1 < dist_2);
			});

			auto& best = data.BoucEntityList.front();
			if (best.isValid)
			{
				float dist = viewMatrix.GetCameraVec().Distance(best.location);
				if (dist < 2.0f)
					data.localPlayerHeroID = best.heroID;
				else
					data.localPlayerHeroID = NULL;
			}
			else
				data.localPlayerHeroID = NULL;
		}
		data.entityListMutex.unlock();
	}
}

void Run()
{
	GameData& data = GameData::Get();
	while (TRUE)
	{
		if (data.lastPtrUpdate + 500 < clock())
		{
			GetPointers();
			data.lastPtrUpdate = clock();
		}

		UpdateEntities();

		Sleep(1);
	}

	__fastfail(0);
}

int TarGetIndex = -1;

Vector3 GetVector3Predit()
{
	Vector3 target = Vector3(0, 0, 0);
	Vector2 CrossHair = Vector2(1920 / 2.0f, 1080 / 2.0f);

	float origin = 100000.f;

	if (TarGetIndex == -1)
	{
		if (EntityPTR.size())
		{
			for (int i = 0; i < EntityPTR.size(); i++)
			{
				if (Entitys[i].Alive && Entitys[i].Enemy)
				{
					Vector3 world = Entitys[i].Location;
					AimCorrection(&world, Entitys[i].Velocity, viewMatrix.GetCameraVec().Distance(world), Config::Get().PreditLevel, 9.8f);

					Vector2 Vec2 = viewMatrix.WorldToScreen(world, 1920, 1080);
					Vector2 RealVe2 = Vector2(Vec2.x - CrossHair.x, Vec2.y - CrossHair.y);
					float CrossDist = CrossHair.Distance(Vec2);
					if (CrossDist < origin && CrossDist < Config::Get().Fov)
					{
						target = world;
						origin = CrossDist;
						TarGetIndex = i;
					}
					else
					{
						TarGetIndex = -1;
					}
				}
				else
				{
					TarGetIndex = -1;
				}

			}
		}
	}
	else
	{
		if (Entitys[TarGetIndex].Alive && Entitys[TarGetIndex].Enemy)
		{
			Vector3 world = Entitys[TarGetIndex].Location;
			AimCorrection(&world, Entitys[TarGetIndex].Velocity, viewMatrix.GetCameraVec().Distance(world), Config::Get().PreditLevel, 9.8f);

			Vector2 Vec2 = viewMatrix.WorldToScreen(world, 1920, 1080);

			float CrossDist = CrossHair.Distance(Vec2);
			if (CrossDist < origin && CrossDist < Config::Get().Fov)
			{
				target = world;
				origin = CrossDist;
			}
			else
			{
				TarGetIndex = -1;

			}
		}
		else
		{
			TarGetIndex = -1;
		}
	}

	return target;
}

Vector3 GetVector3()
{
	Vector3 target{};
	Vector2 CrossHair = Vector2(1920 / 2.0f, 1080 / 2.0f);

	float origin = 100000.f;

	if (TarGetIndex == -1)
	{
		if (EntityPTR.size())
		{
			for (int i = 0; i < EntityPTR.size(); i++)
			{
				if (Entitys[i].Alive && Entitys[i].Enemy)
				{
					Vector2 Vec2 = viewMatrix.WorldToScreen(Entitys[i].Location, 1920, 1080);
					float CrossDist = CrossHair.Distance(Vec2);

					if (CrossDist < origin && CrossDist < Config::Get().Fov)
					{
						target = Entitys[i].Location;
						origin = CrossDist;
						TarGetIndex = i;
					}
					else
					{
						TarGetIndex = -1;
					}
				}
				else
				{
					TarGetIndex = -1;
				}

			}
		}
	}
	else
	{
		if (Entitys[TarGetIndex].Alive && Entitys[TarGetIndex].Enemy)
		{
			Vector2 Vec2 = viewMatrix.WorldToScreen(Entitys[TarGetIndex].Location, 1920, 1080);
			float CrossDist = CrossHair.Distance(Vec2);

			if (CrossDist < origin && CrossDist < Config::Get().Fov)
			{
				target = Entitys[TarGetIndex].Location;
				origin = CrossDist;
			}
			else
			{
				TarGetIndex = -1;

			}
		}
		else
		{
			TarGetIndex = -1;
		}
	}

	return target;
}

int TarGetIndex2 = -1;

Vector3 GetVector3123123()
{
	Vector3 target{};
	Vector2 CrossHair = Vector2(1920 / 2.0f, 1080 / 2.0f);

	float origin = FLT_MAX;

	if (EntityPTR.size())
	{
		for (int i = 0; i < EntityPTR.size(); i++)
		{
			Vector3 world = Entitys[i].Location;
			AimCorrection(&world, Entitys[i].Velocity, viewMatrix.GetCameraVec().Distance(world), Config::Get().PreditLevel, 9.8f);
			if (Entitys[i].Alive && Entitys[i].Enemy)
			{
				Vector2 Vec2 = viewMatrix.WorldToScreen(world, 1920, 1080);
				float CrossDist = viewMatrix.GetCameraVec().Distance(world);

				if (CrossDist < origin)
				{
					target = world;
					origin = CrossDist;
					TarGetIndex2 = i;
				}
			}

		}
	}

	return target;
}

std::array<HeroID_Bone, MAX_PATH> Head_HeroIDs
{
	HeroID_Bone("Ana", 0x02E000000000013B, 67),
	HeroID_Bone("Ashe", 0x02E0000000000200, 125),
	HeroID_Bone("Baptiste", 0x02E0000000000221, 167),
	HeroID_Bone("Bastion", 0x02E0000000000015, 81),
	HeroID_Bone("Brigitte", 0x2E0000000000195, 77),
	HeroID_Bone("Doomfist", 0x02E000000000012F, 83),
	HeroID_Bone("Dva", 0x02E000000000007A, 140), // 140
	HeroID_Bone("Echo", 0x02E0000000000206, 42),
	HeroID_Bone("Genji", 0x02E0000000000029, 53),
	HeroID_Bone("Hanzo", 0x02E0000000000005, 38),
	HeroID_Bone("Junkrat", 0x02E0000000000065, 100),
	HeroID_Bone("Lucio", 0x02E0000000000079, 53),
	HeroID_Bone("Mccree", 0x02E0000000000042, 53),
	HeroID_Bone("Mei", 0x02E00000000000DD, 50),
	HeroID_Bone("Mercy", 0x02E0000000000004, 150),
	HeroID_Bone("Moira", 0x02E00000000001A2, 64),
	HeroID_Bone("Orisa", 0x02E000000000013E, 50),
	HeroID_Bone("Pharah", 0x02E0000000000008, 38),
	HeroID_Bone("Reaper", 0x02E0000000000002, 36),
	HeroID_Bone("Reinhardt", 0x02E0000000000007, 41),
	HeroID_Bone("Roadhog", 0x02E0000000000040, 61),
	HeroID_Bone("Soldier", 0x02E000000000006E, 38),
	HeroID_Bone("Sombra", 0x02E000000000012E, 42),
	HeroID_Bone("Sigma", 0x02E000000000023B, 180), //180
	HeroID_Bone("Symmetra", 0x02E0000000000016, 89),
	HeroID_Bone("Torbjorn", 0x02E0000000000006, 45),
	HeroID_Bone("Tracer", 0x02E0000000000003, 52),
	HeroID_Bone("Widowmaker", 0x02E000000000000A, 40),
	HeroID_Bone("Winston", 0x02E0000000000009, 109),
	HeroID_Bone("WreckingBall", 0x02E00000000001CA, 199),
	HeroID_Bone("Zarya", 0x02E0000000000068, 65),
	HeroID_Bone("Zenyatta", 0x02E0000000000020, 149),
	HeroID_Bone("TrainingBot1", 0x02E000000000016B, 37),
	HeroID_Bone("TrainingBot2", 0x02E000000000016C, 37),
	HeroID_Bone("TrainingBot3", 0x02E000000000016D, 37),
	HeroID_Bone("TrainingBot4", 0x02E000000000016E, 37),
};

std::array<pair<DWORD_PTR, int>, 544> Head_SkinIDs
{
	//Ana:
pair<DWORD64, int>(0x0A50000000001921,67),
pair<DWORD64, int>(0x0A50000000001924,67),
pair<DWORD64, int>(0x0A50000000001925,67),
pair<DWORD64, int>(0x0A50000000001922,67),
pair<DWORD64, int>(0x0A50000000001926,67),
pair<DWORD64, int>(0x0A5000000000194B,68),
pair<DWORD64, int>(0x0A50000000001923,67),
pair<DWORD64, int>(0x0A50000000001927,67),
pair<DWORD64, int>(0x0A5000000000199C,67),
pair<DWORD64, int>(0x0A50000000001B11,67),
pair<DWORD64, int>(0x0A5000000000194A,68),
pair<DWORD64, int>(0x0A50000000001950,68),
pair<DWORD64, int>(0x0A50000000001951,68),
pair<DWORD64, int>(0x0A50000000001BB8,64),
pair<DWORD64, int>(0x0A50000000001B0F,75),
pair<DWORD64, int>(0x0A50000000001C0F,68),
pair<DWORD64, int>(0x0A50000000004570, 117),
//Ashe:
pair<DWORD64, int>(0x0A50000000001ED3,125),
pair<DWORD64, int>(0x0A500000000021CF,111),
pair<DWORD64, int>(0x0A50000000002A02,125),
pair<DWORD64, int>(0x0A50000000002A01,125),
pair<DWORD64, int>(0x0A50000000002A04,125),
pair<DWORD64, int>(0x0A50000000002A03,125),
pair<DWORD64, int>(0x0A50000000002A06,125),
pair<DWORD64, int>(0x0A50000000002A05,125),
pair<DWORD64, int>(0x0A50000000002A10,125),
pair<DWORD64, int>(0x0A50000000002A07,111),
pair<DWORD64, int>(0x0A50000000002A09,108),
pair<DWORD64, int>(0x0A500000000021D2,108),
pair<DWORD64, int>(0x0A50000000002A13,122),
//Baptiste:
pair<DWORD64, int>(0x0A50000000002188,66),
pair<DWORD64, int>(0x0A50000000002C8A,66),
pair<DWORD64, int>(0x0A50000000002C87,66),
pair<DWORD64, int>(0x0A50000000002C89,66),
pair<DWORD64, int>(0x0A50000000002C88,66),
pair<DWORD64, int>(0x0A50000000002C92,66),
pair<DWORD64, int>(0x0A50000000002C90,69),
pair<DWORD64, int>(0x0A50000000002CDD,50),
pair<DWORD64, int>(0x0A50000000002C77,50),
pair<DWORD64, int>(0x0A50000000002C7F,52),
pair<DWORD64, int>(0x0A50000000002CDB,52),
pair<DWORD64, int>(0x0A50000000002C7A,166),
//Bastion:
pair<DWORD64, int>(0x0A50000000001627,81),
pair<DWORD64, int>(0x0A50000000001628,81),
pair<DWORD64, int>(0x0A50000000001629,81),
pair<DWORD64, int>(0x0A500000000018CC,81),
pair<DWORD64, int>(0x0A500000000018CD,81),
pair<DWORD64, int>(0x0A50000000002A46,81),
pair<DWORD64, int>(0x0A50000000001799,98),
pair<DWORD64, int>(0x0A5000000000162A,81),
pair<DWORD64, int>(0x0A500000000018CE,81),
pair<DWORD64, int>(0x0A5000000000199F,81),
pair<DWORD64, int>(0x0A50000000001AE8,81),
pair<DWORD64, int>(0x0A50000000001B93,81),
pair<DWORD64, int>(0x0A50000000001798,98),
pair<DWORD64, int>(0x0A50000000001795,109),
pair<DWORD64, int>(0x0A50000000001794,109),
pair<DWORD64, int>(0x0A50000000001C3E,99),
pair<DWORD64, int>(0x0A50000000001B90,96),
pair<DWORD64, int>(0x0A50000000001E97,97),
pair<DWORD64, int>(0x0A50000000001623,106),
pair<DWORD64, int>(0x0A50000000002A58,86),
//Brigitte:
pair<DWORD64, int>(0x0A50000000001BCE,77),
pair<DWORD64, int>(0x0A50000000001EAB,77),
pair<DWORD64, int>(0x0A50000000001EAA,77),
pair<DWORD64, int>(0x0A50000000001EA8,77),
pair<DWORD64, int>(0x0A50000000001EA9,77),
pair<DWORD64, int>(0x0A50000000001EA5,77),
pair<DWORD64, int>(0x0A50000000001EAD,75),
pair<DWORD64, int>(0x0A50000000002131,77),
pair<DWORD64, int>(0x0A50000000002A54,121),
pair<DWORD64, int>(0x0A50000000001EC2,70),
pair<DWORD64, int>(0x0A50000000001E80,70),
pair<DWORD64, int>(0x0A50000000001E81,73),
pair<DWORD64, int>(0x0A50000000001EC3,73),
pair<DWORD64, int>(0x0A50000000001EBC,61),
//Doomfist:
pair<DWORD64, int>(0x0A5000000000160F,83),
pair<DWORD64, int>(0x0A50000000001610,83),
pair<DWORD64, int>(0x0A500000000018C3,83),
pair<DWORD64, int>(0x0A50000000001611,83),
pair<DWORD64, int>(0x0A50000000001612,83),
pair<DWORD64, int>(0x0A500000000018C5,83),
pair<DWORD64, int>(0x0A500000000018C4,83),
pair<DWORD64, int>(0x0A50000000001C14,64),
pair<DWORD64, int>(0x0A50000000001BE3,65),
pair<DWORD64, int>(0x0A50000000001BD9,65),
pair<DWORD64, int>(0x0A50000000001BE4,81),
//Dva:

pair<DWORD64, int>(0x0A50000000001613, 151),
pair<DWORD64, int>(0x0A50000000001616,151),
pair<DWORD64, int>(0x0A500000000018C6,151),
pair<DWORD64, int>(0x0A5000000000197A,151),
pair<DWORD64, int>(0x0A50000000001764,72),
pair<DWORD64, int>(0x0A50000000001615, 151),
pair<DWORD64, int>(0x0A50000000001614, 151),
pair<DWORD64, int>(0x0A500000000018C7, 151),
pair<DWORD64, int>(0x0A500000000018C8, 151),
pair<DWORD64, int>(0x0A500000000017A0, 75),
pair<DWORD64, int>(0x0A500000000017A1, 75),
pair<DWORD64, int>(0x0A50000000001765, 72),
pair<DWORD64, int>(0x0A50000000001C3D, 88),
pair<DWORD64, int>(0x0A50000000001BB0, 71),
pair<DWORD64, int>(0x0A50000000001EA2, 44),
pair<DWORD64, int>(0x0A50000000001A19, 92),
pair<DWORD64, int>(0x0A5000000000196C, 71),

// Echo
pair<DWORD64, int>(0x0A500000000020E0, 42),
pair<DWORD64, int>(0x0A500000000046C3, 42),
pair<DWORD64, int>(0x0A500000000046C6, 42),
pair<DWORD64, int>(0x0A500000000046C4, 42),
pair<DWORD64, int>(0x0A500000000046C5, 42),
pair<DWORD64, int>(0x0A500000000046C7, 42),
pair<DWORD64, int>(0x0A500000000046C8, 42),

pair<DWORD64, int>(0x0A500000000046B7, 53),
pair<DWORD64, int>(0x0A500000000046E4, 53),
pair<DWORD64, int>(0x0A500000000046BC, 43),
pair<DWORD64, int>(0x0A500000000046D4, 43),
//Genji:
pair<DWORD64, int>(0x0A500000000016D7, 53),
pair<DWORD64, int>(0x0A500000000016D8, 53),
pair<DWORD64, int>(0x0A500000000018EA, 53),
pair<DWORD64, int>(0x0A500000000016D9, 53),
pair<DWORD64, int>(0x0A500000000016DA, 53),
pair<DWORD64, int>(0x0A500000000018EB, 53),
pair<DWORD64, int>(0x0A50000000001785, 55),
pair<DWORD64, int>(0x0A50000000001789, 60),
pair<DWORD64, int>(0x0A50000000001994, 47),
pair<DWORD64, int>(0x0A500000000018EC, 53),
pair<DWORD64, int>(0x0A5000000000197C, 53),
pair<DWORD64, int>(0x0A50000000001784, 55),
pair<DWORD64, int>(0x0A50000000001788, 60),
pair<DWORD64, int>(0x0A50000000001C1D, 54),
pair<DWORD64, int>(0x0A50000000001B7D, 42),
pair<DWORD64, int>(0x0A50000000001B91, 57),
//hanzo:
pair<DWORD64, int>(0x0A500000000015EB, 38),
pair<DWORD64, int>(0x0A500000000015ED, 38),
pair<DWORD64, int>(0x0A500000000018B4, 38),
pair<DWORD64, int>(0x0A500000000015EC, 38),
pair<DWORD64, int>(0x0A500000000015EE, 38),
pair<DWORD64, int>(0x0A500000000018B6, 38),
pair<DWORD64, int>(0x0A500000000018B5, 38),
pair<DWORD64, int>(0x0A500000000019A7, 38),
pair<DWORD64, int>(0x0A500000000019B4, 34),
pair<DWORD64, int>(0x0A500000000015E3, 40),
pair<DWORD64, int>(0x0A500000000015E4, 40),
pair<DWORD64, int>(0x0A500000000015E8, 55),
pair<DWORD64, int>(0x0A500000000015E7, 55),
pair<DWORD64, int>(0x0A500000000019B2, 46),
pair<DWORD64, int>(0x0A50000000002129, 42),
pair<DWORD64, int>(0x0A50000000001C28, 33),
pair<DWORD64, int>(0x0A500000000019B0, 33),
//Junkrat:
pair<DWORD64, int>(0x0A50000000001607, 100),
pair<DWORD64, int>(0x0A50000000001608, 100),
pair<DWORD64, int>(0x0A50000000001609, 100),
pair<DWORD64, int>(0x0A500000000018BD, 100),
pair<DWORD64, int>(0x0A50000000001A2D, 106),
pair<DWORD64, int>(0x0A5000000000179C, 149),
pair<DWORD64, int>(0x0A50000000001962, 137),
pair<DWORD64, int>(0x0A5000000000160A, 100),
pair<DWORD64, int>(0x0A50000000001C4D, 100),
pair<DWORD64, int>(0x0A500000000018BE, 100),
pair<DWORD64, int>(0x0A500000000018BF, 100),
pair<DWORD64, int>(0x0A5000000000179D, 149),
pair<DWORD64, int>(0x0A5000000000177D, 84),
pair<DWORD64, int>(0x0A5000000000177C, 84),
pair<DWORD64, int>(0x0A50000000001BC1, 128),
pair<DWORD64, int>(0x0A500000000020E7, 146),
pair<DWORD64, int>(0x0A50000000001C13, 99),
pair<DWORD64, int>(0x0A50000000001C73, 155),
pair<DWORD64, int>(0x0A50000000002CE5, 100),
pair<DWORD64, int>(0x0A500000000041F5, 108),
//Lucio:
pair<DWORD64, int>(0x0A5000000000160B, 52),
pair<DWORD64, int>(0x0A500000000018C0, 52),
pair<DWORD64, int>(0x0A5000000000160C, 52),
pair<DWORD64, int>(0x0A5000000000160E, 52),
pair<DWORD64, int>(0x0A500000000018C2, 52),
pair<DWORD64, int>(0x0A500000000018C1, 52),
pair<DWORD64, int>(0x0A50000000001778, 52),
pair<DWORD64, int>(0x0A5000000000160D, 52),
pair<DWORD64, int>(0x0A50000000001A0B, 52),
pair<DWORD64, int>(0x0A500000000020EC, 52),
pair<DWORD64, int>(0x0A50000000001BC2, 65),
pair<DWORD64, int>(0x0A50000000001779, 52),
pair<DWORD64, int>(0x0A50000000001911, 46),
pair<DWORD64, int>(0x0A50000000001910, 46),
pair<DWORD64, int>(0x0A50000000001947, 51),
pair<DWORD64, int>(0x0A50000000001946, 51),
pair<DWORD64, int>(0x0A5000000000257D, 54),
pair<DWORD64, int>(0x0A50000000001E2F, 47),
pair<DWORD64, int>(0x0A50000000001B94, 51),
//Mccree:
pair<DWORD64, int>(0x0A500000000015F7, 53),
pair<DWORD64, int>(0x0A500000000015FA, 53),
pair<DWORD64, int>(0x0A500000000018B7, 53),
pair<DWORD64, int>(0x0A500000000015F9, 53),
pair<DWORD64, int>(0x0A500000000018B9, 53),
pair<DWORD64, int>(0x0A500000000015F3, 37),
pair<DWORD64, int>(0x0A500000000015F0, 57),
pair<DWORD64, int>(0x0A500000000015F8, 53),
pair<DWORD64, int>(0x0A500000000018B8, 53),
pair<DWORD64, int>(0x0A50000000001C4C, 53),
pair<DWORD64, int>(0x0A50000000001976, 53),
pair<DWORD64, int>(0x0A500000000021CD, 53),
pair<DWORD64, int>(0x0A50000000001A12, 56),
pair<DWORD64, int>(0x0A500000000015F4, 37),
pair<DWORD64, int>(0x0A500000000015EF, 57),
pair<DWORD64, int>(0x0A50000000001BCD, 94),
pair<DWORD64, int>(0x0A50000000001BCA, 85),
pair<DWORD64, int>(0x0A50000000001C12, 125),
pair<DWORD64, int>(0x0A500000000019B6, 94),
pair<DWORD64, int>(0x0A50000000001E0C, 97),
pair<DWORD64, int>(0x0A50000000002A08, 54),
pair<DWORD64, int>(0x0A50000000002CD5, 54),
//Mei:
pair<DWORD64, int>(0x0A5000000000161F, 50),
pair<DWORD64, int>(0x0A50000000001620, 50),
pair<DWORD64, int>(0x0A500000000018C9, 50),
pair<DWORD64, int>(0x0A50000000001621, 50),
pair<DWORD64, int>(0x0A50000000001982, 72),
pair<DWORD64, int>(0x0A50000000001B67, 58),
pair<DWORD64, int>(0x0A50000000001622, 50),
pair<DWORD64, int>(0x0A500000000018CB, 50),
pair<DWORD64, int>(0x0A500000000018CA, 50),
pair<DWORD64, int>(0x0A500000000021AC, 50),
pair<DWORD64, int>(0x0A50000000001BE1, 58),
pair<DWORD64, int>(0x0A500000000017A5, 55),
pair<DWORD64, int>(0x0A500000000017A4, 55),
pair<DWORD64, int>(0x0A50000000001915, 106),
pair<DWORD64, int>(0x0A50000000001914, 106),
pair<DWORD64, int>(0x0A50000000001BEC, 112),
pair<DWORD64, int>(0x0A50000000001A10, 50),
pair<DWORD64, int>(0x0A50000000001981, 86),
pair<DWORD64, int>(0x0A500000000046A2, 115),
//Mercy:
pair<DWORD64, int>(0x0A500000000015DB, 150),
pair<DWORD64, int>(0x0A500000000018AE, 150),
pair<DWORD64, int>(0x0A500000000015DC, 150),
pair<DWORD64, int>(0x0A500000000015DE, 150),
pair<DWORD64, int>(0x0A500000000015D4, 149),
pair<DWORD64, int>(0x0A500000000015D8, 157),
pair<DWORD64, int>(0x0A500000000015DD, 168),
pair<DWORD64, int>(0x0A500000000018B0, 168),
pair<DWORD64, int>(0x0A500000000018AF, 168),
pair<DWORD64, int>(0x0A50000000001979, 168),
pair<DWORD64, int>(0x0A50000000001A2A, 168),
pair<DWORD64, int>(0x0A500000000015D3, 149),
pair<DWORD64, int>(0x0A500000000015D7, 157),
pair<DWORD64, int>(0x0A50000000001BC6, 171),
pair<DWORD64, int>(0x0A5000000000196A, 157),
pair<DWORD64, int>(0x0A50000000001F71, 171),
pair<DWORD64, int>(0x0A50000000001C11, 170),
pair<DWORD64, int>(0x0A50000000001B7B, 152),
//Moira:
pair<DWORD64, int>(0x0A50000000001BE8, 64),
pair<DWORD64, int>(0x0A50000000001C5E, 64),
pair<DWORD64, int>(0x0A50000000001C5F, 64),
pair<DWORD64, int>(0x0A50000000001C61, 64),
pair<DWORD64, int>(0x0A50000000001C60, 64),
pair<DWORD64, int>(0x0A50000000001C62, 64),
pair<DWORD64, int>(0x0A50000000001C63, 64),
pair<DWORD64, int>(0x0A50000000002136, 64),
pair<DWORD64, int>(0x0A50000000001C6A, 69),
pair<DWORD64, int>(0x0A50000000001C42, 69),
pair<DWORD64, int>(0x0A50000000001C45, 114),
pair<DWORD64, int>(0x0A50000000001C79, 114),
pair<DWORD64, int>(0x0A5000000000212A, 51),
pair<DWORD64, int>(0x0A50000000001C75, 42),
pair<DWORD64, int>(0x0A50000000002C72, 95),
//Orisa:
pair<DWORD64, int>(0x0A50000000001933, 50),
pair<DWORD64, int>(0x0A50000000001935, 50),
pair<DWORD64, int>(0x0A50000000001934, 50),
pair<DWORD64, int>(0x0A50000000001937, 50),
pair<DWORD64, int>(0x0A50000000001936, 50),
pair<DWORD64, int>(0x0A50000000001938, 50),
pair<DWORD64, int>(0x0A50000000001B95, 49),
pair<DWORD64, int>(0x0A50000000002A11, 58),
pair<DWORD64, int>(0x0A50000000001C10, 58),
pair<DWORD64, int>(0x0A50000000001B62, 59),
pair<DWORD64, int>(0x0A50000000001B65, 59),
pair<DWORD64, int>(0x0A50000000001B64, 55),
pair<DWORD64, int>(0x0A50000000001B63, 55),
pair<DWORD64, int>(0x0A50000000001B61, 54),
pair<DWORD64, int>(0x0A50000000001C6F, 56),
//Pharah:
pair<DWORD64, int>(0x0A500000000016BF, 38),
pair<DWORD64, int>(0x0A500000000016C2, 38),
pair<DWORD64, int>(0x0A50000000001768, 49),
pair<DWORD64, int>(0x0A500000000016C1, 38),
pair<DWORD64, int>(0x0A500000000018E1, 38),
pair<DWORD64, int>(0x0A500000000016C0, 38),
pair<DWORD64, int>(0x0A50000000001929, 42),
pair<DWORD64, int>(0x0A50000000001928, 42),
pair<DWORD64, int>(0x0A500000000019A0, 38),
pair<DWORD64, int>(0x0A50000000001A16, 42),
pair<DWORD64, int>(0x0A500000000019EA, 92),
pair<DWORD64, int>(0x0A50000000001769, 49),
pair<DWORD64, int>(0x0A5000000000192A, 112),
pair<DWORD64, int>(0x0A5000000000192B, 112),
pair<DWORD64, int>(0x0A500000000020E6, 5), // voir 6 ou 87
pair<DWORD64, int>(0x0A50000000001C0B, 38),
pair<DWORD64, int>(0x0A500000000019E6, 111),
pair<DWORD64, int>(0x0A500000000016A7, 105),
pair<DWORD64, int>(0x0A50000000002D7C, 108),
//Reaper:
pair<DWORD64, int>(0x0A50000000001697, 36),
pair<DWORD64, int>(0x0A50000000001699, 36),
pair<DWORD64, int>(0x0A500000000018DB, 36),
pair<DWORD64, int>(0x0A500000000018DD, 36),
pair<DWORD64, int>(0x0A5000000000167C, 47),
pair<DWORD64, int>(0x0A5000000000169A, 36),
pair<DWORD64, int>(0x0A50000000001698, 36),
pair<DWORD64, int>(0x0A500000000018DC, 36),
pair<DWORD64, int>(0x0A50000000001C3C, 36),
pair<DWORD64, int>(0x0A50000000001A07, 36),
pair<DWORD64, int>(0x0A50000000001770, 49),
pair<DWORD64, int>(0x0A50000000001771, 49),
pair<DWORD64, int>(0x0A5000000000167B, 47),
pair<DWORD64, int>(0x0A50000000001BC0, 45),
pair<DWORD64, int>(0x0A5000000000195A, 58),
pair<DWORD64, int>(0x0A50000000001BEB, 41),
pair<DWORD64, int>(0x0A500000000021C1, 38),
pair<DWORD64, int>(0x0A50000000001C74, 34),
pair<DWORD64, int>(0x0A5000000000168B, 50),
//Reinhardt:
pair<DWORD64, int>(0x0A5000000000165F, 41),
pair<DWORD64, int>(0x0A50000000001660, 41),
pair<DWORD64, int>(0x0A50000000001662, 41),
pair<DWORD64, int>(0x0A500000000018D6, 41),
pair<DWORD64, int>(0x0A5000000000163F, 41),
pair<DWORD64, int>(0x0A50000000001954, 53),
pair<DWORD64, int>(0x0A500000000018D5, 41),
pair<DWORD64, int>(0x0A50000000001661, 41),
pair<DWORD64, int>(0x0A500000000017B1, 41),
pair<DWORD64, int>(0x0A500000000019A1, 41),
pair<DWORD64, int>(0x0A50000000002A0C, 41),
pair<DWORD64, int>(0x0A50000000001B87, 41),
pair<DWORD64, int>(0x0A50000000001B7E, 37),
pair<DWORD64, int>(0x0A50000000001640, 41),
pair<DWORD64, int>(0x0A5000000000163B, 39),
pair<DWORD64, int>(0x0A5000000000163C, 39),
pair<DWORD64, int>(0x0A50000000001955, 53),
pair<DWORD64, int>(0x0A50000000001EB6, 37),
pair<DWORD64, int>(0x0A500000000021BB, 38),
pair<DWORD64, int>(0x0A50000000001991, 44),
//Roadhog:
pair<DWORD64, int>(0x0A500000000016A3, 61),
pair<DWORD64, int>(0x0A500000000018DE, 61),
pair<DWORD64, int>(0x0A500000000016A4, 61),
pair<DWORD64, int>(0x0A50000000001A14, 61),
pair<DWORD64, int>(0x0A50000000001C1C, 80),
pair<DWORD64, int>(0x0A500000000016A5, 61),
pair<DWORD64, int>(0x0A500000000016A6, 61),
pair<DWORD64, int>(0x0A500000000018E0, 61),
pair<DWORD64, int>(0x0A500000000018DF, 61),
pair<DWORD64, int>(0x0A50000000001C1B, 74),
pair<DWORD64, int>(0x0A500000000016A0, 53),
pair<DWORD64, int>(0x0A5000000000169F, 53),
pair<DWORD64, int>(0x0A5000000000169C, 65),
pair<DWORD64, int>(0x0A5000000000169B, 65),
pair<DWORD64, int>(0x0A500000000020E9, 112),
pair<DWORD64, int>(0x0A5000000000195C, 62),
pair<DWORD64, int>(0x0A5000000000197D, 53),
pair<DWORD64, int>(0x0A50000000002D76, 78),
//Soldier:
pair<DWORD64, int>(0x0A500000000016C7, 38),
pair<DWORD64, int>(0x0A500000000016C9, 38),
pair<DWORD64, int>(0x0A500000000016CA, 38),
pair<DWORD64, int>(0x0A500000000018E4, 38),
pair<DWORD64, int>(0x0A500000000016C8, 38),
pair<DWORD64, int>(0x0A500000000018E6, 38),
pair<DWORD64, int>(0x0A500000000018E5, 38),
pair<DWORD64, int>(0x0A500000000019A6, 38),
pair<DWORD64, int>(0x0A500000000020E8, 38),
pair<DWORD64, int>(0x0A5000000000178C, 55),
pair<DWORD64, int>(0x0A5000000000178D, 55),
pair<DWORD64, int>(0x0A50000000001791, 54),
pair<DWORD64, int>(0x0A50000000001790, 54),
pair<DWORD64, int>(0x0A50000000001BC8, 41),
pair<DWORD64, int>(0x0A50000000001EBE, 47),
pair<DWORD64, int>(0x0A50000000001C1E, 45),
pair<DWORD64, int>(0x0A50000000001A1E, 116),
pair<DWORD64, int>(0x0A500000000016C3, 43),
pair<DWORD64, int>(0x0A50000000002A5D, 46),
//Sombra:
pair<DWORD64, int>(0x0A5000000000162B, 42),
pair<DWORD64, int>(0x0A5000000000162D, 42),
pair<DWORD64, int>(0x0A5000000000162E, 42),
pair<DWORD64, int>(0x0A50000000001A1D, 42),
pair<DWORD64, int>(0x0A5000000000162C, 42),
pair<DWORD64, int>(0x0A500000000018CF, 42),
pair<DWORD64, int>(0x0A500000000018D0, 42),
pair<DWORD64, int>(0x0A500000000018D1, 42),
pair<DWORD64, int>(0x0A50000000002138, 42),
pair<DWORD64, int>(0x0A5000000000198B, 57),
pair<DWORD64, int>(0x0A5000000000198A, 57),
pair<DWORD64, int>(0x0A5000000000198C, 36),
pair<DWORD64, int>(0x0A5000000000198D, 36),
pair<DWORD64, int>(0x0A50000000001BC7, 37),
pair<DWORD64, int>(0x0A500000000020DB, 52),
pair<DWORD64, int>(0x0A50000000001C16, 46),
pair<DWORD64, int>(0x0A50000000001C17, 36),
pair<DWORD64, int>(0x0A5000000000213B, 49),
// SIGMA
pair<DWORD64, int>(0x0A500000000028CF, 110),
pair<DWORD64, int>(0x0A50000000002D65, 110),
pair<DWORD64, int>(0x0A50000000002D64, 110),
pair<DWORD64, int>(0x0A50000000002D62, 110),
pair<DWORD64, int>(0x0A50000000002D66, 110),
pair<DWORD64, int>(0x0A50000000002D67, 110),

//Symmetra:
pair<DWORD64, int>(0x0A500000000016E7, 89),
pair<DWORD64, int>(0x0A500000000016E9, 89),
pair<DWORD64, int>(0x0A50000000001998, 89),
pair<DWORD64, int>(0x0A500000000016E4, 86),
pair<DWORD64, int>(0x0A500000000016E3, 86),
pair<DWORD64, int>(0x0A500000000016DB, 92),
pair<DWORD64, int>(0x0A500000000016E8, 89),
pair<DWORD64, int>(0x0A500000000016EA, 89),
pair<DWORD64, int>(0x0A500000000018ED, 89),
pair<DWORD64, int>(0x0A50000000001C44, 89),
pair<DWORD64, int>(0x0A500000000018EE, 89),
pair<DWORD64, int>(0x0A500000000018EF, 89),
pair<DWORD64, int>(0x0A50000000001A27, 89),
pair<DWORD64, int>(0x0A500000000016DC, 92),
pair<DWORD64, int>(0x0A500000000016DF, 97),
pair<DWORD64, int>(0x0A50000000002133, 90),
pair<DWORD64, int>(0x0A50000000001E0A, 95),
pair<DWORD64, int>(0x0A50000000001B92, 83),
pair<DWORD64, int>(0x0A500000000046A3, 89),
//Torbjorn:
pair<DWORD64, int>(0x0A50000000001637, 45),
pair<DWORD64, int>(0x0A50000000001638, 45),
pair<DWORD64, int>(0x0A50000000001639, 45),
pair<DWORD64, int>(0x0A50000000001BAD, 64),
pair<DWORD64, int>(0x0A5000000000163A, 45),
pair<DWORD64, int>(0x0A500000000018D2, 45),
pair<DWORD64, int>(0x0A500000000018D4, 45),
pair<DWORD64, int>(0x0A500000000018D3, 45),
pair<DWORD64, int>(0x0A5000000000197B, 45),
pair<DWORD64, int>(0x0A50000000001C18, 92),
pair<DWORD64, int>(0x0A5000000000162F, 51),
pair<DWORD64, int>(0x0A50000000001630, 51),
pair<DWORD64, int>(0x0A50000000001633, 59),
pair<DWORD64, int>(0x0A50000000001634, 59),
pair<DWORD64, int>(0x0A50000000001BCB, 96),
pair<DWORD64, int>(0x0A50000000001968, 92),
pair<DWORD64, int>(0x0A500000000021AB, 55),
pair<DWORD64, int>(0x0A50000000001B60, 121),
pair<DWORD64, int>(0x0A50000000001C6E, 118),
pair<DWORD64, int>(0x0A500000000046A6, 46),
//Tracer:
pair<DWORD64, int>(0x0A5000000000170F, 52),
pair<DWORD64, int>(0x0A50000000001711, 52),
pair<DWORD64, int>(0x0A50000000001712, 52),
pair<DWORD64, int>(0x0A50000000001710, 52),
pair<DWORD64, int>(0x0A500000000018F1, 52),
pair<DWORD64, int>(0x0A50000000001942, 45),
pair<DWORD64, int>(0x0A5000000000195E, 46),
pair<DWORD64, int>(0x0A500000000018F0, 52),
pair<DWORD64, int>(0x0A500000000018F2, 52),
pair<DWORD64, int>(0x0A50000000001B07, 52),
pair<DWORD64, int>(0x0A500000000020EB, 52),
pair<DWORD64, int>(0x0A500000000016EB, 49),
pair<DWORD64, int>(0x0A500000000016EC, 49),
pair<DWORD64, int>(0x0A5000000000170B, 50),
pair<DWORD64, int>(0x0A5000000000170C, 50),
pair<DWORD64, int>(0x0A50000000001943, 45),
pair<DWORD64, int>(0x0A500000000021F2, 58),
pair<DWORD64, int>(0x0A50000000001B66, 41),
pair<DWORD64, int>(0x0A50000000001B2B, 37),
pair<DWORD64, int>(0x0A500000000016F7, 123),
//Widowmaker:
pair<DWORD64, int>(0x0A5000000000171B, 40),
pair<DWORD64, int>(0x0A5000000000171C, 40),
pair<DWORD64, int>(0x0A5000000000171E, 40),
pair<DWORD64, int>(0x0A500000000018F3, 40),
pair<DWORD64, int>(0x0A5000000000171D, 40),
pair<DWORD64, int>(0x0A50000000001C21, 38),
pair<DWORD64, int>(0x0A500000000018F4, 40),
pair<DWORD64, int>(0x0A500000000018F5, 40),
pair<DWORD64, int>(0x0A50000000001978, 40),
pair<DWORD64, int>(0x0A500000000021BA, 40),
pair<DWORD64, int>(0x0A50000000001714, 39),
pair<DWORD64, int>(0x0A50000000001713, 39),
pair<DWORD64, int>(0x0A50000000001919, 47),
pair<DWORD64, int>(0x0A50000000001918, 47),
pair<DWORD64, int>(0x0A50000000001C20, 38),
pair<DWORD64, int>(0x0A50000000001BC9, 38),
pair<DWORD64, int>(0x0A50000000002113, 46),
pair<DWORD64, int>(0x0A50000000001C1F, 46),
pair<DWORD64, int>(0x0A50000000001BAF, 38),
pair<DWORD64, int>(0x0A50000000001717, 42), // 누아르
//Winston:
pair<DWORD64, int>(0x0A500000000016D3, 109),
pair<DWORD64, int>(0x0A500000000016D6, 109),
pair<DWORD64, int>(0x0A500000000018E7, 109),
pair<DWORD64, int>(0x0A500000000018E9, 109),
pair<DWORD64, int>(0x0A5000000000197F, 87),
pair<DWORD64, int>(0x0A500000000016D5, 109),
pair<DWORD64, int>(0x0A500000000016D4, 109),
pair<DWORD64, int>(0x0A500000000018E8, 109),
pair<DWORD64, int>(0x0A500000000016CF, 61),
pair<DWORD64, int>(0x0A500000000016D0, 61),
pair<DWORD64, int>(0x0A500000000016CB, 105),
pair<DWORD64, int>(0x0A500000000016CC, 105),
pair<DWORD64, int>(0x0A50000000001EAC, 61),
pair<DWORD64, int>(0x0A50000000001964, 61),
pair<DWORD64, int>(0x0A50000000001CC6, 56),
//WreckingBall:
pair<DWORD64, int>(0x0A50000000001C56, 199),
pair<DWORD64, int>(0x0A5000000000213F, 199),
pair<DWORD64, int>(0x0A5000000000213D, 199),
pair<DWORD64, int>(0x0A5000000000213C, 199),
pair<DWORD64, int>(0x0A5000000000213E, 199),
pair<DWORD64, int>(0x0A50000000002143, 199),
pair<DWORD64, int>(0x0A50000000002142, 199),
pair<DWORD64, int>(0x0A5000000000214A, 145),
pair<DWORD64, int>(0x0A50000000002128, 138),
pair<DWORD64, int>(0x0A50000000002147, 153),
pair<DWORD64, int>(0x0A50000000002130, 153),
pair<DWORD64, int>(0x0A5000000000214E, 153),
pair<DWORD64, int>(0x0A50000000002CD8, 199),
//Zarya:
pair<DWORD64, int>(0x0A5000000000166B, 65),
pair<DWORD64, int>(0x0A5000000000166E, 65),
pair<DWORD64, int>(0x0A500000000018D8, 65),
pair<DWORD64, int>(0x0A5000000000166D, 65),
pair<DWORD64, int>(0x0A5000000000166C, 65),
pair<DWORD64, int>(0x0A500000000018D9, 65),
pair<DWORD64, int>(0x0A50000000001A1B, 65),
pair<DWORD64, int>(0x0A50000000001664, 36),
pair<DWORD64, int>(0x0A500000000018DA, 65),
pair<DWORD64, int>(0x0A50000000001C1A, 51),
pair<DWORD64, int>(0x0A50000000001668, 43),
pair<DWORD64, int>(0x0A50000000001667, 43),
pair<DWORD64, int>(0x0A50000000001663, 36),
pair<DWORD64, int>(0x0A50000000001944, 52),
pair<DWORD64, int>(0x0A50000000001945, 52),
pair<DWORD64, int>(0x0A5000000000196E, 57),
pair<DWORD64, int>(0x0A50000000002134, 76),
pair<DWORD64, int>(0x0A50000000001C19, 58),
pair<DWORD64, int>(0x0A50000000001B6A, 49),
pair<DWORD64, int>(0x0A50000000002CDF, 65),
pair<DWORD64, int>(0x0A500000000045BE, 109),
//Zenyatta:
pair<DWORD64, int>(0x0A50000000001603, 149),
pair<DWORD64, int>(0x0A500000000018BA, 149),
pair<DWORD64, int>(0x0A50000000001604, 149),
pair<DWORD64, int>(0x0A500000000018BB, 149),
pair<DWORD64, int>(0x0A500000000015FB, 52),
pair<DWORD64, int>(0x0A50000000001966, 99),
pair<DWORD64, int>(0x0A50000000001605, 149),
pair<DWORD64, int>(0x0A50000000001606, 149),
pair<DWORD64, int>(0x0A50000000001C40, 149),
pair<DWORD64, int>(0x0A500000000018BC, 149),
pair<DWORD64, int>(0x0A500000000019A3, 149),
pair<DWORD64, int>(0x0A500000000015FC, 52),
pair<DWORD64, int>(0x0A500000000015FF, 98),
pair<DWORD64, int>(0x0A50000000001600, 98),
pair<DWORD64, int>(0x0A50000000001E2D, 89),
pair<DWORD64, int>(0x0A50000000001BE7, 128),
pair<DWORD64, int>(0x0A50000000001960, 110),
pair<DWORD64, int>(0x0A500000000021D1, 93),
//Training Bots:
pair<DWORD64, int>(0x0A50000000001AFC, 37),
pair<DWORD64, int>(0x0A50000000001AF8, 37),
pair<DWORD64, int>(0x0A50000000001AFA, 37),
};

void Taimbot()
{
	while (TRUE)
	{
		uint64_t pAngle = Config::Get().RPM<uint64_t>(AnglePTR + OFFSET_PLAYER_CONTROLLER_ROTATION);
		bool shooted = false;
		BOOL IsMouse = FALSE;

		if (Config::Get().TPAimbot)
		{
			Config::Get().GravityBool = false;
			while (GetAsyncKeyState(VK_XBUTTON2))
			{
				if (!shooted)
				{
					Vector3 world = GetVector3Predit();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(AnglePTR + OFFSET_PLAYER_CONTROLLER_ROTATION);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.01f;
						Vector3 smoothed = SmoothAngle(currentAngle, angle, Config::Get().AimSpeed, Config::Get().AimSpeed);
						Config::Get().WPM<Vector3>(pAngle, smoothed);
					}
				}
				this_thread::sleep_for(1ms);
			}
		}

		if (Config::Get().HanzoAimbot)
		{
			Config::Get().GravityBool = true;
			while (GetAsyncKeyState(VK_XBUTTON2))
			{
				Config::Get().PreditLevel = 115.f;
				if (!shooted)
				{
					Vector3 world = GetVector3Predit();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(AnglePTR + OFFSET_PLAYER_CONTROLLER_ROTATION);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.01f;
						Vector3 smoothed = SmoothAngle(currentAngle, angle, speed, speed);
						Config::Get().WPM<Vector3>(pAngle, smoothed);
						if (currentAngle.Distance(angle) * (180.f / M_PI) <= 15.f / viewMatrix.GetCameraVec().Distance(world))
						{
							Sendinput::SendVKcodesUp(0x4C);
							shooted = true;
						}
					}
				}
				this_thread::sleep_for(2ms);
			}
		}

		if (Config::Get().AnaSkill)
		{
			Config::Get().GravityBool = false;
			Config::Get().PreditLevel = 60.f;
			while (GetAsyncKeyState(VK_XBUTTON2))
			{
				if (!shooted)
				{
					Vector3 world = GetVector3Predit();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(AnglePTR + OFFSET_PLAYER_CONTROLLER_ROTATION);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.02f;
						Vector3 smoothed = SmoothAngle(currentAngle, angle, speed, speed);
						Config::Get().WPM<BYTE>(AnglePTR + OFFSET_PLAYER_CONTROLLER_KEY, 0x8);
						Config::Get().WPM<Vector3>(pAngle, smoothed);
						if (currentAngle.Distance(angle) * (180.f / M_PI) <= 10.f / viewMatrix.GetCameraVec().Distance(world))
						{
							shooted = true;
						}
					}
				}
				this_thread::sleep_for(2ms);
			}
		}

		if (Config::Get().ESkill)
		{
			Config::Get().GravityBool = false;
			while (GetAsyncKeyState(0x45))
			{
				if (!shooted)
				{
					Vector3 world = GetVector3Predit();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(AnglePTR + OFFSET_PLAYER_CONTROLLER_ROTATION);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.02f;
						Vector3 smoothed = SmoothAngle(currentAngle, angle, speed, speed);
						Config::Get().WPM<Vector3>(pAngle, smoothed);
						if (currentAngle.Distance(angle) * (180.f / M_PI) <= 10.f / viewMatrix.GetCameraVec().Distance(world))
						{
							shooted = true;
						}
					}
				}
				this_thread::sleep_for(2ms);
			}
		}

		if (Config::Get().Roadhog)
		{
			Config::Get().GravityBool = false;
			while (GetAsyncKeyState(VK_XBUTTON2))
			{
				if (!shooted)
				{
					Vector3 world = GetVector3Predit();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(AnglePTR + OFFSET_PLAYER_CONTROLLER_ROTATION);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.02f;
						Vector3 smoothed = SmoothAngle(currentAngle, angle, speed, speed);
						Config::Get().WPM<BYTE>(AnglePTR + OFFSET_PLAYER_CONTROLLER_KEY, 0x8);
						Config::Get().WPM<Vector3>(pAngle, smoothed);
						if (currentAngle.Distance(angle) * (180.f / M_PI) <= 10.f / viewMatrix.GetCameraVec().Distance(world))
						{
							shooted = true;
						}
					}
				}
				this_thread::sleep_for(2ms);
			}
		}

		if (Config::Get().SAimbot)
		{
			Config::Get().GravityBool = false;
			//Config::PreditLevel = 50.f;
			while (Config::Get().RPM<BYTE>(AnglePTR + OFFSET_GenjiQ) == 0xB6)
			{
				Vector3 world = GetVector3123123();
				Vector3 currentAngle = Config::Get().RPM<Vector3>(pAngle);
				Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));

				if (Entitys[TarGetIndex2].Alive && viewMatrix.GetCameraVec().Distance(world) < 15.f && GetAsyncKeyState(VK_LBUTTON))
				{
					Vector3 smoothed = SmoothAngle(currentAngle, angle, Config::Get().AimSpeed, Config::Get().AimSpeed);
					Config::Get().WPM<Vector3>(pAngle, smoothed);

					if (currentAngle.Distance(angle) * (180.f / M_PI) <= 30.f / viewMatrix.GetCameraVec().Distance(world))
					{
						if (viewMatrix.GetCameraVec().Distance(world) > 5.f)
							Config::Get().WPM<BYTE>(AnglePTR + OFFSET_PLAYER_CONTROLLER_KEY, 0x8);
						else
							Config::Get().WPM<BYTE>(AnglePTR + OFFSET_PLAYER_CONTROLLER_KEY, 1);
					}

				}
				this_thread::sleep_for(2ms);
			}
		}

		if (Config::Get().TAimbot)
		{
			Config::Get().GravityBool = false;
			while (GetAsyncKeyState(VK_LBUTTON))
			{
				if (!shooted)
				{
					Vector3 world = GetVector3();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(pAngle);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.01f;
						Vector3 smooted = SmoothAngle(currentAngle, angle, Config::Get().AimSpeed, Config::Get().AimSpeed);
						Config::Get().WPM<Vector3>(pAngle, smooted);
						shooted = false;
					}
				}
				this_thread::sleep_for(1ms);
			}
		}

		if (Config::Get().FAimbot)
		{
			Config::Get().GravityBool = false;
			while (GetAsyncKeyState(VK_XBUTTON2))
			{
				if (!shooted)
				{
					Vector3 world = GetVector3();
					Vector3 currentAngle = Config::Get().RPM<Vector3>(pAngle);
					Vector3 angle = CalcAngle(viewMatrix.GetCameraVec(), world, viewMatrix.GetCameraVec().Distance(world));
					if (currentAngle.Distance(angle) * (180.f / M_PI) <= Config::Get().Fov / viewMatrix.GetCameraVec().Distance(world))
					{
						float speed = (Config::Get().AimSpeed / currentAngle.Distance(angle)) * 0.01f;
						Vector3 smoothed = SmoothAngle(currentAngle, angle, speed, speed);
						Config::Get().WPM<Vector3>(pAngle, smoothed);

						if (currentAngle.Distance(angle) * (180.f / M_PI) <= 15.f / viewMatrix.GetCameraVec().Distance(world))
						{
							Config::Get().WPM<BYTE>(AnglePTR + OFFSET_PLAYER_CONTROLLER_KEY, 1);
							shooted = true;
						}
					}
				}

				this_thread::sleep_for(2ms);
			}
		}
		this_thread::sleep_for(25ms);
	}
}

LONG WINAPI Exc2pt10nHand1111er(EXCEPTION_POINTERS* e)
{
	std::string EncryptEA = encrypt((UINT64)(e->ExceptionRecord->ExceptionAddress));
	auto ctx = e->ContextRecord;

	if (EncryptEA == EnFovHook)
	{
		DWORD Filter = *(DWORD*)(*(DWORD64*)(ctx->Rsp + 0x38) - 0xD); //0x28, 0x38
		if (Filter == 0x8E8B49A5) //8E8B49A5
		{
			uint64_t EnumComponentParent = *(uint64_t*)(ctx->R14 + 0x48);

			if (*(float*)(&ctx->Xmm7) == 0.01f || *(float*)(&ctx->Xmm8) == 0.01f)
			{
				EnPos = *(Vector3*)(ctx->Rsp + 0x310); // 28 - D -> 300, 38 - D 200

				uint64_t HealthBase = FnDecryptParnet(EnumComponentParent, OFFSET_UNIT_HEALTH);
				//uint64_t HasPlayerBase = FnDecryptParnet(EnumComponentParent, OFFSET_UNIT_HASPLAYERID);
				uint64_t HeroIDBase = FnDecryptParnet(EnumComponentParent, OFFSET_PLAYER_HEROIDENTITY);
				uint64_t VelocityBase = FnDecryptParnet(EnumComponentParent, OFFSET_UNIT_VELOCITY);
				uint64_t VisBase = FnDecryptParnet(EnumComponentParent, OFFSET_PLAYER_VISIBILITY);
				//uint64_t SkillBase = FnDecryptParnet(EnumComponentParent, Compo__SKILL);

				cout << hex << HealthBase << endl;
				for (int i = 0; i < EntityPTR.size(); i++)
				{
					if (abs(EnPos.x - Entitys[i].Location.x) <= 1.5f && abs(EnPos.z - Entitys[i].Location.z) <= 1.5f)
					{


						Entitys[i].VisCheck = Config::Get().RPM<BYTE>(VisBase + OFFSET_VISIBILITYPTR_ISVISIBLE);
						float p1 = Config::Get().RPM<float>(HealthBase + OFFSET_HEALTHPTR_HEALTH);
						float p2 = Config::Get().RPM<float>(HealthBase + OFFSET_HEALTHPTR_ARMOR);
						float p3 = Config::Get().RPM<float>(HealthBase + OFFSET_HEALTHPTR_BARRIER);
						Entitys[i].PlayerHealth = p1 + p2 + p3;
						Entitys[i].Velocity = Config::Get().RPM<Vector3>(VelocityBase + OFFSET_VELOCITYPTR_VELOCITY);
						Entitys[i].HeroID = Config::Get().RPM<uint64_t>(HeroIDBase + OFFSET_HEROIDPTR_HEROID);
						Entitys[i].SkinID = Config::Get().RPM<uint64_t>(HeroIDBase + OFFSET_HEROIDPTR_SKINID);
						uint64_t pBoneData = Config::Get().RPM<uint64_t>(VelocityBase + OFFSET_VELOCITYPTR_BONEDATA);
						Entitys[i].rootPos = Config::Get().RPM<Vector3>(VelocityBase + OFFSET_VELOCITYPTR_LOCATION);
						if (pBoneData)
						{
							int boneIndex = NULL;
							uint64_t bonesBase = Config::Get().RPM<uint64_t>(pBoneData + OFFSET_BONEDATA_BONEBASE);
							if (bonesBase)
							{
								auto it = std::find_if(Head_SkinIDs.begin(), Head_SkinIDs.end(), [&](pair<DWORD_PTR, int>& sk) {
									return sk.first == Entitys[i].SkinID; });
								if (it != Head_SkinIDs.end())
									boneIndex = it->second;
								else {
									auto it2 = std::find_if(Head_HeroIDs.begin(), Head_HeroIDs.end(), [&](HeroID_Bone& oh) {
										return oh.heroID == Entitys[i].HeroID; });
									if (it2 != Head_HeroIDs.end())
										boneIndex = it2->defaultHeadBoneIndex;
									else
										continue;
								}
								DirectX::XMFLOAT3 currentBone = Config::Get().RPM<DirectX::XMFLOAT3>(bonesBase + OFFSET_BONE_SIZE * boneIndex + OFFSET_BONE_LOCATION);
								DirectX::XMFLOAT3 Result{};
								DirectX::XMMATRIX rotMatrix = DirectX::XMMatrixRotationY(Rotations());
								DirectX::XMStoreFloat3(&Result, XMVector3Transform(XMLoadFloat3(&currentBone), rotMatrix));
								Entitys[i].BonePos = Vector3(Result.x, Result.y, Result.z) + Entitys[i].rootPos - Vector3(0, 0, 0);
								break;
							}
						}
					}
				}
			}
		}
		ctx->Rax ^= ctx->R9;
		ctx->Rip += 0x3;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	else if (EncryptEA == EnAngleHook)
	{
		MyAngle = *(Vector3*)(ctx->Rsp + 0x20);
		AnglePTR = ctx->Rdi;
		*(Vector3*)(&ctx->Xmm0) = *(Vector3*)(ctx->Rsp + 0x20);
		ctx->Rip += 0x5;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	else if (EncryptEA == EnWallHook)
	{
		ctx->Rcx = ctx->Rsi;
		Vector3 BorderPos = *(Vector3*)(ctx->Rcx + 0x140);
		if (Config::Get().UseGlowESP)
		{
			ctx->Rdx = 0xC0;

			/*if (currentEntity.valuesPointers.isVisible)
			{
				ctx->R8 = RGBA2ARGB(Config::Get().E2SPColor1.x * 255, Config::Get().E2SPColor1.y * 255, Config::Get().E2SPColor1.z * 255, Config::Get().E2SPColor1.w * 255);
			}
			else
			{
				ctx->R8 = RGBA2ARGB(Config::Get().E2SPColor.x * 255, Config::Get().E2SPColor.y * 255, Config::Get().E2SPColor.z * 255, Config::Get().E2SPColor.w * 255);
			}*/

		}
		ctx->Rip += 0x3;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

#pragma endregion

#pragma region initsk
void SettingBreakPoints()
{
	HANDLE hMainThread = HW1BP->G2tMa1nThre2d();
	srand(GetTickCount64());
	PVOID pHandler = AddVectoredExceptionHandler(1, Exc2pt10nHand1111er);
	CONTEXT c{};
	c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	SuspendThread(hMainThread);
	c.Dr0 = Config::Get().BaseAddress + offset::FovHook;
	c.Dr1 = Config::Get().BaseAddress + offset::AngleHook;
	c.Dr2 = Config::Get().BaseAddress + offset::BorderLine;
	c.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
	SetThreadContext(hMainThread, &c);
	ResumeThread(hMainThread);
}

void BaseSettings()
{
	Config::Get().hProcess = GetCurrentProcess();
	Config::Get().BaseAddress = (DWORD64)GetModuleHandleA(("Overwatch.exe"));
	auto wndStr = "TankWindowClass";
	Config::Get().hWindow = FindWindowA(wndStr, NULL);
}
#pragma endregion

//void esp() // 거리 esp 기능 
//{
//	ImGuiWindow* window = ImGui::GetCurrentWindow(); // 임구이 오버레이
//
//	for (int i = 0; i < NAMETagPTR.size(); i++)
//	{
//		viewMatrix = Config::Get().RPM<Matrix>(viewMatrixPtr);
//		Vector2 output{}, output2{};
//		if (Players[i].Alive && Players[i].Enemy)
//		{
//			Vector3 Vec3 = Players[i].BonePos;
//
//			if (viewMatrix.WorldToScreen(Vector3(Vec3.x, Vec3.y - 2.f, Vec3.z), 1920, 1080, output) && viewMatrix.WorldToScreen(Vector3(Vec3.x, Vec3.y - 0.f, Vec3.z), 1920, 1080, output2))
//			{
//				float Size = abs(output.y - output2.y) / 2.0f;
//				float Size2 = abs(output.y - output2.y) / 20.0f;
//				float xpos = (output.x + output2.x) / 2;
//				float ypos = output.y + Size / 5;
//
//				string dist = to_string((int)viewMatrix.GetCameraVec().Distance(Vec3)) + "M";
//
//				if (Config::Get().DrawDist)
//				{
//					ImVec2 TextSize = ImGui::CalcTextSize(dist.c_str());
//					window->DrawList->AddText(ImVec2(xpos - TextSize.x / 2.0f, output.y - TextSize.y / 2.0f), ImGui::GetColorU32(Config::Get().ESPColor3), dist.c_str()); // 거리 색변경 
//				}
//				
//				if (Config::Get().DrawHeroName)
//				{
//					ImVec2 TextSize = ImGui::CalcTextSize(Hero2Str(Players[i].Skin));
//					window->DrawList->AddText(ImVec2(xpos - TextSize.x / 2.0f, output.y - TextSize.y / 2.0f - 15), ImGui::GetColorU32(Config::Get().ESPColor2), Hero2Str(Players[i].Skin)); // 영웅
//				}
//
//			}
//
//		}
//	}
//
//}

#pragma region Dllmain
DWORD WINAPI IMGUILOGIN(LPVOID lpParam) 
{
	if (AllocConsole()) {

		freopen("CONIN$", "rb", stdin);

		freopen("CONOUT$", "wb", stdout);

		freopen("CONOUT$", "wb", stderr);
	}

	InputSys::Get().Initialize();
	D3dHook::AttachHook();
	ImGuiStyle* style = &ImGui::GetStyle();
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	io.Fonts->AddFontFromFileTTF("C:\\REACH.ttf", 13.0f, NULL, io.Fonts->GetGlyphRangesKorean());

	ImVec4* colors = ImGui::GetStyle().Colors;
	colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
	colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
	colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 0.94f);
	colors[ImGuiCol_ChildWindowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
	colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
	colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_FrameBg] = ImVec4(0.44f, 0.44f, 0.44f, 0.60f);
	colors[ImGuiCol_FrameBgHovered] = ImVec4(0.57f, 0.57f, 0.57f, 0.70f);
	colors[ImGuiCol_FrameBgActive] = ImVec4(0.76f, 0.76f, 0.76f, 0.80f);
	colors[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);
	colors[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.16f, 0.16f, 1.00f);
	colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.60f);
	colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
	colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
	colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
	colors[ImGuiCol_CheckMark] = ImVec4(0.13f, 0.75f, 0.55f, 0.80f);
	colors[ImGuiCol_SliderGrab] = ImVec4(0.13f, 0.75f, 0.75f, 0.80f);
	colors[ImGuiCol_SliderGrabActive] = ImVec4(0.13f, 0.75f, 1.00f, 0.80f);
	colors[ImGuiCol_Button] = ImVec4(0.13f, 0.75f, 0.55f, 0.40f);
	colors[ImGuiCol_ButtonHovered] = ImVec4(0.13f, 0.75f, 0.75f, 0.60f);
	colors[ImGuiCol_ButtonActive] = ImVec4(0.13f, 0.75f, 1.00f, 0.80f);
	colors[ImGuiCol_Header] = ImVec4(0.13f, 0.75f, 0.55f, 0.40f);
	colors[ImGuiCol_HeaderHovered] = ImVec4(0.13f, 0.75f, 0.75f, 0.60f);
	colors[ImGuiCol_HeaderActive] = ImVec4(0.13f, 0.75f, 1.00f, 0.80f);
	colors[ImGuiCol_Separator] = ImVec4(0.13f, 0.75f, 0.55f, 0.40f);
	colors[ImGuiCol_SeparatorHovered] = ImVec4(0.13f, 0.75f, 0.75f, 0.60f);
	colors[ImGuiCol_SeparatorActive] = ImVec4(0.13f, 0.75f, 1.00f, 0.80f);
	colors[ImGuiCol_ResizeGrip] = ImVec4(0.13f, 0.75f, 0.55f, 0.40f);
	colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.13f, 0.75f, 0.75f, 0.60f);
	colors[ImGuiCol_ResizeGripActive] = ImVec4(0.13f, 0.75f, 1.00f, 0.80f);
	colors[ImGuiCol_Tab] = ImVec4(0.13f, 0.75f, 0.55f, 0.80f);
	colors[ImGuiCol_TabHovered] = ImVec4(0.13f, 0.75f, 0.75f, 0.80f);
	colors[ImGuiCol_TabActive] = ImVec4(0.13f, 0.75f, 1.00f, 0.80f);
	colors[ImGuiCol_TabUnfocused] = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
	colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.36f, 0.36f, 0.36f, 0.54f);
	colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
	colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
	colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
	colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
	colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
	colors[ImGuiCol_DragDropTarget] = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
	colors[ImGuiCol_NavHighlight] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
	colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
	colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
	colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);


	while (!Config::Get().IsLogin)
	{

	}

	BaseSettings();
	SaveEncrypted();
	SettingBreakPoints();

	while (true)
	{
		Pointer();
		StructT();
		Taimbot();
	}

	FreeLibraryAndExitThread((HMODULE)g_Module, 0);
	return 0;
}

BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved)
{

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_Module = hInst;
		DisableThreadLibraryCalls(g_Module);
		RemovePeHeader(g_Module);
		//Aeternum::get_retaddr();
		////////////////// Thread //////////////////
		CloseHandle(CreateThread(nullptr, 0, IMGUILOGIN, (LPVOID)hInst, 0, nullptr));
		////////////////// Thread //////////////////
	}
	return TRUE;
}
#pragma endregion 