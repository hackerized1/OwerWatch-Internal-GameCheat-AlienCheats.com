#pragma once
#include <Windows.h>
#include <iostream>

struct offset
{
	static uint64_t AngleHook;
	static uint64_t BorderLine;
	static uint64_t FovHook;
	static uint64_t EntityHook;
	static uint64_t CompoenetHook;
	static uint64_t Skill;
	static uint64_t Bone;
	static uint64_t ViewMatrixOffset;
	static uint64_t PlayerController;
};

uint64_t offset::AngleHook             = 0x6CE7FC;   //ok
uint64_t offset::BorderLine            = 0xB879C6;   //ok  //48 8b ec 48 83 ec ? 48 8b f9 81 fa
uint64_t offset::FovHook               = 0x6cbfbf;   //ok
uint64_t offset::EntityHook            = 0x603D51;   //ok
uint64_t offset::CompoenetHook         = 0x175f277;  //ok
uint64_t offset::Skill                 = 0x1b5b760;  //ok
uint64_t offset::ViewMatrixOffset      = 0x2FC3418;  //ok  //E8 81 ? ? ? 01 00 00 ? ? ? ? F7 7F 00 00 ? ? ? ? F7 7F 00 00
uint64_t offset::Bone                  = 0x1ad7f63;  //ok
uint64_t offset::PlayerController      = 0x3057730;  //ok  // + 0xC8 //48 8b 05 ? ? ? ? 8b cf 48 8b 1c f8

#define Compo__SKILL                     0x2F // 0x2F
#define Compo__OUTLINE                   0x53 // 0x2F

#define OFFSET_BADREADPTR_SIZEDEFAULT    0x540
#define OFFSET_BADREADPTR_SIZEBONES      0xE474
#define OFFSET_BADREADPTR_SIZEROTSTRUCT  0xB00


#define OFFSET_GenjiQ								0x24B
#define OFFSET_PLAYER_CONTROLLER_ROTATION			0x1090
#define OFFSET_PLAYER_CONTROLLER_KEY				0x1034
#define OFFSET_PLAYER_CONTROLLER_DELTA				(OFFSET_PLAYER_CONTROLLER_ROTATION + 0x4C) // 이걸 왜쓰는거임 ? 저거 현재 시점이요 현재시점 ? 그니깐 앵글 1090도 시점이고 저것도 현재시점일거에요 어차피 1090 써도 되는데 머더러 ? ㅋ

#define OFFSET_UNIT_VELOCITY						0x4
#define OFFSET_UNIT_COMPNENT_TO_WORLD				0x10
#define OFFSET_PLAYER_VISIBILITY					0x2D 
#define OFFSET_UNIT_HEALTH							0x33 
#define OFFSET_PLAYER_HEROIDENTITY					0x4B
#define OFFSET_UNIT_HASPLAYERID						0x2B
#define OFFSET_UNIT_ROTATIONBASE					0x27
#define OFFSET_UINT_LINK							0x2C

#define OFFSET_HEALTHPTR_HEALTH						0xE0 // OK
#define OFFSET_HEALTHPTR_ARMOR						0x220 // OK
#define OFFSET_HEALTHPTR_BARRIER					0x360 // OK

#define OFFSET_HEALTHPTR_TAG						0x8 // OK

#define OFFSET_UCWPIDPTR_COMPOID					0xD0 // OK
#define OFFSET_HEROIDPTR_COMPOID					0xE8// OK //0xD8
#define OFFSET_HEALTHPTR_TEAM						0x504// OK
#define OFFSET_HEROIDPTR_HEROID						0xE8 // OK
#define OFFSET_HEROIDPTR_SKINID						0xF0 // OK

#define OFFSET_VELOCITYPTR_LOCATION					0x140 // ㅇ
#define OFFSET_VELOCITYPTR_ENCRYPTED				0x80 // 이건 왜씀 ? 아그냥 누가줘서욤
#define OFFSET_VELOCITYPTR_VELOCITY					0x50  // ㅇ
#define OFFSET_VELOCITYPTR_BONEDATA					0x6C0 // ㅇ
#define OFFSET_BONEDATA_BONEBASE					0x28 //  ㅇ
#define OFFSET_BONE_SIZE							0x30 //  ㅇ
#define OFFSET_BONE_LOCATION						0x20 // ㅇ

#define OFFSET_BONEDATA_BONESCOUNT					0x48 // OK?
#define OFFSET_VISIBILITYPTR_ISVISIBLE				0x98

#define OFFSET_ROTATIONPTRPTR_ROTSTRUCT				0x1598 // // OK
#define OFFSET_ROTSTRUCT_ROT						0xA98 // OK
#define OFFSET__SKill								0xD0