#pragma once
#include <Windows.h>
#include "Heroes.h"
float HEROID2YPITCH(Heroes HeroID)
{
	if (HeroID == Heroes::ANA)
		return 1.2f;
	else if (HeroID == Heroes::ASHE)
		return 1.6f;
	else if (HeroID == Heroes::BARTIST)
		return 1.475f;
	else if (HeroID == Heroes::BASTION)
		return 1.2f;
	else if (HeroID == Heroes::BRIGITTE)
		return 1.575f;
	else if (HeroID == Heroes::DOOMFIST)
		return 1.6f;
	else if (HeroID == Heroes::DVA)
		return 1.2f;
	else if (HeroID == Heroes::GENJI)
		return 1.15f;
	else if (HeroID == Heroes::HANZO)
		return 1.4f;
	else if (HeroID == Heroes::JUNKRAT)
		return 1.4f;
	else if (HeroID == Heroes::LUCIO)
		return 1.2f;
	else if (HeroID == Heroes::MCCREE)
		return 1.60f;
	else if (HeroID == Heroes::MEI)
		return 1.4f;
	else if (HeroID == Heroes::MERCY)
		return 1.55f;
	else if (HeroID == Heroes::MOIRA)
		return 1.725f;
	else if (HeroID == Heroes::ORISA)
		return 1.9f;
	else if (HeroID == Heroes::PHARAH)
		return 1.55f;
	else if (HeroID == Heroes::REAPER)
		return 1.625f;
	else if (HeroID == Heroes::REINHARDT)
		return 1.92f;
	else if (HeroID == Heroes::ROADHOG)
		return 1.75f;
	else if (HeroID == Heroes::SOLDIER)
		return 1.6f;
	else if (HeroID == Heroes::SOMBRA)
		return 1.35f;
	else if (HeroID == Heroes::SYMMETRA)
		return 1.35f;
	else if (HeroID == Heroes::TORBJORN)
		return 1.05f;
	else if (HeroID == Heroes::TRACER)
		return 1.17f;
	else if (HeroID == Heroes::WIDOWMAKER)
		return 1.6f;
	else if (HeroID == Heroes::WINSTON)
		return 1.42f;
	else if (HeroID == Heroes::WRECKINGBALL)
		return 1.2f;
	else if (HeroID == Heroes::ZARYA)
		return 1.7f;
	else if (HeroID == Heroes::ZENYATTA)
		return 1.6f;
	else if (HeroID == Heroes::SIGMA)
		return 2.1f;
	else if (HeroID == Heroes::ECHO)
		return 1.5f;
	else if (HeroID == Heroes::TRAINING_BOT)
		return 2.0f;

	return 2.0f;
}