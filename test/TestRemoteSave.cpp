// TestRemoteSave.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <tchar.h>
#include <cocos2d.h>
#include "AppDefs.h"
#include "AppDelegate.h"

USING_NS_CC;

// int APIENTRY _tWinMain(HINSTANCE hInstance,
// 					   HINSTANCE hPrevInstance,
// 					   LPTSTR    lpCmdLine,
// 					   int       nCmdShow)
// {
// 	UNREFERENCED_PARAMETER(hPrevInstance);
// 	UNREFERENCED_PARAMETER(lpCmdLine);
// 
// 	// create the application instance
// 	AppDelegate app;
// 	return Application::getInstance()->run();
// }



int _tmain(int argc, _TCHAR* argv[])
{
	AppDelegate app;
	return Application::getInstance()->run();
}

