#include "AppDefs.h"
#include "RemoteSave.h"
#include "TestScene.h"


TestScene::TestScene(void)
{
}


TestScene::~TestScene(void)
{
}

bool TestScene::init()
{
	if (!Scene::init()) return false;

	const std::string uid = "test001";
	const std::string version = "0.0.1";
	const std::string key = "1a2b3c4d5e6f7g8h";
	const std::string iv = "#this_is_not_key";
	const std::string URLBase = "http://1234.com/test/yunbee/";
	std::string urlLoad = URLBase + "load_userdata.php";
	std::string urlSave = URLBase + "save_userdata.php";

	do
	{
		if (!g_RemoteSave->init(uid, version, key, iv, urlLoad, urlSave))
		{
			cocos2d::log("init failed");
			break;
		}

		g_RemoteSave->setCallBackOnLoad([](RemoteSave::ErrorCode code, const std::string &msg)
		{
			cocos2d::log("callback OnLoad");
			cocos2d::log("OnLoad code: %s, msg: %s", std::to_string(code).c_str(), msg.c_str());

			if (code == RemoteSave::EC_OK)
			{
				g_RemoteSave->setBoolForKey("Bool1", true);
				g_RemoteSave->setIntegerForKey("Int2", 3333);
				g_RemoteSave->setStringForKey("Str3", "123 456#789+0-=.我晕\"'dd\"");
				g_RemoteSave->save();
			}
		});

		g_RemoteSave->setCallBackOnSave([](RemoteSave::ErrorCode code, const std::string &msg)
		{
			cocos2d::log("callback OnSave");
			cocos2d::log("OnSave code: %s, msg: %s", std::to_string(code).c_str(), msg.c_str());

			if (code == RemoteSave::EC_OK)
			{
			}
		});

		g_RemoteSave->load();
	} while (0);


	schedule(schedule_selector(TestScene::update));

	return true;
}

void TestScene::update(float dt)
{
	cocos2d::Scene::update(dt);
}

