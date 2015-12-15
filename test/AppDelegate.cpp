#include "AppDefs.h"
#include "AppDelegate.h"
#include "TestScene.h"

AppDelegate::AppDelegate() {
}

AppDelegate::~AppDelegate() 
{
}

#if CC_TARGET_PLATFORM == CC_PLATFORM_WIN32
static void keyEventCallback(cocos2d::EventKeyboard::KeyCode code, cocos2d::Event *event)
{
	switch (code)
	{
		case cocos2d::EventKeyboard::KeyCode::KEY_DELETE:
			cocos2d::IMEDispatcher::sharedDispatcher()->dispatchDeleteBackward();
			break;
	}
}
#endif

//if you want a different context,just modify the value of glContextAttrs
//it will takes effect on all platforms
void AppDelegate::initGLContextAttrs()
{
    //set OpenGL context attributions,now can only set six attributions:
    //red,green,blue,alpha,depth,stencil
    GLContextAttrs glContextAttrs = {8, 8, 8, 8, 24, 8};

	cocos2d::GLView::setGLContextAttrs(glContextAttrs);
}

// If you want to use packages manager to install more packages, 
// don't modify or remove this function
static int register_all_packages()
{
    return 0; //flag for packages manager
}

bool AppDelegate::applicationDidFinishLaunching()
{
	// initialize director
    auto director = cocos2d::Director::getInstance();
    auto glview = director->getOpenGLView();
	if (!glview)
	{
#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32) || (CC_TARGET_PLATFORM == CC_PLATFORM_MAC) || (CC_TARGET_PLATFORM == CC_PLATFORM_LINUX)
		glview = cocos2d::GLViewImpl::createWithRect("Test", cocos2d::Rect(0, 0, AppDefs::DesignResolutionSize.width, AppDefs::DesignResolutionSize.height));
#else
		glview = cocos2d::GLViewImpl::create("Test");
#endif
        director->setOpenGLView(glview);
    }

    // turn on display FPS
	director->setDisplayStats(true);

    // set FPS. the default value is 1.0/60 if you don't call this
    director->setAnimationInterval(1.0f / 60);

    // Set the design resolution
	glview->setDesignResolutionSize(AppDefs::DesignResolutionSize.width, AppDefs::DesignResolutionSize.height, ResolutionPolicy::SHOW_ALL);

    register_all_packages();


#if CC_TARGET_PLATFORM == CC_PLATFORM_WIN32
	auto listener = cocos2d::EventListenerKeyboard::create();
	listener->onKeyReleased = keyEventCallback;
	director->getEventDispatcher()->addEventListenerWithFixedPriority(listener, 1);
#endif

	// create a scene. it's an autorelease object
	auto scene = TestScene::create();

    // run
    director->runWithScene(scene);

    return true;
}

// This function will be called when the app is inactive. When comes a phone call,it's be invoked too
void AppDelegate::applicationDidEnterBackground() {
    // if you use SimpleAudioEngine, it must be pause
}

// this function will be called when the app is active again
void AppDelegate::applicationWillEnterForeground() {
    // if you use SimpleAudioEngine, it must resume here
}
