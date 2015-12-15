#ifndef __TestScene_H
#define __TestScene_H


#include <cocos2d.h>
#include <network/HttpClient.h>

USING_NS_CC;

class TestScene : public Scene
{
public:
	TestScene(void);
	~TestScene(void);
	CREATE_FUNC(TestScene);

	bool init();

	virtual void update(float dt) override;
};

#endif // __TestScene_H
