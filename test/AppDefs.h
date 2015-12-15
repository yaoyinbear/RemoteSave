#ifndef __AppDefs_H
#define __AppDefs_H

#include <cocos2d.h>

// UTF-8 with BOM编写的cpp，到执行时会自动解析为本地编码
// 用以下编译指令可以强制执行时使用UTF-8
// 不过由于VS2012的bug不支持，要升级到VS2013
#pragma execution_character_set("utf-8")

#define CCASSERT_NOTNULL(x) CCASSERT((x), #x" is null");

#define STRINGIFY(A)  #A

namespace AppDefs
{
	extern const cocos2d::Size DesignResolutionSize;
	extern const cocos2d::Vec2 DesignResolutionCenter;
}

#endif // __AppDefs_H
