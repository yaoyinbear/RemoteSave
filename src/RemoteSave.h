#ifndef __GameSave_H
#define __GameSave_H


#include <cocos2d.h>
#include <json/document.h>
#include <network/HttpClient.h>


class RemoteSave
{
public:
	enum ErrorCode
	{
		EC_OK, // 成功
		EC_RESPONSE, // 网络错误，有详细信息
		EC_PARSE_RESPONSE, // 服务器回传数据解析错误
		EC_LOAD_DATA, // 加载数据错误
		EC_SAVE_DATA, // 保存数据错误
		EC_SAVE_RESULT, // 服务器保存错误，有详细信息
	};

	static RemoteSave* getInstance();
    
	bool getBoolForKey(const char *pKey, bool defaultValue = false);
	int getIntegerForKey(const char *pKey, int defaultValue = 0);
	float getFloatForKey(const char *pKey, float defaultValue = 0.f);
	double getDoubleForKey(const char *pKey, double defaultValue = 0.);
	std::string getStringForKey(const char *pKey, const std::string &defaultValue = RemoteSave::NullString);
	cocos2d::Data getDataForKey(const char *pKey, const cocos2d::Data &defaultValue = cocos2d::Data::Null);

	void setBoolForKey(const char *pKey, bool value);
	void setIntegerForKey(const char *pKey, int value);
	void setFloatForKey(const char *pKey, float value);
	void setDoubleForKey(const char *pKey, double value);
	void setStringForKey(const char *pKey, const std::string &value);
	void setDataForKey(const char *pKey, const cocos2d::Data &value);

	// 初始化
	// uid: 用户ID，唯一标识
	// version: 当前版本号
	// key: 加密密钥，16字节
	// iv: 加密向量，16字节
	// urlLoad: 加载数据URL
	// urlSave: 保存数据URL
	bool init(const std::string &uid, const std::string &version,
			  const std::string &key, const std::string &iv, 
			  const std::string &urlLoad, const std::string &urlSave);
    void release();

	// 从服务器加载数据，异步操作
	void load();
	// 向服务器保存数据，异步操作
	void save();

	// 设置是否在使用默认值的时候，自动保存
	void setSaveOnGetDefault(bool enabled) { m_saveOnGetDefault = enabled; }
	// 设置是否在值发生改变的时候，自动保存
	void setSaveOnChangeValue(bool enabled) { m_saveOnChangeValue = enabled; }

	// 设置加载数据回调
	void setCallBackOnLoad(const std::function<void(ErrorCode, const std::string&)> &func) { m_cbOnLoad = func; }
	// 设置保存数据回调
	void setCallBackOnSave(const std::function<void(ErrorCode, const std::string&)> &func) { m_cbOnSave = func; }

	// 空字符串
	const static std::string NullString;

protected:
	RemoteSave();
	~RemoteSave() {};

	void sendRequestLoadGame();
	void onHttpRequestCompletedLoadGame(cocos2d::network::HttpClient *sender, cocos2d::network::HttpResponse *response);
	bool parseResponseLoadGame(const std::string &buffer, unsigned long long &sn, std::string &saveData);
	bool loadWithBuffer(const std::string &buffer);

	void sendRequestSaveGame();
	void onHttpRequestCompletedSaveGame(cocos2d::network::HttpClient *sender, cocos2d::network::HttpResponse *response);
	bool saveToBuffer(std::string &buffer);

	void encode(const std::string &in, std::string &out);
	void decode(const std::string &in, std::string &out);
	void formatPostData(const std::string &dataIn, std::string &dataOut);
	
	void saveOnGetDefault() { m_saveOnGetDefault ? save() : 0; }
	void saveOnChangeValue() { m_saveOnChangeValue ? save() : 0; }

	static RemoteSave *m_instance;

	bool m_inited;
	bool m_saveOnGetDefault;
	bool m_saveOnChangeValue;
	std::function<void(ErrorCode, const std::string&)> m_cbOnLoad;
	std::function<void(ErrorCode, const std::string&)> m_cbOnSave;

	std::string m_uid;
	std::string m_version;
	std::string m_key;
	std::string m_iv;
	std::string m_urlLoad;
	std::string m_urlSave;
	unsigned long long m_sn;

	rapidjson::Document m_jsonDoc;
};

inline RemoteSave* RemoteSave::getInstance()
{
	if (!m_instance)
	{
		static RemoteSave _inst;
		m_instance = &_inst;
	}
	return m_instance;
}

#define g_RemoteSave RemoteSave::getInstance()

#endif // __GameSave_H
