////////////////////////////////////////////////////////////////////
// Copyright (C) 2011, SafeNet, Inc. All rights reserved.
//
// Sentinel(R) is a registered trademark of SafeNet, Inc. 
//
//
// $Id: hasp_api_cpp.h,v 1.16 2011-12-20 14:56:36 lukas Exp $
////////////////////////////////////////////////////////////////////
#if !defined(__HASP_API_CPP_H__)
#define __HASP_API_CPP_H__


#include <iterator>
#include <string>
#include <vector>
#include <typeinfo>

#if !defined(__HASP_API_H__)
    // DO NOT ALTER THIS PATH
    // OTHERWISE YOU BLOW UP THE CD INSTALLATION
    #include "hasp_api.h"
#endif // __HASP_API_H__


#if !defined(HASPCPP_DECL)
    #define HASPCPP_DECL
#endif // HASP_DECL

#ifdef __GNUC__
#define DEPRECATED(func) func __attribute__ ((deprecated))
#elif (_MSC_VER >= 1400)
#define DEPRECATED(func) __declspec(deprecated) func
#else
#pragma message("WARNING: DEPRECATED is not defined for this compiler")
#define DEPRECATED(func) func
#endif

////////////////////////////////////////////////////////////////////
// Foreward declarations
////////////////////////////////////////////////////////////////////

struct HASPCPP_DECL ChaspFeature;
struct HASPCPP_DECL ChaspInfo;
struct HASPCPP_DECL ChaspTime;

struct HASPCPP_DECL ChaspHandle;

class HASPCPP_DECL ChaspBase;
    class HASPCPP_DECL Chasp;
    class HASPCPP_DECL ChaspFile;
    class HASPCPP_DECL ChaspLegacy;


////////////////////////////////////////////////////////////////////
// struct ChaspFeature
////////////////////////////////////////////////////////////////////
 struct HASPCPP_DECL ChaspFeature
{
// Construction/Destruction
public:
    explicit ChaspFeature(hasp_u32_t ulFeature);
    ~ChaspFeature();

// Attributes
public:
    enum
    {
        optDefault                          = 0,
        optNotLocal                         = HASP_PROGNUM_OPT_NO_LOCAL,
        optNotRemote                        = HASP_PROGNUM_OPT_NO_REMOTE,
        optProcess                          = HASP_PROGNUM_OPT_PROCESS,
        optClassic                          = HASP_PROGNUM_OPT_CLASSIC,
        optIgnoreTS                         = HASP_PROGNUM_OPT_TS,
    };

protected:
    hasp_feature_t                          m_ulFeature;

// Operators
public:
     operator hasp_feature_t() const;

// Implementation
public:
    hasp_u32_t feature() const;
    hasp_u32_t featureId() const;
    static ChaspFeature defaultFeature();
    static ChaspFeature fromFeature(hasp_u32_t ulFeature);
    static ChaspFeature fromProgNum(hasp_u32_t ulProgNum);
    hasp_u32_t getOptions() const;
    bool hasOption(hasp_u32_t ulOption) const;
    bool isDefault() const;
    bool isProgNum() const;
    static ChaspFeature progNumDefault();
    bool setOptions(hasp_u32_t ulAdd, hasp_u32_t ulRemove);
    std::string toString() const;
};


 ////////////////////////////////////////////////////////////////////
// struct ChaspInfo
////////////////////////////////////////////////////////////////////
struct HASPCPP_DECL ChaspInfo
{
// Construction/Destruction
public:
    ChaspInfo();
    ~ChaspInfo();

// Attributes
public:
    char*                                   m_pszInfo;

// Operators
public:
    operator const char*() const;

// Implementation
public:
    void clear();
    const char* getInfo() const;
};


////////////////////////////////////////////////////////////////////
// struct ChaspTime
////////////////////////////////////////////////////////////////////
struct HASPCPP_DECL ChaspTime
{
// Constrution/Destruction
public:
    ChaspTime(hasp_time_t time = 0);
    ChaspTime(unsigned int nYear, unsigned int nMonth, unsigned int nDay,
              unsigned int nHour, unsigned int nMinute, unsigned int nSecond);
    ~ChaspTime();

// Attributes
protected:
    hasp_time_t                             m_time;

// Operators
public:
    operator hasp_time_t() const;

// Implementation
public:
    unsigned int year() const;
    unsigned int month() const;
    unsigned int day() const;
    unsigned int hour() const;
    unsigned int minute() const;
    unsigned int second() const;
    hasp_time_t time() const;
};


////////////////////////////////////////////////////////////////////
// struct ChaspVersion
////////////////////////////////////////////////////////////////////
struct HASPCPP_DECL ChaspVersion
{
// Constrution/Destruction
public:
    ChaspVersion();
    ChaspVersion(const ChaspVersion& version);
    ChaspVersion(unsigned int nMajorVersion, unsigned int nMinorVersion,
                 unsigned int nServerBuild, unsigned int nBuildNumber);
    ~ChaspVersion();

// Attributes
protected:
    unsigned int m_nMajorVersion;
    unsigned int m_nMinorVersion;
    unsigned int m_nServerBuild;
    unsigned int m_nBuildNumber;

// Operators
public:
    ChaspVersion& operator=(const ChaspVersion& version);
    bool operator==(const ChaspVersion& version) const;
    bool operator!=(const ChaspVersion& version) const;

// Implementation
public:
    unsigned int majorVersion() const;
    unsigned int minorVersion() const;
    unsigned int serverBuild() const;
    unsigned int buildNumber() const;
};


////////////////////////////////////////////////////////////////////
// struct ChaspHandle
////////////////////////////////////////////////////////////////////
struct HASPCPP_DECL ChaspHandle
{
// Construction/Destruction
public:
    ChaspHandle();
    ~ChaspHandle();

// Attributes
public:
    hasp_u32_t                              m_ulIndex;
    hasp_u32_t                              m_ulCount;
    hasp_u32_t                              m_ulAltered;

// Operators
public:
    bool operator==(const ChaspHandle& other) const;
    bool operator!=(const ChaspHandle& other) const;

// Implementation
public:
    void clear();
    bool isNull() const;
};


////////////////////////////////////////////////////////////////////
// class ChaspBase
////////////////////////////////////////////////////////////////////
class HASPCPP_DECL ChaspBase
{
// Construction/Destruction
protected:
    ChaspBase();
    explicit ChaspBase(const ChaspBase& other);
    explicit ChaspBase(hasp_feature_t feature);
    virtual ~ChaspBase();

// Attributes
protected:
    ChaspHandle                             m_handle;

// Operators
public:
    ChaspBase& operator=(const ChaspBase& other);
    virtual bool operator==(const ChaspBase& other) const;
    bool operator!=(const ChaspBase& other) const;

// Overrides
public:
    virtual hasp_u32_t hashCode() const;
    virtual bool isValid() const;
    virtual std::string toString() const = 0;

protected:
    virtual bool addRef(const ChaspBase& other);
    virtual bool construct(hasp_feature_t feature);
    virtual bool release();
    virtual void synchronize() const;

// Implementation
public:
    bool dispose();
    bool isKindOf(const std::type_info& info) const;
    bool isLoggedIn() const;

protected:
    ChaspHandle handle() const;
};


////////////////////////////////////////////////////////////////////
// Sentinel HASP status codes
////////////////////////////////////////////////////////////////////
typedef hasp_status_t haspStatus;


////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////
template<typename _Type>
__inline bool HASP_SUCCEEDED(_Type status)
    { return HASP_STATUS_OK == static_cast<haspStatus>(status); }


////////////////////////////////////////////////////////////////////
// class Chasp
////////////////////////////////////////////////////////////////////
class HASPCPP_DECL Chasp : public ChaspBase
{
// Construction/Destruction
public:
    Chasp();
    Chasp(const Chasp& other);
    explicit Chasp(const ChaspBase& other);
    explicit Chasp(const ChaspFeature& feature);

// Operators
public:
    Chasp& operator=(const ChaspBase& other);
    Chasp& operator=(const Chasp& other);

// Overrides
public:
    virtual std::string toString() const;

protected:
    virtual void synchronize() const;

// Implementation
public:
    haspStatus decrypt(unsigned char* pData, hasp_size_t ulSize) const;
    haspStatus decrypt(const char* szData) const;
    haspStatus decrypt(std::string& data) const;
    haspStatus encrypt(unsigned char* pData, hasp_size_t ulSize) const;
    haspStatus encrypt(const char* szData) const;
    haspStatus encrypt(std::string& data) const;
    ChaspFeature feature() const;
    ChaspFile getFile() const;
    ChaspFile getFile(hasp_fileid_t fileId) const;
    static haspStatus getInfo(const char* pszQuery, const char* pszFormat, hasp_vendor_code_t vendorCode, std::string& info);
    static haspStatus getInfo(const char* pszQuery, const std::string& format, hasp_vendor_code_t vendorCode, std::string& info);
    static haspStatus getInfo(const std::string& query, const char* pszFormat, hasp_vendor_code_t vendorCode, std::string& info);
    static haspStatus getInfo(const std::string& query, const std::string& format, hasp_vendor_code_t vendorCode, std::string& info);

    // Starting from Sentinel LDK version 6.0, the “hasp_detach” API has been deprecated.
    //SafeNet recommends that user should use the “hasp_transfer” API to perform 
    //the detach/cancel actions.This API has been retained for backward compatibility.
    DEPRECATED(static haspStatus detach(const std::string& action, const std::string& scope, hasp_vendor_code_t vendorCode, 
                             const std::string& recipient, std::string& v2c));
    DEPRECATED(static haspStatus detach(const char* pszAction, const char* pszScope, hasp_vendor_code_t vendorCode, 
                             const char* pszRecipient, std::string& v2c));

    static haspStatus transfer(const std::string& action, const std::string& scope, hasp_vendor_code_t vendorCode, 
                             const std::string& recipient, std::string& v2c);
    static haspStatus transfer(const char* pszAction, const char* pszScope, hasp_vendor_code_t vendorCode, 
                             const char* pszRecipient, std::string& v2c);
    ChaspLegacy getLegacy() const;
    haspStatus getRtc(ChaspTime& time) const;
    haspStatus getSessionInfo(const char* pszFormat, ChaspInfo& info) const;
    haspStatus getSessionInfo(const std::string& format, std::string& info) const;
    static haspStatus getVersion(hasp_vendor_code_t vendorCode, ChaspVersion& version);
    bool hasLegacy() const;
    haspStatus login(hasp_vendor_code_t vendorCode, const char* pszScope = 0);
    haspStatus login(hasp_vendor_code_t vendorCode, const std::string& scope );
    haspStatus logout();
    static std::string keyInfo();
    static std::string sessionInfo();
    static haspStatus update(const char* pszUpdate, ChaspInfo& acknowledge);
    static haspStatus update(const char* pszUpdate, std::string& acknowledge);
    static haspStatus update(const std::string& update, std::string& acknowledge);
    static std::string updateInfo();
    static std::string recipientInfo();
};


////////////////////////////////////////////////////////////////////
// class ChaspLegacy
////////////////////////////////////////////////////////////////////
class HASPCPP_DECL ChaspLegacy : public ChaspBase
{
// Construction/Destruction
public:
    ChaspLegacy();
    explicit ChaspLegacy(const Chasp& other);
    ChaspLegacy(const ChaspLegacy& other);

// Operators
public:
    ChaspLegacy& operator=(const Chasp& other);
    ChaspLegacy& operator=(const ChaspLegacy& other);

// Overrides
public:
    virtual std::string toString() const;

// Implementation
public:
    haspStatus decrypt(unsigned char* pData, hasp_size_t ulSize) const;
    haspStatus decrypt(const char* szData) const;
    haspStatus decrypt(std::string& data) const;
    haspStatus encrypt(unsigned char* pData, hasp_size_t ulSize) const;
    haspStatus encrypt(const char* szData) const;
    haspStatus encrypt(std::string& data) const;
    haspStatus setIdleTime(hasp_u16_t nIdleTime) const;
    haspStatus setRtc(const ChaspTime& time) const;
};


////////////////////////////////////////////////////////////////////
// Chasp and CHaspLegacy template helper functions.
// Provided for your convenience.
////////////////////////////////////////////////////////////////////
#if !defined(HASPCPP_NO_TEMPLATES)

////////////////////////////////////////////////////////////////////
//! Decrypts the provided data
////////////////////////////////////////////////////////////////////
template<typename _Class, typename _Type>
__inline haspStatus HaspDecrypt(const _Class& hasp, _Type* pData)
{
    return (NULL == pData) ?
                HASP_INVALID_PARAMETER :
                hasp.decrypt(reinterpret_cast<unsigned char*>(pData),
                             sizeof(_Type));

}

////////////////////////////////////////////////////////////////////
//! Decrypts the data provided through a std::vector collection
////////////////////////////////////////////////////////////////////
template<typename _Class, typename _Type>
__inline haspStatus HaspDecrypt(const _Class& hasp,
                                std::vector<_Type>& vector)
{
    return vector.empty() ?
                HASP_STATUS_OK :
                hasp.decrypt(reinterpret_cast<unsigned char*>(&vector[0]),
                             static_cast<hasp_size_t>(vector.size() * sizeof(_Type)));
}

////////////////////////////////////////////////////////////////////
//! Encrypts the provided data
////////////////////////////////////////////////////////////////////
template<typename _Class, typename _Type>
__inline haspStatus HaspEncrypt(const _Class& hasp, _Type* pData)
{
    return (NULL == pData) ?
                HASP_INVALID_PARAMETER :
                hasp.encrypt(reinterpret_cast<unsigned char*>(pData),
                             sizeof(_Type));
}

////////////////////////////////////////////////////////////////////
//! Encrypts the data provided through a std::vector collection
////////////////////////////////////////////////////////////////////
template<typename _Class, typename _Type>
__inline haspStatus HaspEncrypt(const _Class& hasp,
                                std::vector<_Type>& vector)
{
    return vector.empty() ?
                HASP_STATUS_OK :
                hasp.encrypt(reinterpret_cast<unsigned char*>(&vector[0]),
                             static_cast<hasp_size_t>(vector.size() * sizeof(_Type)));
}

#endif //! HASPCPP_NO_TEMPLATES


////////////////////////////////////////////////////////////////////
// class ChaspFile
////////////////////////////////////////////////////////////////////
class HASPCPP_DECL ChaspFile : public ChaspBase
{
// Construction/Destruction
public:
    ChaspFile();
    ChaspFile(const ChaspFile& other);
    ChaspFile(hasp_fileid_t fileId, const Chasp& other);
    virtual ~ChaspFile();

// Attributes
public:
    enum
    {
        fileMain                            = HASP_FILEID_MAIN,
        fileLicense                         = HASP_FILEID_LICENSE,
        fileReadWrite                       = HASP_FILEID_RW,
        fileReadOnly                        = HASP_FILEID_RO
    };

protected:
    hasp_fileid_t                           m_fileId;
    hasp_size_t                             m_ulFilePos;

// Operators
public:
    ChaspFile& operator=(const ChaspFile& other);

// Overrides
public:
    virtual hasp_u32_t hashCode() const;
    virtual std::string toString() const;

protected:
    virtual bool release();

// Implementation
public:
    static bool canWriteString(const char* szString);
    static bool canWriteString(const std::string& string);
    hasp_fileid_t getFileId() const;
    hasp_size_t getFilePos() const;
    static hasp_size_t getFilePosFromString(const char* szString);
    static hasp_size_t getFilePosFromString(const std::string& string);
    haspStatus getFileSize(hasp_size_t& ulSize) const;
    static unsigned char maxStringLength();
    haspStatus read(unsigned char* pData, hasp_size_t ulSize) const;
    haspStatus read(std::string& string) const;
    bool setFilePos(hasp_size_t ulPos);
    haspStatus write(const unsigned char* pData, hasp_size_t ulCount) const;
    haspStatus write(const char* szData) const;
    haspStatus write(const std::string& string) const;

protected:
    void init(hasp_fileid_t fileId = 0);
};


////////////////////////////////////////////////////////////////////
// class ChaspFile template helper functions.
// Provided for your convenience.
////////////////////////////////////////////////////////////////////
#if !defined(HASPCPP_NO_TEMPLATES)

////////////////////////////////////////////////////////////////////
//! Reads data from the current position.
////////////////////////////////////////////////////////////////////
template<typename _Type>
__inline haspStatus HaspRead(const ChaspFile& file, _Type& data)
{
    return file.read(reinterpret_cast<unsigned char*>(&data),
                     sizeof(_Type));
}

////////////////////////////////////////////////////////////////////
//! Reads data from the current position and appends it to the
//! vector referenced by \c it.
//!
//! \param it                   The output iterator of the vector.
//! \param ulCount              The number of element to be read.
//!
//! \return                     A \a haspStatus status code.
////////////////////////////////////////////////////////////////////
template<typename _Container>
__inline haspStatus HaspRead(const ChaspFile& file,
                             std::back_insert_iterator<_Container> iter,
                             hasp_size_t ulCount)
{
    if (0 == ulCount)
        return HASP_STATUS_OK;

    std::vector<typename _Container::value_type> vector(ulCount, 0);

    haspStatus status =
        file.read(reinterpret_cast<unsigned char*>(&vector[0]),
                  static_cast<hasp_size_t>(vector.size() * sizeof(typename _Container::value_type)));

    // if succeeded append values to
    // the end of the vector.
    if (HASP_SUCCEEDED(status))
        std::copy(vector.begin(), vector.end(), iter);

    return status;
}


////////////////////////////////////////////////////////////////////
//! Writes the data into the key.
////////////////////////////////////////////////////////////////////
template<typename _Type>
__inline haspStatus HaspWrite(const ChaspFile& file, const _Type& data)
{
    return file.write(reinterpret_cast<const unsigned char*>(&data),
                      sizeof(_Type));
}

////////////////////////////////////////////////////////////////////
//! Writes the data into the key.
//!
//! \return                     A \a haspStatus status code.
////////////////////////////////////////////////////////////////////
template<typename _Type, typename _Iter>
__inline haspStatus HaspWrite(const ChaspFile& file,
                              _Iter first,
                              _Iter last)
{
    std::vector<_Type> vector;
    std::copy(first, last, std::back_inserter(vector));

    return file.write(reinterpret_cast<const unsigned char*>(&vector[0]),
                      static_cast<hasp_size_t>(vector.size() * sizeof(_Type)));
}

#endif // !HASP_NO_TEMPLATES

#endif // !__HASP_API_CPP_H__
