#ifndef TRENDYCRYPTO_H
#define TRENDYCRYPTO_H


class TrendyCrypto
{
    public:
        TrendyCrypto();
        virtual ~TrendyCrypto();

        const char* TrendyEncode(int osdNum, long long Capacity, int version, const char* szPgStamp, char* szEncodeMsg);
        const char* TrendyDecode(int& osdNum, long long&Capacity, int& version, char* szPgStamp, char* szDecodeMsg);
        char get_rand();
    protected:
    private:
		const char* numtoletter(int version,int osdNum,const char* szPgStamp,long long Capacity,char* letterMsg);
		const char* insetRandLetter(const char* letterMsg,char* randmsg);
		const char* removeRand(const char* original,char* compression);
		const char* decodeCompress(int& osdNum, long long&Capacity, int& version, char* szPgStamp, char* compression);
        //时间加解密
        const char* encodeByTime(const char* szMsg, char* szEncodeMsg);
        const char* decodeByTime(const char* szMsg, char* szDecodeMsg);

        //base64加解密
        char* base64Encode(char const* origSigned, unsigned origLength);
        unsigned char* base64Decode(char* in, unsigned int& resultSize, bool trimTrailingZeros = true);

        const char* encodeByRand(const char* szMsg, int osdNum, long long Capacity, char* szEncodeMsg);
        const char* decodeByRand(const char* szMsg, int& osdNum, long long &Capacity, char* szDecodeMsg);

        char* strDup(char const* str);
        char* strDupSize(char const* str);

        void cut_endline(char* str, int len);
        bool is_number(const char* str);

};

#endif // TRENDYCRYPTO_H
