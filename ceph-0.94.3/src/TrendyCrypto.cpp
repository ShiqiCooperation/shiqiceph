#include "TrendyCrypto.h"
#include <ctime>
#include<stdio.h>
#include<string.h>
#include<memory.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>

using std::srand;
using std::rand;
using namespace std;
static char base64DecodeTable[256];

TrendyCrypto::TrendyCrypto()
{
    //ctor
}

TrendyCrypto::~TrendyCrypto()
{
    //dtor
}

const char* TrendyCrypto::encodeByTime(const char* szMsg, char* szEncodeMsg)
{
    if(NULL == szMsg)
        return NULL;

    if(NULL == szEncodeMsg)
        return NULL;

    time_t rawtime;
    struct tm* tm_now;

    time(&rawtime);
    tm_now = localtime(&rawtime);

    sprintf(szEncodeMsg,"%04d%02d%02d%02d%02d%s\n", tm_now->tm_year+1900, tm_now->tm_mon+1, tm_now->tm_mday,
            tm_now->tm_hour, tm_now->tm_min ,szMsg);

    return szEncodeMsg;
}

const char* TrendyCrypto::decodeByTime(const char* szMsg, char* szDecodeMsg)
{
    if(NULL == szMsg)
        return NULL;

    if(NULL == szDecodeMsg)
        return NULL;

    sprintf(szDecodeMsg,"%s",szMsg + 12);
    return szDecodeMsg;
}

char* TrendyCrypto::strDup(char const* str)
{
if (str == NULL) return NULL;
size_t len = strlen(str) + 1;
char* copy = new char[len];

if (copy != NULL)
{
memcpy(copy, str, len);
}
return copy;
}

char* TrendyCrypto::strDupSize(char const* str)
{
if (str == NULL) return NULL;
size_t len = strlen(str) + 1;
char* copy = new char[len];
return copy;
}



static void initBase64DecodeTable()
{
  int i;
  for (i = 0; i < 256; ++i) base64DecodeTable[i] = (char)0x80;
      // default value: invalid

  for (i = 'A'; i <= 'Z'; ++i) base64DecodeTable[i] = 0 + (i - 'A');
  for (i = 'a'; i <= 'z'; ++i) base64DecodeTable[i] = 26 + (i - 'a');
  for (i = '0'; i <= '9'; ++i) base64DecodeTable[i] = 52 + (i - '0');
  base64DecodeTable[(unsigned char)'+'] = 62;
  base64DecodeTable[(unsigned char)'/'] = 63;
  base64DecodeTable[(unsigned char)'='] = 0;
}

unsigned char* TrendyCrypto::base64Decode(char* in, unsigned int& resultSize, bool trimTrailingZeros)
{
  static bool haveInitedBase64DecodeTable = false;
  if (!haveInitedBase64DecodeTable)
  {
    initBase64DecodeTable();
    haveInitedBase64DecodeTable = true;
  }

  unsigned char* out = (unsigned char*)strDupSize(in); // ensures we have enough space
  int k = 0;
  int const jMax = strlen(in) - 3;
     // in case "in" is not a multiple of 4 bytes (although it should be)
  for (int j = 0; j < jMax; j += 4)
  {
    char inTmp[4], outTmp[4];
    for (int i = 0; i < 4; ++i)
    {
      inTmp[i] = in[i+j];
      outTmp[i] = base64DecodeTable[(unsigned char)inTmp[i]];
      if ((outTmp[i]&0x80) != 0) outTmp[i] = 0; // pretend the input was 'A'
    }

    out[k++] = (outTmp[0]<<2) | (outTmp[1]>>4);
    out[k++] = (outTmp[1]<<4) | (outTmp[2]>>2);
    out[k++] = (outTmp[2]<<6) | outTmp[3];
  }

  if (trimTrailingZeros)
  {
    while (k > 0 && out[k-1] == '\0') --k;
  }
  resultSize = k;

  unsigned char* result = new unsigned char[resultSize +1];
  memset(result, 0x0, resultSize + 1);
  memmove(result, out, resultSize);
  delete[] out;

  return result;
}

static const char base64Char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* TrendyCrypto::base64Encode(char const* origSigned, unsigned origLength)
{
  unsigned char const* orig = (unsigned char const*)origSigned; // in case any input bytes have the MSB set
  if (orig == NULL) return NULL;

  unsigned const numOrig24BitValues = origLength/3;
  bool havePadding = origLength > numOrig24BitValues*3;
  bool havePadding2 = origLength == numOrig24BitValues*3 + 2;
  unsigned const numResultBytes = 4*(numOrig24BitValues + havePadding);
  char* result = new char[numResultBytes+1]; // allow for trailing '/0'

  // Map each full group of 3 input bytes into 4 output base-64 characters:
  unsigned i;
  for (i = 0; i < numOrig24BitValues; ++i)
  {
    result[4*i+0] = base64Char[(orig[3*i]>>2)&0x3F];
    result[4*i+1] = base64Char[(((orig[3*i]&0x3)<<4) | (orig[3*i+1]>>4))&0x3F];
    result[4*i+2] = base64Char[((orig[3*i+1]<<2) | (orig[3*i+2]>>6))&0x3F];
    result[4*i+3] = base64Char[orig[3*i+2]&0x3F];
  }

  // Now, take padding into account.  (Note: i == numOrig24BitValues)
  if (havePadding)
  {
    result[4*i+0] = base64Char[(orig[3*i]>>2)&0x3F];
    if (havePadding2)
    {
      result[4*i+1] = base64Char[(((orig[3*i]&0x3)<<4) | (orig[3*i+1]>>4))&0x3F];
      result[4*i+2] = base64Char[(orig[3*i+1]<<2)&0x3F];
    }
    else
    {
      result[4*i+1] = base64Char[((orig[3*i]&0x3)<<4)&0x3F];
      result[4*i+2] = '=';
    }
    result[4*i+3] = '=';
  }

  result[numResultBytes] = 0x0;
  return result;
}

char TrendyCrypto::get_rand()
{
	char aChar;
    //srand(time(0));//生成随机种子，以便每次运行程序获得的随机数 都不同

    aChar='a'+rand()%(('z'+1)-'a');//产生一个 A---Z之间的随机数 (字符）
	return aChar;
}

void TrendyCrypto::cut_endline(char* str, int len)
{
     for(int i = 0; i < len; ++i)
         if(str[i] == '\n')
         {
              str[i] = '\0';
              break;
         }
}

bool TrendyCrypto::is_number(const char* str)
{
    const char* p = NULL;
    const char* temp = str;
    while('\0' != (p = temp++)[0])
        if(p[0] < '0' || p[0] > '9')
            return false;
    return true;
}

const char* TrendyCrypto::encodeByRand(const char* szMsg,int iOsdNum,long long iCapacity, char* value2)
{
    if(NULL == szMsg)
        return NULL;

    if(NULL == value2)
        return NULL;

    if(strlen(szMsg) > 8)
        return NULL;

    srand(time(0)); //生成随机数种子
    char value[32];
//    char value2[34];
    char str2[16];
    memset(value2,0,34);
 //   int ret;
    char str[9],osd_num[9],capcity[9];
    sprintf(str, "%s", szMsg);
    sprintf(osd_num, "%d", iOsdNum);
    sprintf(capcity, "%lld", iCapacity);

	 int size_osd=strlen(osd_num);
	 int size_cap=strlen(capcity);
	 char osd_num2[8];
	 char capcity2[8];
	 memset( osd_num2, '0', 8 );
	 memcpy( osd_num2+ 8-size_osd, osd_num , size_osd );
	 memset( capcity2, '0', 8 );
	 memcpy( capcity2 + 8-size_cap, capcity , size_cap );
	 //数字转化成字母
	 for(int i=0;i<8;i++)
	 {
		osd_num2[i]=osd_num2[i]+50;
		capcity2[i]=capcity2[i]+50;
	 }
	 //把str中添加随机字符变成16位长度
	 for(int i=0,j=0;i<16;i++)
	 {
		if(1!=i%2)
		{
			str2[i]=str[j];
			j++;
		}
		else
		{
			str2[i]=get_rand();
		}
	 }
	 //printf("%s \n",str2);
	 memcpy(value,str2,16);
	 memcpy(value+16,osd_num2,8);
	 memcpy(value+24,capcity2,8);
	 //printf("%s \n",value);
	 //间隔交换
	 for(int j=0;j<16;j++)
	 {
		if(1==j%2)
		{
			value2[j]=value[j+16];
			value2[j+16]=value[j];
		}
		else
		{
			value2[j]=value[j];
			value2[j+16]=value[j+16];
		}
	 }

         value2[32]='\n';
//	 printf("%s \n",value2);
//	 printf("%02x \n",value2);
	 return value2;
}

const char* TrendyCrypto::decodeByRand(const char* szMsg, int& number_osd, long long &num_cap, char* str2)
{
    unsigned char * outbuf = NULL;
 //   unsigned int len;
 //   char Temp[128];
 //   memset(Temp, 0x00, 128);
	char str[16];
	memset(str2,0,9);
	char osd_num[8],capcity[8];
	char osd_num2[9],capcity2[9];

	memset(osd_num2,0,9);
	memset(capcity2,0,9);
//	printf("enter a string of key!\n");
	char key[32];
	char key2[32];
//	gets(Temp);
//	gets(Temp);

	memcpy(key,szMsg,32);
	 //间隔交换
	 for(int j=0;j<16;j++)
	 {
		if(1==j%2)
		{
			key2[j]=key[j+16];
			key2[j+16]=key[j];
		}
		else
		{
			key2[j]=key[j];
			key2[j+16]=key[j+16];
		}
	 }
	 memcpy(str,key2,16);
	 memcpy(osd_num,key2+16,8);
	 memcpy(capcity,key2+24,8);

	 for(int i=0;i<8;i++)
	 {
		osd_num[i]=osd_num[i]-50;
		capcity[i]=capcity[i]-50;
	 }
	 memcpy(osd_num2,osd_num,8);
	 memcpy(capcity2,capcity,8);
	 number_osd=atoi(osd_num2);
	 num_cap=atoll(capcity2);

	 for(int i=0,j=0;i<16;i++)
	 {
		if(1!=i%2)
		{
			str2[j]=str[i];
			j++;
		}
	 }
	 printf("str is %s, osd_num is %d, capcity is %lld",str2,number_osd,num_cap);
	 if(outbuf)
        delete [] outbuf;

    return str2;
}
const char* TrendyCrypto::numtoletter(int version,int osdNum,const char* szPgStamp,long long Capacity,char* letterMsg)
{
	char version_byte[32];
	char osdNum_byte[32];
	char szPgStamp_byte[32];
	char Capacity_byte[32];
	char current_time_byte[32];
	char current_time[16];
	memset(version_byte,0,32);
	memset(osdNum_byte,0,32);
	memset(szPgStamp_byte,0,32);
	memset(Capacity_byte,0,32);
	memset(current_time_byte,0,32);
	memset(current_time,0,16);
	time_t rawtime;
    struct tm* tm_now;

	sprintf(version_byte,"%d",version);
    time(&rawtime);
    tm_now = localtime(&rawtime);

    sprintf(current_time,"%04d%02d%02d%02d%02d",
                                   tm_now->tm_year+1900,
                                    tm_now->tm_mon+1,
                                    tm_now->tm_mday,
                                    tm_now->tm_hour,
                                    tm_now->tm_min);
	
    sprintf(letterMsg,"%032d",version);
	sprintf(letterMsg+32,"%032d",osdNum);
	sprintf(letterMsg+64,"%032s",szPgStamp);
	sprintf(letterMsg+96,"%032lld",Capacity);
	sprintf(letterMsg+128,"%s",current_time);

	for(int i=0;i<strlen(letterMsg);i++)
		{
			letterMsg[i]+=61;
		}
	return letterMsg;

}
const char* TrendyCrypto::insetRandLetter(const char* letterMsg,char* randmsg)
{
	/*char temp_letter[400];
	int letter_size=strlen(letterMsg);
	int letter_index=letter_size/2;
	for(int i=0;i<letter_index;i++)
	{
		if(1==i%2)
		{
			temp_letter[i]=letterMsg[i+letter_index];
			temp_letter[i+letter_index]=letterMsg[i];
		}
		else
		{
			temp_letter[i]=letterMsg[i];
			temp_letter[i+letter_index]=letterMsg[i+letter_index];
		}	 
	}*/
	
	for(int i=0,j=0;i<strlen(letterMsg)*2;i++)
	{
		if(1!=i%2)
		{
			randmsg[i]=letterMsg[j];
			j++;
		}
		else
		{
			randmsg[i]=get_rand();
		}
	}
	return randmsg;
}
const char* TrendyCrypto::TrendyEncode(int osdNum, long long Capacity, int version, const char* szPgStamp, char* szEncodeMsg)
{
    char* szEncodeByBase64 = NULL;
	char letterMsg[225];
	memset(letterMsg,0,225);
	char randmsg[400];
	memset(randmsg,0,400);
	//数字提升为字母，交换位置
	numtoletter(version,osdNum,szPgStamp,Capacity,letterMsg);
	
	//插入随机字母
	insetRandLetter(letterMsg,randmsg);
	//base64加密
	szEncodeByBase64=base64Encode(randmsg,strlen(randmsg));
    sprintf(szEncodeMsg, "%s", szEncodeByBase64);
	if(szEncodeByBase64)
        delete [] szEncodeByBase64;
	
    return szEncodeMsg;
}
const char* TrendyCrypto::removeRand(const char* original,char* compression)
{
	//char temp[400];
	int size_original=strlen(original);
	for(int i=0,j=0;i<size_original;i++)
	{
		if(1!=i%2)
		{
			compression[j]=original[i];
			j++;
		}
	}

	/*int size_temp=strlen(temp);
	int temp_index=size_temp/2;
	for(int j=0;j<temp_index;j++)
         {
                if(1==j%2)
                {
                        compression[j]=temp[j+temp_index];
                        compression[j+temp_index]=temp[j];
                }
                else
                {
                        compression[j]=temp[j];
                        compression[j+temp_index]=temp[j+temp_index];
                }
         }*/
	return compression;
}
const char* TrendyCrypto::decodeCompress(int& osdNum, long long&Capacity, int& version, char* szPgStamp, char* compression)
{
	char version_byte[33];
	char osdNum_byte[33];
	char szPgStamp_byte[33];
	char Capacity_byte[33];
	char current_time_byte[33];
	char current_time[16];
	memset(version_byte,0,33);
	memset(osdNum_byte,0,33);
	memset(szPgStamp_byte,0,33);
	memset(Capacity_byte,0,33);
	memset(current_time_byte,0,33);
	memset(current_time,0,16);

	time_t rawtime;
    struct tm* tm_now;

	sprintf(version_byte,"%d",version);
    time(&rawtime);
    tm_now = localtime(&rawtime);

    sprintf(current_time,"%04d%02d%02d%02d%02d",
                                   tm_now->tm_year+1900,
                                    tm_now->tm_mon+1,
                                    tm_now->tm_mday,
                                    tm_now->tm_hour,
                                    tm_now->tm_min);
	
	for(int i=0;i<strlen(compression);i++)
	{
		compression[i]-=61;
	}
	strncpy(version_byte,compression,32);
	strncpy(osdNum_byte,compression+32,32);
	strncpy(szPgStamp_byte,compression+64,32);
	strncpy(Capacity_byte,compression+96,32);
	strncpy(current_time_byte,compression+128,12);


	if(0!=strcmp(current_time,current_time_byte))
	{
		//std::cerr<<"time is not match "<<current_time<<","<<current_time_byte<<std::endl;
		return NULL;
	}
	osdNum=atoi(osdNum_byte);
	Capacity=atoll(Capacity_byte);
	version=atoi(version_byte);
	long long pgstamp=atoll(szPgStamp_byte);
	sprintf(szPgStamp,"%lld",pgstamp);

	return compression;
}
const char* TrendyCrypto::TrendyDecode(int& osdNum, long long&Capacity, int& version, char* szPgStamp, char* szDecodeMsg)
{
    unsigned char* szDecodeByBase64 = NULL;
    unsigned int resultSize;

	char compression[225];
	char szTemp[400];
    szDecodeByBase64 = base64Decode(szDecodeMsg,  resultSize, true);
    if(szDecodeByBase64)
    {
        sprintf(szTemp,"%s", (char*)szDecodeByBase64);
        delete [] szDecodeByBase64;
        szDecodeByBase64 = NULL;
    }
    else
        return NULL;

	//交换还原，去随机字符
	removeRand(szTemp,compression);

	//字符-a，解析字符
	decodeCompress(osdNum,Capacity,version,szPgStamp,compression);
    return szDecodeMsg;
}
