// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string>

using namespace std;

#include "common/config.h"
#include "include/ceph_features.h"

#include "mon/MonMap.h"
#include "mon/Monitor.h"
#include "mon/MonitorDBStore.h"
#include "mon/MonClient.h"
#include "mon/ConfigKeyService.h"
#include "mon/OSDMonitor.h"
#include "mon/PGMonitor.h"

#include "msg/Messenger.h"

#include "include/CompatSet.h"

#include "common/ceph_argparse.h"
#include "common/pick_address.h"
#include "common/Timer.h"
#include "common/errno.h"
#include "common/Preforker.h"

#include "global/global_init.h"
#include "global/signal_handler.h"

#include "perfglue/heap_profiler.h"

#include "include/assert.h"

#include "erasure-code/ErasureCodePlugin.h"

#define dout_subsys ceph_subsys_mon
//=== zhanglei add ===
#include "hasp_api_cpp.h"
#include "vendor_code.h"

#include "TrendyCrypto.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define LISTEN_BACKLOG 50
#define LISTEN_PORT 8081
#define BUFF_SIZE 512
const int DEFAULT_OSD_NUM = 3;
const long long  DEFAULT_CAPACITY = 1000;
pthread_mutex_t work_mutex;
int osdNum_fresh;
long long Capacity_fresh;


unsigned char data[] = 
{    
    0x74, 0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72,    
	0x69, 0x6e, 0x67, 0x20, 0x31, 0x32, 0x33, 0x34
};

const unsigned int dataLen = sizeof(data);
//The size of the part of the memory which 
//will be printed during the memory demo
const hasp_size_t numBytesToShow = 64;
//=====
Monitor *mon = NULL;

int handl;
extern int tds_warning;
extern int src_capacity,dest_capacity;
extern int src_osd_num,dest_osd_num;
int handle;

struct Mon_store
{
	MonitorDBStore *store;
	Monitor *mon;
	Messenger *_msgr;
};
void handle_mon_signal(int signum)
{
  if (mon)
    mon->handle_signal(signum);
}


int obtain_monmap(MonitorDBStore &store, bufferlist &bl)
{
  dout(10) << __func__ << dendl;
  /*
   * the monmap may be in one of three places:
   *  'monmap:<latest_version_no>' - the monmap we'd really like to have
   *  'mon_sync:latest_monmap'     - last monmap backed up for the last sync
   *  'mkfs:monmap'                - a monmap resulting from mkfs
   */

  if (store.exists("monmap", "last_committed")) {
    version_t latest_ver = store.get("monmap", "last_committed");
    if (store.exists("monmap", latest_ver)) {
      int err = store.get("monmap", latest_ver, bl);
      assert(err == 0);
      assert(bl.length() > 0);
      dout(10) << __func__ << " read last committed monmap ver "
               << latest_ver << dendl;
      return 0;
    }
  }

  if (store.exists("mon_sync", "in_sync")
      || store.exists("mon_sync", "force_sync")) {
    dout(10) << __func__ << " detected aborted sync" << dendl;
    if (store.exists("mon_sync", "latest_monmap")) {
      int err = store.get("mon_sync", "latest_monmap", bl);
      assert(err == 0);
      assert(bl.length() > 0);
      dout(10) << __func__ << " read backup monmap" << dendl;
      return 0;
    }
  }

  if (store.exists("mkfs", "monmap")) {
    dout(10) << __func__ << " found mkfs monmap" << dendl;
    int err = store.get("mkfs", "monmap", bl);
    assert(err == 0);
    assert(bl.length() > 0);
    return 0;
  }

  derr << __func__ << " unable to find a monmap" << dendl;
  return -ENOENT;
}

int check_mon_data_exists()
{
  string mon_data = g_conf->mon_data;
  struct stat buf;
  if (::stat(mon_data.c_str(), &buf)) {
    if (errno != ENOENT) {
      cerr << "stat(" << mon_data << ") " << cpp_strerror(errno) << std::endl;
    }
    return -errno;
  }
  return 0;
}

/** Check whether **mon data** is empty.
 *
 * Being empty means mkfs has not been run and there's no monitor setup
 * at **g_conf->mon_data**.
 *
 * If the directory g_conf->mon_data is not empty we will return -ENOTEMPTY.
 * Otherwise we will return 0.  Any other negative returns will represent
 * a failure to be handled by the caller.
 *
 * @return **0** on success, -ENOTEMPTY if not empty or **-errno** otherwise.
 */
int check_mon_data_empty()
{
  string mon_data = g_conf->mon_data;

  DIR *dir = ::opendir(mon_data.c_str());
  if (!dir) {
    cerr << "opendir(" << mon_data << ") " << cpp_strerror(errno) << std::endl;
    return -errno;
  }
  char buf[offsetof(struct dirent, d_name) + PATH_MAX + 1];

  int code = 0;
  struct dirent *de;
  errno = 0;
  while (!::readdir_r(dir, reinterpret_cast<struct dirent*>(buf), &de)) {
    if (!de) {
      if (errno) {
	cerr << "readdir(" << mon_data << ") " << cpp_strerror(errno) << std::endl;
	code = -errno;
      }
      break;
    }
    if (string(".") != de->d_name &&
	string("..") != de->d_name) {
      code = -ENOTEMPTY;
      break;
    }
  }

  ::closedir(dir);

  return code;
}

void usage()
{
  cerr << "usage: ceph-mon -i monid [flags]" << std::endl;
  cerr << "  --debug_mon n\n";
  cerr << "        debug monitor level (e.g. 10)\n";
  cerr << "  --mkfs\n";
  cerr << "        build fresh monitor fs\n";
  cerr << "  --force-sync\n";
  cerr << "        force a sync from another mon by wiping local data (BE CAREFUL)\n";
  cerr << "  --yes-i-really-mean-it\n";
  cerr << "        mandatory safeguard for --force-sync\n";
  cerr << "  --compact\n";
  cerr << "        compact the monitor store\n";
  cerr << "  --osdmap <filename>\n";
  cerr << "        only used when --mkfs is provided: load the osdmap from <filename>\n";
  cerr << "  --inject-monmap <filename>\n";
  cerr << "        write the <filename> monmap to the local monitor store and exit\n";
  cerr << "  --extract-monmap <filename>\n";
  cerr << "        extract the monmap from the local monitor store and exit\n";
  cerr << "  --mon-data <directory>\n";
  cerr << "        where the mon store and keyring are located\n";
  generic_server_usage();
}

int preload_erasure_code()
{
  string directory = g_conf->osd_pool_default_erasure_code_directory;
  string plugins = g_conf->osd_erasure_code_plugins;
  stringstream ss;
  int r = ErasureCodePluginRegistry::instance().preload(plugins,
							directory,
							ss);
  if (r)
    derr << ss.str() << dendl;
  else
    dout(10) << ss.str() << dendl;
  return r;
}
//zhanglei
void TrendySendMessage(const char* szIp, const char* msg, int msg_len)
{
    int ret;
    int socketfd;
    int timeout = 1000;
    struct sockaddr_in server_addr;
    socklen_t server_addr_size;
//	int count = 0;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_aton(szIp, (struct in_addr*)&server_addr.sin_addr);
    server_addr.sin_port = htons(LISTEN_PORT);

    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketfd < 0)
    {
        cerr<<"failed to get socket fd";
        return ;
    }

    setsockopt(socketfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(int));
    server_addr_size = sizeof(server_addr);
    if(connect(socketfd,(struct sockaddr*)&server_addr, server_addr_size) < 0)
    {
        cerr<<"connect error";
        return ;
    }

  //  do{
        ret = send(socketfd, msg, msg_len,0);
        if(ret < 0)
        {
            cerr<<"failed to send message";
//			sleep(1);
//			count++;
        }
    close(socketfd);
}

//zhanglei
int getLicense(unsigned char *memdata , unsigned int& fsize)
{	
    int ret = 0;
    char readusbbuf[64];
	haspStatus status;
	hasp_size_t size = 0;
	ChaspFile mainFile;

	Chasp hasp1(ChaspFeature::fromFeature(2));
	status = hasp1.login(vendorCode);
	if (!HASP_SUCCEEDED(status))
	    return -1;
	
    std::string infoTemplate ="<?xml version=\"1.0\" encoding=\"UTF-8\" ?>" \
		"<haspformat root=\"haspscope\">" \
		"<hasp>" \
		"<attribute name=\"id\" />" \
		"</hasp>" \
		"</haspformat>";

	std::string resultingScope;
	status = hasp1.getSessionInfo(infoTemplate, resultingScope);

	if (!HASP_SUCCEEDED(status))
	{
		ret = -1;
		goto end;
	}

	
	mainFile = hasp1.getFile(ChaspFile::fileReadWrite);
	status = mainFile.getFileSize(size);

	if (!HASP_SUCCEEDED(status))
	{
		ret = -1;
		goto end;
	}

	if(size)
	{
	    fsize = (size < numBytesToShow) ? size : numBytesToShow;
		status = mainFile.read(memdata, fsize);
		if (!HASP_SUCCEEDED(status))
		{
		    ret = -1;
			goto end;
		}		
	}

end:
	hasp1.logout();	
	return ret;
}

void trendy_sync(int osd_num, long long capcity) 
{
	//const char* szMsg = "qundingx";
	char szPgStamp[16] = {0};
	memset(szPgStamp ,0 ,16);
	char szEncodeMsg[512];
	memset(szEncodeMsg, 0, 512); 
	//tc.TrendyEncode(szMsg, osd_num, capcity, szEncodeMsg);

    if(NULL == mon)
    {
        std::cout<<"mon is null"<<std::endl;
		return;
    }
    TrendyCrypto tc;
	if(NULL == mon->monmap)
	{
	    std::cout<<"monmap is null"<<std::endl;
		return;
	}

	int v = mon->pgmon()->pg_map.version;
    struct tm bdt;
    time_t tm = mon->pgmon()->pg_map.stamp.sec();
    localtime_r(&tm, &bdt);
    sprintf(szPgStamp, "%04d%02d%02d%02d%02d%02d", bdt.tm_year + 1900
            , bdt.tm_mon + 1, bdt.tm_mday, bdt.tm_hour, bdt.tm_min, bdt.tm_sec);

    if(NULL == tc.TrendyEncode(osd_num, capcity, v, szPgStamp, szEncodeMsg))
        return;
	
    for (map<entity_addr_t,string>::const_iterator p = mon->monmap->addr_name.begin();
       p != mon->monmap->addr_name.end();
       ++p)
    {
	    //TODO 此处机制为，出错重复发生。因此一台服务器出错可能会对别的服务器收发有影响
	    TrendySendMessage(inet_ntoa(p->first.addr4.sin_addr), szEncodeMsg, strlen(szEncodeMsg));
    }	   

	
}
int judgment(int osdNum_temp, long long Capacity_temp,int version_temp, char* pgStamp_temp)
{
    char szPgStamp[16] = {0};
	memset(szPgStamp, 0, 16);
	
    int v = mon->pgmon()->pg_map.version;
    struct tm bdt;
    time_t tm = mon->pgmon()->pg_map.stamp.sec();
    localtime_r(&tm, &bdt);
    sprintf(szPgStamp, "%04d%02d%02d%02d%02d%02d", bdt.tm_year + 1900
            , bdt.tm_mon + 1, bdt.tm_mday, bdt.tm_hour, bdt.tm_min, bdt.tm_sec);

    if(v != version_temp)
    {
    	//std::cerr<<"version_temp no match "<<v<<","<<version_temp<<std::endl;
        return -1;
    }

    if(strcmp(szPgStamp,pgStamp_temp))
    {
    	//std::cerr<<"version_temp no match "<<szPgStamp<<","<<pgStamp_temp<<std::endl;
        return -1;
    }
	pthread_mutex_lock(&work_mutex);
	osdNum_fresh=osdNum_temp;
	Capacity_fresh=Capacity_temp;
	pthread_mutex_unlock(&work_mutex);
	//std::cerr<<"judgment ok "<<osdNum_fresh<<","<<Capacity_fresh<<std::endl;
	return 0;
}

//shiqi	add
int decode_lisence(unsigned char* memdata,int len,int &number_osd,long long &num_cap)
{
    char temp_num[64] = {0};
	char* phead = NULL;
    char* pcurrent = NULL;

    phead = (char*)memdata;
	pcurrent = strchr(phead,'@');

	if(pcurrent == NULL || (pcurrent - phead + 1) >= len)
		return -1;

    memset(temp_num,'\0',64);
	strncpy(temp_num,phead,pcurrent - phead);
	number_osd = atoi(temp_num);

	phead = pcurrent + 1;
    pcurrent = strchr(phead, '$');
	if(pcurrent == NULL)
		return -1;

	memset(temp_num,'\0',64);
	strncpy(temp_num,phead,pcurrent - phead);
	num_cap = atoll(temp_num);
	
	return 0;	
}
void tdsWarningToDB(int iTdsWarning, MonitorDBStore *store)
{
	if(NULL == store)
		return;
	TrendyCrypto tc;
	bufferlist bl;
	std::string strTemp;
	char szTdsWarning[7];
	memset(szTdsWarning,0x00,7);
	char temp_tds_warning[16];
	memset(temp_tds_warning, 0x00, 16);

	snprintf(szTdsWarning,7,"%d",iTdsWarning);
	for(int i = 0; i< strlen(szTdsWarning); ++i)
		szTdsWarning[i] = szTdsWarning[i] + 61;

	snprintf(temp_tds_warning, 16, "%c%c%c%c%c%s",tc.get_rand(),tc.get_rand(),tc.get_rand(),tc.get_rand(),tc.get_rand(),szTdsWarning);
	strTemp=std::string(temp_tds_warning);
	bl.append(strTemp);
	MonitorDBStore::TransactionRef t(new MonitorDBStore::Transaction);
	t->put("lastcommitnew", "newcommited", bl);
	store->apply_transaction(t);
	bl.clear();
	strTemp.clear();
}

void* lisence_proc(void* args)
{
    Mon_store *mon_store=(Mon_store*)args;
	MonitorDBStore *store=mon_store->store;
	TrendyCrypto tc;
	bufferlist bl;
	std::string strTemp;
	int osd_number;
	long long capcity;
	int max_osd;
	long long max_capcity;
	int ret;
	unsigned char memdata[128] = {0};
	char temp_tds_warning[16];
	memset(temp_tds_warning, 0, 16);
	int lisence_waring = 0;
	while(true)
	{
		set<int32_t> osds;
		set<int>::iterator iter;
		set<unsigned int> ips;
//		bufferlist bl;
        unsigned int fsize;

		if(tds_warning>144)
			mon_store->_msgr->shutdown();
		usleep(57777777);
//		store->get("mon_config_key","TDS-SN",bl);
		//std::cerr<<"get in sleep "<<std::endl;
		if(0 == (ret = getLicense(memdata, fsize)))
		{
		    decode_lisence(memdata, fsize, max_osd, max_capcity);
			trendy_sync(max_osd, max_capcity);
		}
		else
		{
			//std::cerr<<"get in else1 "<<std::endl;
			pthread_mutex_lock(&work_mutex);
			if(osdNum_fresh<=DEFAULT_OSD_NUM)
			{
			    max_osd=DEFAULT_OSD_NUM;
			}
			else
			{
				max_osd=osdNum_fresh;
			}
			if(Capacity_fresh<=DEFAULT_CAPACITY)
			{
			    max_capcity=DEFAULT_CAPACITY;
			}
			else
			{
				max_capcity=Capacity_fresh;
			}
			pthread_mutex_unlock(&work_mutex);
			//std::cerr<<"get in else2 "<<","<<max_osd<<","<<max_capcity<<std::endl;
		}
	    //获得字符串并解析
		
		//osd_number=mon_store->mon->osdmon()->osdmap.get_num_osds();
		mon_store->mon->osdmon()->osdmap.get_all_osds(osds);
		for(iter = osds.begin() ; iter != osds.end() ; ++iter)
		{
			unsigned int temp_ip=mon_store->mon->osdmon()->osdmap.get_addr(*iter).addr4.sin_addr.s_addr;
			ips.insert(temp_ip);//获得所有的机器数
		}
		capcity=(mon_store->mon->pgmon()->pg_map.osd_sum.kb)/1024;
		if(ips.size()>max_osd||capcity>(max_capcity*1024))
		{ 
			//匹配key字符串，如果不匹配
			if( (lisence_waring++)%10 >= 9)
			{
			    src_osd_num = ips.size();
			    dest_osd_num = max_osd;
			    src_capacity = capcity;
			    dest_capacity = max_capcity;
			    tds_warning++;
				tdsWarningToDB(tds_warning, store);
				//std::cerr<<"get in warining add "<<src_osd_num<<","<<dest_osd_num<<","<<src_capacity<<","<<dest_capacity<<std::endl;
			}
			continue;
		}
		lisence_waring = 0;
		//bl.clear();
		tds_warning=0;
		//std::cerr<<"get out warining add "<<src_osd_num<<","<<dest_osd_num<<","<<src_capacity<<","<<dest_capacity<<std::endl;
		tdsWarningToDB(tds_warning, store);
		max_osd=DEFAULT_OSD_NUM;
		max_capcity=DEFAULT_CAPACITY;
	}
}
//zhanglei add


void* clear_license(void* args)
{
    while(1)
    {
	    pthread_mutex_lock(&work_mutex);
		osdNum_fresh=DEFAULT_OSD_NUM;
		Capacity_fresh=DEFAULT_CAPACITY;	
		pthread_mutex_unlock(&work_mutex);
	    usleep(299999999);
    }
}

//zhanglei add
void* TrendySocketServer(void* args)
{
	//shiqi add
    //::write(handle,"aaa\n",4);
    //shiqi add
    char g_buf[BUFF_SIZE] = {0};
	TrendyCrypto tc;
	int ret;
	int socketfd, csocketfd;
//	  int FD_id[LISTEN_BACKLOG] = {0};
	std::list<int> FD_id;
	std::list<int>::iterator  fd_iter;
    int one  = 1;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	fd_set rwfd;
	struct timeval tv;
	socklen_t client_addr_size;
	int maxsock,secondsock;

	int osdNum_temp;
	long long Capacity_temp;
	int version_temp;
	char pgStamp_temp[16];
	memset(pgStamp_temp,0,16);

	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1)
		cerr<<"socket";
	
    if(0 > setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)))
    {
        cerr<<"Listener can not set the options of the socket";
    }
	
	memset(&server_addr, 0, sizeof(struct sockaddr_in));

	server_addr.sin_family=AF_INET;
	server_addr.sin_port = htons(LISTEN_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(socketfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1)
	{
		cerr<<"bind";
		return NULL;
	}
	
	if (listen(socketfd, 51) == -1)
	{
		cerr<<"listen";
		return NULL;
	}    

	if(csocketfd == -1)
	{
		cerr<<"accept";
		return NULL;
	}
	
	client_addr_size = sizeof(struct sockaddr_in);
	maxsock = secondsock = socketfd;
	while(1)
	{
		//::write(handle,"bbb\n",4);
		FD_ZERO(&rwfd);
		FD_SET(maxsock, &rwfd);

		tv.tv_sec = 2;
		tv.tv_usec = 0;

		ret = select(maxsock + 1, &rwfd, NULL, NULL,&tv);
		//::write(handle,"ccc\n",4);
		//char test[258];
		//memset(test,0,258);
		//sprintf(test,"%s\n",g_buf);
		//::write(handle,test,258);
		switch(ret)
		{
		case -1:
			cerr<<"select error";
			break;;
		case 0:
//			std::cout<<"connect timeout,continue"<<std::endl;
			continue;
		default:
			//::write(handle,"ddd\n",4);
			fd_iter = FD_id.begin();
			for (; fd_iter != FD_id.end();)
			{
				if(FD_ISSET(*fd_iter, &rwfd))
				{
				    pthread_mutex_lock(&work_mutex);
					ret = recv(*fd_iter, g_buf, sizeof(g_buf), 0);
					pthread_mutex_unlock(&work_mutex);
					if(ret <= 0)
					{
//						std::cout<<"client close"<<std::endl;
						FD_CLR(*fd_iter, &rwfd);
						if(maxsock == *fd_iter)
							maxsock = secondsock;
						close(*fd_iter);
						fd_iter = FD_id.erase(fd_iter);
					}
					else
					{
						//std::cerr<<"get in decode "<<std::endl;
						tc.TrendyDecode(osdNum_temp,Capacity_temp, version_temp,pgStamp_temp, g_buf);
						//pthread_mutex_lock(&work_mutex);
						judgment(osdNum_temp,Capacity_temp,version_temp,pgStamp_temp);
						//std::cout<<"next judgment"<<osdNum_temp<<Capacity_temp<<version_temp<<pgStamp_temp<<std::endl;
						//pthread_mutex_unlock(&work_mutex);
						//判断
						++fd_iter;
					}
					
				 }
			     else
				 {
				 	 fd_iter++;
				 }
			}

			if(FD_ISSET(socketfd, &rwfd))
			{
				csocketfd = accept(socketfd, (struct sockaddr*)&client_addr, &client_addr_size);
				if(csocketfd < 0)
				{
					cerr<<"accept";
					continue;
				}

				if(FD_id.size() < LISTEN_BACKLOG)
				{
					FD_id.push_back(csocketfd);
					if(csocketfd > maxsock)
					{
						secondsock = maxsock;
						maxsock = csocketfd;
					}
				}
				else
				{
					cerr<<"queue is full";
					close(csocketfd);
				}
			}
			continue;
		}
	}

}

//shiqi add
int main(int argc, const char **argv) 
{
  int err;
  //shiqi add
  //if((handl=open("/root/ceph/11.log",O_WRONLY|O_CREAT|O_TRUNC,0777))==-1)
  //printf("Erroropeningfile.\n");
  //shiq addi

  bool mkfs = false;
  bool compact = false;
  bool force_sync = false;
  bool yes_really = false;
  std::string osdmapfn, inject_monmap, extract_monmap;

  vector<const char*> args;
  argv_to_vec(argc, argv, args);
  env_to_vec(args);

  // We need to specify some default values that may be overridden by the
  // user, that are specific to the monitor.  The options we are overriding
  // are also used on the OSD (or in any other component that uses leveldb),
  // so changing them directly in common/config_opts.h is not an option.
  // This is not the prettiest way of doing this, especially since it has us
  // having a different place than common/config_opts.h defining default
  // values, but it's not horribly wrong enough to prevent us from doing it :)
  //
  // NOTE: user-defined options will take precedence over ours.
  //
  //  leveldb_write_buffer_size = 32*1024*1024  = 33554432  // 32MB
  //  leveldb_cache_size        = 512*1024*1204 = 536870912 // 512MB
  //  leveldb_block_size        = 64*1024       = 65536     // 64KB
  //  leveldb_compression       = false
  //  leveldb_log               = ""
  vector<const char*> def_args;
  def_args.push_back("--leveldb-write-buffer-size=33554432");
  def_args.push_back("--leveldb-cache-size=536870912");
  def_args.push_back("--leveldb-block-size=65536");
  def_args.push_back("--leveldb-compression=false");
  def_args.push_back("--leveldb-log=");

  int flags = 0;
  {
    vector<const char*> args_copy = args;
    std::string val;
    for (std::vector<const char*>::iterator i = args_copy.begin();
	 i != args_copy.end(); ) {
      if (ceph_argparse_double_dash(args_copy, i)) {
	break;
      } else if (ceph_argparse_flag(args_copy, i, "--mkfs", (char*)NULL)) {
	flags |= CINIT_FLAG_NO_DAEMON_ACTIONS;
      } else if (ceph_argparse_witharg(args_copy, i, &val, "--inject_monmap", (char*)NULL)) {
	flags |= CINIT_FLAG_NO_DAEMON_ACTIONS;
      } else if (ceph_argparse_witharg(args_copy, i, &val, "--extract-monmap", (char*)NULL)) {
	flags |= CINIT_FLAG_NO_DAEMON_ACTIONS;
      } else {
	++i;
      }
    }
  }

  global_init(&def_args, args,
              CEPH_ENTITY_TYPE_MON, CODE_ENVIRONMENT_DAEMON, flags);
  ceph_heap_profiler_init();

  uuid_d fsid;
  std::string val;
  for (std::vector<const char*>::iterator i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_double_dash(args, i)) {
      break;
    } else if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      usage();
      exit(0);
    } else if (ceph_argparse_flag(args, i, "--mkfs", (char*)NULL)) {
      mkfs = true;
    } else if (ceph_argparse_flag(args, i, "--compact", (char*)NULL)) {
      compact = true;
    } else if (ceph_argparse_flag(args, i, "--force-sync", (char*)NULL)) {
      force_sync = true;
    } else if (ceph_argparse_flag(args, i, "--yes-i-really-mean-it", (char*)NULL)) {
      yes_really = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--osdmap", (char*)NULL)) {
      osdmapfn = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--inject_monmap", (char*)NULL)) {
      inject_monmap = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--extract-monmap", (char*)NULL)) {
      extract_monmap = val;
    } else {
      ++i;
    }
  }
  if (!args.empty()) {
    cerr << "too many arguments: " << args << std::endl;
    usage();
  }

  if (force_sync && !yes_really) {
    cerr << "are you SURE you want to force a sync?  this will erase local data and may\n"
	 << "break your mon cluster.  pass --yes-i-really-mean-it if you do." << std::endl;
    exit(1);
  }

  if (g_conf->mon_data.empty()) {
    cerr << "must specify '--mon-data=foo' data path" << std::endl;
    usage();
  }

  if (g_conf->name.get_id().empty()) {
    cerr << "must specify id (--id <id> or --name mon.<id>)" << std::endl;
    usage();
  }

  // -- mkfs --
  if (mkfs) {

    int err = check_mon_data_exists();
    if (err == -ENOENT) {
      if (::mkdir(g_conf->mon_data.c_str(), 0755)) {
	cerr << "mkdir(" << g_conf->mon_data << ") : "
	     << cpp_strerror(errno) << std::endl;
	exit(1);
      }
    } else if (err < 0) {
      cerr << "error opening '" << g_conf->mon_data << "': "
           << cpp_strerror(-err) << std::endl;
      exit(-err);
    }

    err = check_mon_data_empty();
    if (err == -ENOTEMPTY) {
      // Mon may exist.  Let the user know and exit gracefully.
      cerr << "'" << g_conf->mon_data << "' already exists and is not empty"
           << ": monitor may already exist" << std::endl;
      exit(0);
    } else if (err < 0) {
      cerr << "error checking if '" << g_conf->mon_data << "' is empty: "
           << cpp_strerror(-err) << std::endl;
      exit(-err);
    }

    // resolve public_network -> public_addr
    pick_addresses(g_ceph_context, CEPH_PICK_ADDRESS_PUBLIC);

    common_init_finish(g_ceph_context, flags);

    bufferlist monmapbl, osdmapbl;
    std::string error;
    MonMap monmap;

    // load or generate monmap
    if (g_conf->monmap.length()) {
      int err = monmapbl.read_file(g_conf->monmap.c_str(), &error);
      if (err < 0) {
	cerr << argv[0] << ": error reading " << g_conf->monmap << ": " << error << std::endl;
	exit(1);
      }
      try {
	monmap.decode(monmapbl);

	// always mark seed/mkfs monmap as epoch 0
	monmap.set_epoch(0);
      }
      catch (const buffer::error& e) {
	cerr << argv[0] << ": error decoding monmap " << g_conf->monmap << ": " << e.what() << std::endl;
	exit(1);
      }      
    } else {
      int err = monmap.build_initial(g_ceph_context, cerr);
      if (err < 0) {
	cerr << argv[0] << ": warning: no initial monitors; must use admin socket to feed hints" << std::endl;
      }

      // am i part of the initial quorum?
      if (monmap.contains(g_conf->name.get_id())) {
	// hmm, make sure the ip listed exists on the current host?
	// maybe later.
      } else if (!g_conf->public_addr.is_blank_ip()) {
	entity_addr_t a = g_conf->public_addr;
	if (a.get_port() == 0)
	  a.set_port(CEPH_MON_PORT);
	if (monmap.contains(a)) {
	  string name;
	  monmap.get_addr_name(a, name);
	  monmap.rename(name, g_conf->name.get_id());
	  cout << argv[0] << ": renaming mon." << name << " " << a
	       << " to mon." << g_conf->name.get_id() << std::endl;
	}
      } else {
	// is a local address listed without a name?  if so, name myself.
	list<entity_addr_t> ls;
	monmap.list_addrs(ls);
	entity_addr_t local;

	if (have_local_addr(g_ceph_context, ls, &local)) {
	  string name;
	  monmap.get_addr_name(local, name);

	  if (name.find("noname-") == 0) {
	    cout << argv[0] << ": mon." << name << " " << local
		 << " is local, renaming to mon." << g_conf->name.get_id() << std::endl;
	    monmap.rename(name, g_conf->name.get_id());
	  } else {
	    cout << argv[0] << ": mon." << name << " " << local
		 << " is local, but not 'noname-' + something; not assuming it's me" << std::endl;
	  }
	}
      }
    }

    if (!g_conf->fsid.is_zero()) {
      monmap.fsid = g_conf->fsid;
      cout << argv[0] << ": set fsid to " << g_conf->fsid << std::endl;
    }
    
    if (monmap.fsid.is_zero()) {
      cerr << argv[0] << ": generated monmap has no fsid; use '--fsid <uuid>'" << std::endl;
      exit(10);
    }

    //monmap.print(cout);

    // osdmap
    if (osdmapfn.length()) {
      err = osdmapbl.read_file(osdmapfn.c_str(), &error);
      if (err < 0) {
	cerr << argv[0] << ": error reading " << osdmapfn << ": "
	     << error << std::endl;
	exit(1);
      }
    }

    // go
    MonitorDBStore store(g_conf->mon_data);
    int r = store.create_and_open(cerr);
    if (r < 0) {
      cerr << argv[0] << ": error opening mon data directory at '"
           << g_conf->mon_data << "': " << cpp_strerror(r) << std::endl;
      exit(1);
    }
    assert(r == 0);

    Monitor mon(g_ceph_context, g_conf->name.get_id(), &store, 0, &monmap);
    r = mon.mkfs(osdmapbl);
    if (r < 0) {
      cerr << argv[0] << ": error creating monfs: " << cpp_strerror(r) << std::endl;
      exit(1);
    }
    store.close();
    cout << argv[0] << ": created monfs at " << g_conf->mon_data 
	 << " for " << g_conf->name << std::endl;
    return 0;
  }

  err = check_mon_data_exists();
  if (err < 0 && err == -ENOENT) {
    cerr << "monitor data directory at '" << g_conf->mon_data << "'"
         << " does not exist: have you run 'mkfs'?" << std::endl;
    exit(1);
  } else if (err < 0) {
    cerr << "error accessing monitor data directory at '"
         << g_conf->mon_data << "': " << cpp_strerror(-err) << std::endl;
    exit(1);
  }

  err = check_mon_data_empty();
  if (err == 0) {
    derr << "monitor data directory at '" << g_conf->mon_data
      << "' is empty: have you run 'mkfs'?" << dendl;
    exit(1);
  } else if (err < 0 && err != -ENOTEMPTY) {
    // we don't want an empty data dir by now
    cerr << "error accessing '" << g_conf->mon_data << "': "
         << cpp_strerror(-err) << std::endl;
    exit(1);
  }

  {
    // check fs stats. don't start if it's critically close to full.
    ceph_data_stats_t stats;
    int err = get_fs_stats(stats, g_conf->mon_data.c_str());
    if (err < 0) {
      cerr << "error checking monitor data's fs stats: " << cpp_strerror(err)
           << std::endl;
      exit(-err);
    }
    if (stats.avail_percent <= g_conf->mon_data_avail_crit) {
      cerr << "error: monitor data filesystem reached concerning levels of"
           << " available storage space (available: "
           << stats.avail_percent << "% " << prettybyte_t(stats.byte_avail)
           << ")\nyou may adjust 'mon data avail crit' to a lower value"
           << " to make this go away (default: " << g_conf->mon_data_avail_crit
           << "%)\n" << std::endl;
      exit(ENOSPC);
    }
  }

  // we fork early to prevent leveldb's environment static state from
  // screwing us over
  Preforker prefork;
  if (!(flags & CINIT_FLAG_NO_DAEMON_ACTIONS)) {
    if (global_init_prefork(g_ceph_context, 0) >= 0) {
      prefork.prefork();
      if (prefork.is_parent()) {
	return prefork.parent_wait();
      }
      global_init_postfork_start(g_ceph_context);
    }
    common_init_finish(g_ceph_context);
    global_init_chdir(g_ceph_context);
    if (preload_erasure_code() < 0)
      prefork.exit(1);
  }

  MonitorDBStore *store = new MonitorDBStore(g_conf->mon_data);
  err = store->open(std::cerr);
  if (err < 0) {
    derr << "error opening mon data directory at '"
         << g_conf->mon_data << "': " << cpp_strerror(err) << dendl;
    prefork.exit(1);
  }

  bufferlist magicbl;
  err = store->get(Monitor::MONITOR_NAME, "magic", magicbl);
  if (!magicbl.length()) {
    derr << "unable to read magic from mon data" << dendl;
    prefork.exit(1);
  }
  string magic(magicbl.c_str(), magicbl.length()-1);  // ignore trailing \n
  if (strcmp(magic.c_str(), CEPH_MON_ONDISK_MAGIC)) {
    derr << "mon fs magic '" << magic << "' != current '" << CEPH_MON_ONDISK_MAGIC << "'" << dendl;
    prefork.exit(1);
  }

  err = Monitor::check_features(store);
  if (err < 0) {
    derr << "error checking features: " << cpp_strerror(err) << dendl;
    prefork.exit(1);
  }

  // inject new monmap?
  if (!inject_monmap.empty()) {
    bufferlist bl;
    std::string error;
    int r = bl.read_file(inject_monmap.c_str(), &error);
    if (r) {
      derr << "unable to read monmap from " << inject_monmap << ": "
	   << error << dendl;
      prefork.exit(1);
    }

    // get next version
    version_t v = store->get("monmap", "last_committed");
    dout(0) << "last committed monmap epoch is " << v << ", injected map will be " << (v+1)
            << dendl;
    v++;

    // set the version
    MonMap tmp;
    tmp.decode(bl);
    if (tmp.get_epoch() != v) {
      dout(0) << "changing monmap epoch from " << tmp.get_epoch()
           << " to " << v << dendl;
      tmp.set_epoch(v);
    }
    bufferlist mapbl;
    tmp.encode(mapbl, CEPH_FEATURES_ALL);
    bufferlist final;
    ::encode(v, final);
    ::encode(mapbl, final);

    MonitorDBStore::TransactionRef t(new MonitorDBStore::Transaction);
    // save it
    t->put("monmap", v, mapbl);
    t->put("monmap", "latest", final);
    t->put("monmap", "last_committed", v);
    store->apply_transaction(t);

    dout(0) << "done." << dendl;
    prefork.exit(0);
  }

  // monmap?
  MonMap monmap;
  {
    // note that even if we don't find a viable monmap, we should go ahead
    // and try to build it up in the next if-else block.
    bufferlist mapbl;
    int err = obtain_monmap(*store, mapbl);
    if (err >= 0) {
      try {
        monmap.decode(mapbl);
      } catch (const buffer::error& e) {
        cerr << "can't decode monmap: " << e.what() << std::endl;
      }
    } else {
      derr << "unable to obtain a monmap: " << cpp_strerror(err) << dendl;
    }
    if (!extract_monmap.empty()) {
      int r = mapbl.write_file(extract_monmap.c_str());
      if (r < 0) {
	r = -errno;
	derr << "error writing monmap to " << extract_monmap << ": " << cpp_strerror(r) << dendl;
	prefork.exit(1);
      }
      derr << "wrote monmap to " << extract_monmap << dendl;
      prefork.exit(0);
    }
  }

  // this is what i will bind to
  entity_addr_t ipaddr;

  if (monmap.contains(g_conf->name.get_id())) {
    ipaddr = monmap.get_addr(g_conf->name.get_id());

    // print helpful warning if the conf file doesn't match
    entity_addr_t conf_addr;
    std::vector <std::string> my_sections;
    g_conf->get_my_sections(my_sections);
    std::string mon_addr_str;
    if (g_conf->get_val_from_conf_file(my_sections, "mon addr",
				       mon_addr_str, true) == 0) {
      if (conf_addr.parse(mon_addr_str.c_str()) && (ipaddr != conf_addr)) {
	derr << "WARNING: 'mon addr' config option " << conf_addr
	     << " does not match monmap file" << std::endl
	     << "         continuing with monmap configuration" << dendl;
      }
    }
  } else {
    dout(0) << g_conf->name << " does not exist in monmap, will attempt to join an existing cluster" << dendl;

    pick_addresses(g_ceph_context, CEPH_PICK_ADDRESS_PUBLIC);
    if (!g_conf->public_addr.is_blank_ip()) {
      ipaddr = g_conf->public_addr;
      if (ipaddr.get_port() == 0)
	ipaddr.set_port(CEPH_MON_PORT);
      dout(0) << "using public_addr " << g_conf->public_addr << " -> "
	      << ipaddr << dendl;
    } else {
      MonMap tmpmap;
      int err = tmpmap.build_initial(g_ceph_context, cerr);
      if (err < 0) {
	derr << argv[0] << ": error generating initial monmap: "
             << cpp_strerror(err) << dendl;
	usage();
	prefork.exit(1);
      }
      if (tmpmap.contains(g_conf->name.get_id())) {
	ipaddr = tmpmap.get_addr(g_conf->name.get_id());
      } else {
	derr << "no public_addr or public_network specified, and " << g_conf->name
	     << " not present in monmap or ceph.conf" << dendl;
	prefork.exit(1);
      }
    }
  }

  // bind
  int rank = monmap.get_rank(g_conf->name.get_id());
  Messenger *msgr = Messenger::create(g_ceph_context, g_conf->ms_type,
				      entity_name_t::MON(rank),
				      "mon",
				      0);
  msgr->set_cluster_protocol(CEPH_MON_PROTOCOL);
  msgr->set_default_send_priority(CEPH_MSG_PRIO_HIGH);

  uint64_t supported =
    CEPH_FEATURE_UID |
    CEPH_FEATURE_NOSRCADDR |
    CEPH_FEATURE_MONCLOCKCHECK |
    CEPH_FEATURE_PGID64 |
    CEPH_FEATURE_MSG_AUTH;
  msgr->set_default_policy(Messenger::Policy::stateless_server(supported, 0));
  msgr->set_policy(entity_name_t::TYPE_MON,
                   Messenger::Policy::lossless_peer_reuse(
                       supported,
                       CEPH_FEATURE_UID |
                       CEPH_FEATURE_PGID64 |
                       CEPH_FEATURE_MON_SINGLE_PAXOS));
  msgr->set_policy(entity_name_t::TYPE_OSD,
                   Messenger::Policy::stateless_server(
                       supported,
                       CEPH_FEATURE_PGID64 |
                       CEPH_FEATURE_OSDENC));
  msgr->set_policy(entity_name_t::TYPE_CLIENT,
                   Messenger::Policy::stateless_server(supported, 0));
  msgr->set_policy(entity_name_t::TYPE_MDS,
                   Messenger::Policy::stateless_server(supported, 0));

  // throttle client traffic
  Throttle *client_throttler = new Throttle(g_ceph_context, "mon_client_bytes",
					    g_conf->mon_client_bytes);
  msgr->set_policy_throttlers(entity_name_t::TYPE_CLIENT,
				     client_throttler, NULL);

  // throttle daemon traffic
  // NOTE: actual usage on the leader may multiply by the number of
  // monitors if they forward large update messages from daemons.
  Throttle *daemon_throttler = new Throttle(g_ceph_context, "mon_daemon_bytes",
					    g_conf->mon_daemon_bytes);
  msgr->set_policy_throttlers(entity_name_t::TYPE_OSD, daemon_throttler,
				     NULL);
  msgr->set_policy_throttlers(entity_name_t::TYPE_MDS, daemon_throttler,
				     NULL);

  dout(0) << "starting " << g_conf->name << " rank " << rank
       << " at " << ipaddr
       << " mon_data " << g_conf->mon_data
       << " fsid " << monmap.get_fsid()
       << dendl;

  err = msgr->bind(ipaddr);
  if (err < 0) {
    derr << "unable to bind monitor to " << ipaddr << dendl;
    prefork.exit(1);
  }

  cout << "starting " << g_conf->name << " rank " << rank
       << " at " << ipaddr
       << " mon_data " << g_conf->mon_data
       << " fsid " << monmap.get_fsid()
       << std::endl;

  // start monitor
  mon = new Monitor(g_ceph_context, g_conf->name.get_id(), store,
		    msgr, &monmap);

  if (force_sync) {
    derr << "flagging a forced sync ..." << dendl;
    mon->sync_force(NULL, cerr);
  }

  err = mon->preinit();
  if (err < 0) {
    derr << "failed to initialize" << dendl;
    prefork.exit(1);
  }

  if (compact || g_conf->mon_compact_on_start) {
    derr << "compacting monitor store ..." << dendl;
    mon->store->compact();
    derr << "done compacting" << dendl;
  }

  if (g_conf->daemonize) {
    global_init_postfork_finish(g_ceph_context, 0);
    prefork.daemonize();
  }

  msgr->start();

  mon->init();

  // set up signal handlers, now that we've daemonized/forked.
  init_async_signal_handler();
  register_async_signal_handler(SIGHUP, sighup_handler);
  register_async_signal_handler_oneshot(SIGINT, handle_mon_signal);
  register_async_signal_handler_oneshot(SIGTERM, handle_mon_signal);

  if (g_conf->inject_early_sigterm)
    kill(getpid(), SIGTERM);

  //shiqi add
  pthread_mutex_init(&work_mutex,NULL);
  pthread_t id,id1,id2;
  Mon_store mon_store;
  void* tmp_args = NULL;
  mon_store.mon=mon;
  mon_store.store=store;
  mon_store._msgr=msgr;

  //if((handle=open("/root/ceph/22.log",O_WRONLY|O_CREAT|O_TRUNC,0777))==-1)
  //printf("Erroropeningfile.\n");
  const char* szTempWarning = NULL;
  bufferlist warning_bl;
  char temp_tds_warning[16];
  memset(temp_tds_warning, 0, 16);
  store->get("lastcommitnew", "newcommited", warning_bl);
  szTempWarning=warning_bl.c_str();

  if(NULL != szTempWarning)
  {
    
      sprintf(temp_tds_warning, "%s\n", szTempWarning+5);
	  for(int i = 0; i< strlen(temp_tds_warning); ++i)
	  {
	  	temp_tds_warning[i] = temp_tds_warning[i] - 61;
	  }	  
	  tds_warning = atoi(temp_tds_warning);
	  if(tds_warning>=5)
	  tds_warning -=5;
	  std::cout<<"tmp waring is "<<tds_warning<<std::endl;
  }
  else
  {
      std::cout<<"tmp waring is null"<<std::endl;
  }
  //tds_warning=0;
  pthread_create(&id,NULL,lisence_proc,&mon_store);

  pthread_create(&id1,NULL,TrendySocketServer,tmp_args);
  
  pthread_create(&id2,NULL,clear_license,tmp_args);

  //shiqi add
  
  msgr->wait();

  store->close();

  unregister_async_signal_handler(SIGHUP, sighup_handler);
  unregister_async_signal_handler(SIGINT, handle_mon_signal);
  unregister_async_signal_handler(SIGTERM, handle_mon_signal);
  shutdown_async_signal_handler();

  delete mon;
  delete store;
  delete msgr;
  delete client_throttler;
  delete daemon_throttler;
  g_ceph_context->put();

  // cd on exit, so that gmon.out (if any) goes into a separate directory for each node.
  char s[20];
  snprintf(s, sizeof(s), "gmon/%d", getpid());
  if ((mkdir(s, 0755) == 0) && (chdir(s) == 0)) {
    dout(0) << "ceph-mon: gmon.out should be in " << s << dendl;
  }

  prefork.signal_exit(0);
  return 0;
}

