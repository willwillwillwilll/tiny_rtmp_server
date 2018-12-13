#include "tiny_rtmp_server.h"
#include "rtmp_server_impl.h"

void* rs_create(int port,const char *url_suffix)
{
	return rtmp_server_cls::create_rtmp_server(port,url_suffix);
}

void rs_destroy(void *hndl)
{
	delete (rtmp_server_cls*)hndl;
}

rs_errcode rs_start(void *hndl)
{
	rtmp_server_cls *rtmp_server = (rtmp_server_cls*)hndl;
	return rtmp_server->rs_start();
}

rs_errcode rs_stop(void *hndl)
{
	rtmp_server_cls *rtmp_server = (rtmp_server_cls*)hndl;
	return rtmp_server->rs_stop();
}

rs_status rs_get_status(void *hndl)
{
	rtmp_server_cls *rtmp_server = (rtmp_server_cls*)hndl;
	return rtmp_server->get_status();
}

rs_errcode rs_push_frame(void *hndl,unsigned char *frame, int frame_len)
{
	rtmp_server_cls *rtmp_server = (rtmp_server_cls*)hndl;
	return rtmp_server->push_frame(frame,frame_len);
}






