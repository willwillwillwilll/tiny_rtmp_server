#ifndef TINY_RTMP_SERVER_H_
#define TINY_RTMP_SERVER_H_


#ifdef __cplusplus
extern "C"
{
#endif

typedef enum rtmp_server_status
{
	RS_STATUS_PLAY,
	RS_STATUS_STOP,
	RS_STATUS_UNKNOWN,
}rs_status;

typedef enum rtmp_server_errcode
{
	RS_ERRCODE_SUCCESS = 0,
	RS_ERRCODE_FAIL,
	RS_ERRCODE_PARAMERR,//parameters error
	RS_ERRCODE_NOINIT, // not initialize
	RS_ERRCODE_NOMEM, // memory not enough
	RS_ERRCODE_NETSOCKERR, //socket error
	RS_ERRCODE_NETBINDERR, //socket bind error
	RS_ERRCODE_THREADERR,  //create thread error
	RS_ERRCODE_NOPLAYING, //not at status of playing
	RS_ERRCODE_WAITSPS,   // wait the first sps and pps
	RS_ERRCODE_UNKNOWN,
}rs_errcode;

/**
 * @brief create rtmp server
 * @param[in] port    the port of rtmp server
 * @param[in] url_suffix   i.e. "live" in "rtmp://192.168.9.247:1935/live"
 * @return success: pointer to rtmp server  fail: NULL
 */
void* rs_create(int port,const char *url_suffix);

/**
 * @brief destroy rtmp server
 * @param[in] hndl    pointer to rtmp server
 */
void rs_destroy(void *hndl);

/**
 * @brief start rtmp server
 * @param[in] hndl   pointer to rtmp server
 * @return  rs_errcode
 */
rs_errcode rs_start(void *hndl);

/**
 * @brief stop rtmp server
 * @param[in] hndl   pointer to rtmp server
 * @return  rs_errcode
 */
rs_errcode rs_stop(void *hndl);

/**
 *@brief get the status of rtmp server
 *@param[in] hndl    pointer to rtmp server
 *@return   rtmp_server_status
 */
rs_status rs_get_status(void *hndl);

/**
 *@brief push one h264 frame to rtmp server
 *@param[in] hndl   pointer to rtmp server
 *@param[in] frame_data    pointer to h264 frame
 *@param[in] frame_data_len  the length of h264 frame
 *@return  rs_errcode
 */
rs_errcode rs_push_frame(void *hndl,unsigned char *frame, int frame_len);

#ifdef __cplusplus
}
#endif

#endif /* TINY_RTMP_SERVER_H_ */
