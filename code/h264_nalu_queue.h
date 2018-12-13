

#ifndef H264_NALU_QUEUE_H_
#define H264_NALU_QUEUE_H_

#include <pthread.h>

#include <list>
using namespace std;

typedef enum tag_h264_frame_type
{
	FT_NOIFRAME,
	FT_IFRAME,
	FT_SEI,
	FT_SPS,
	FT_PPS,
	FT_UNKNOWN,
}h264_frame_type;


typedef struct tag_h264_nalu
{
	unsigned char *nalu_data;
	int nalu_len;
	unsigned int timestamp;
	h264_frame_type frame_type;
}h264_nalu;

typedef struct tag_h264_nalu_queue
{
	list<h264_nalu> nalu_queue;
	int max_len;
	int max_frame_rate;
	int min_frame_rate;
	pthread_mutex_t nalu_queue_mutex;
}h264_nalu_queue;



 h264_nalu_queue *h264_nalu_queue_create(int max_len=10,int max_frame_rate=30,int min_frame_rate=20);

 void h264_nalu_queue_destroy(h264_nalu_queue *queue);

 bool h264_nalu_queue_push(h264_nalu_queue *queue,h264_nalu nalu);

 h264_nalu h264_nalu_queue_pop(h264_nalu_queue *queue);



#endif /* H264_NALU_QUEUE_H_ */
