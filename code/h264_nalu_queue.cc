#include "h264_nalu_queue.h"
#include <stdio.h>

 h264_nalu_queue *h264_nalu_queue_create(int max_len,int max_frame_rate,int min_frame_rate)
 {
	 h264_nalu_queue *queue = new h264_nalu_queue;
	 pthread_mutex_init(&queue->nalu_queue_mutex,NULL);
	 queue->max_len = max_len;
	 queue->max_frame_rate = max_frame_rate;
	 queue->min_frame_rate = min_frame_rate;
	 return queue;
 }

 void h264_nalu_queue_destroy(h264_nalu_queue *queue)
 {
	 pthread_mutex_destroy(&queue->nalu_queue_mutex);
	 queue->nalu_queue.clear();
 }

 bool h264_nalu_queue_push(h264_nalu_queue *queue,h264_nalu nalu)
 {
	 if(queue->nalu_queue.size() >= (unsigned)queue->max_len)
	 {
		 return false;
	 }
	 pthread_mutex_lock(&queue->nalu_queue_mutex);
	 queue->nalu_queue.push_back(nalu);
//	 size = queue->nalu_queue.size();
	 pthread_mutex_unlock(&queue->nalu_queue_mutex);
//	 printf("nalu queue size %d \n",size);
	 return true;
 }

 h264_nalu h264_nalu_queue_pop(h264_nalu_queue *queue)
 {
	 h264_nalu nalu;
	 nalu.nalu_data = NULL;
	 pthread_mutex_lock(&queue->nalu_queue_mutex);
	 if(!queue->nalu_queue.empty())
	 {
		 nalu = queue->nalu_queue.front();
		 queue->nalu_queue.pop_front();
	 }
	 pthread_mutex_unlock(&queue->nalu_queue_mutex);

	 return nalu;
 }

