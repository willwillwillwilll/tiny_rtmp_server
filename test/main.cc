
#include "tiny_rtmp_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <list>
using namespace std;


typedef struct tag_h264_frame
{
	unsigned char *frame;
	int frame_len;
	int frame_type; //7:sps 8:pps 5:i frame 1:p & b frame
}h264_frame;

bool read_h264_file(const char *file_name,list<h264_frame> &frame_list)
{
	char frame_buf[1*1024*1024];
	char buf[5];
	int i = 0;
	int frame_count = -1;
	int read_bytes = 0;
	h264_frame frame_packet;

	FILE *pf = fopen(file_name,"r");
	if(pf != NULL)
	{
		while(!feof(pf))
		{
			read_bytes = fread(buf,1,sizeof(buf),pf);
			if(read_bytes < (int)sizeof(buf))
			{
				printf("to the end \n");
				break;
			}
			if( (buf[0] == 0x00) && (buf[1] == 0x00) &&
					(buf[2] == 0x00) && (buf[3] == 0x01) )
			{
//				printf("find start code \n");
				if(frame_count == -1)
				{
					//first
					printf("first start code %d \n",frame_count);
				}
				else
				{
					printf("start code %d \n",frame_count);
					frame_packet.frame_len = i;
					frame_packet.frame = (unsigned char*)malloc(frame_packet.frame_len);
					frame_packet.frame_type = buf[4]&0x1f;

					memcpy(frame_packet.frame,frame_buf,frame_packet.frame_len);
					frame_list.push_back(frame_packet);
				}
				i = 0;
				memset(frame_buf,0,sizeof(frame_buf));
				frame_count++;
				if(frame_count >= 100)// only read 100 frame
				{
					fclose(pf);
					break;
				}
			}
			fseek(pf,-4,SEEK_CUR);

			frame_buf[i++] = buf[0];

		}
	}
	else
	{
		printf("error, can't open file %s \n",file_name);
		return false;
	}

	return true;
}

int main(int argc, char** argv)
{
	list<h264_frame> frame_list;
	if(!read_h264_file("2.h264",frame_list))
	{
		return -1;
	}

//	FILE *pf = fopen("out.h264","w");
//	if(pf != NULL)
//	{
//		for(list<h264_frame>::iterator iter=frame_list.begin(); iter!=frame_list.end(); iter++)
//		{
//			if(iter->frame != NULL)
//			{
//				fwrite(iter->frame,1,iter->frame_len,pf);
//			}
//		}
//		fclose(pf);
//	}
//	return 0;

	void *rtmp_server = NULL;
	rtmp_server = rs_create(1935,"live");
	if(rtmp_server == NULL)
	{
		printf("create rtmp server fail \n");
		return -1;
	}

	if(rs_start(rtmp_server) != RS_ERRCODE_SUCCESS)
	{
		printf("start rtmp server fail \n");
		return -1;
	}
	h264_frame frame_packet;
	while(1)
	{
		if(!frame_list.empty())
		{
			frame_packet = frame_list.front();
			rs_push_frame(rtmp_server,frame_packet.frame,frame_packet.frame_len);
			frame_list.pop_front();
			frame_list.push_back(frame_packet);
			if((frame_packet.frame_type == 1) || (frame_packet.frame_type == 5))
			{
				usleep(35000);
			}
		}
	}
	
	return 0;
}

