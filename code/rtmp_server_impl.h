#ifndef RTMP_SERVER_IMPL_H_
#define RTMP_SERVER_IMPL_H_

#include "amf.h"
#include "utils.h"
#include "rtmp.h"
#include "h264_nalu_queue.h"
#include "tiny_rtmp_server.h"
#include <vector>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>

struct RTMP_Message {
	uint8_t type;
	size_t len;
	unsigned int timestamp;
	uint32_t endpoint; //message stream id
	std::string buf;
	bool  use_exttimestamp; //extended timestamp
};

struct Client {
	int fd;
	bool playing; /* Wants to receive the stream? */
	bool ready; /* Wants to receive and seen a keyframe */
	RTMP_Message messages[64];
	std::string buf;
	std::string send_queue;
	size_t chunk_len;
	uint32_t written_seq;
	uint32_t read_seq;
};

//#define APP_NAME	"live"


class rtmp_server_cls
{
public:
	static rtmp_server_cls *create_rtmp_server(int port, const char *url_suffix);
	virtual ~rtmp_server_cls(void);
protected:
	rtmp_server_cls(int port,const char *url_suffix);

public:
	rs_errcode rs_start(void);
	rs_errcode rs_stop(void);
	rs_status get_status(void);
	rs_errcode push_frame(unsigned char *frame, int frame_len);

	////convert thread function to class function
	void loop(void);
private:
	void do_poll(void);

	Client *new_client();
	void close_client(Client *client, size_t i);

	void recv_from_client(Client *client);
	void rtmp_send(Client *client, uint8_t type, uint32_t endpoint,
			const std::string &buf, unsigned int timestamp = 0,
			int channel_num = CHAN_CONTROL,RTMP_Message *msg = NULL);
	void try_to_send(Client *client);
	size_t recv_all(int fd, void *buf, size_t len);
	size_t send_all(int fd, const void *buf, size_t len);
	void send_reply(Client *client, double txid, const AMFValue &reply = AMFValue(),
			const AMFValue &status = AMFValue());

	void do_handshake(Client *client);
	void start_playback(Client *client);

	void handle_message(Client *client, RTMP_Message *msg);
	void handle_invoke(Client *client, const RTMP_Message *msg, Decoder *dec);
	void handle_connect(Client *client, double txid, Decoder *dec);
	void handle_fcpublish(Client *client, double txid, Decoder *dec);
	void handle_createstream(Client *client, double txid, Decoder *dec);
	void handle_publish(Client *client, double txid, Decoder *dec);
	void handle_play(Client *client, double txid, Decoder *dec);
	void handle_play2(Client *client, double txid, Decoder *dec);
	void handle_pause(Client *client, double txid, Decoder *dec);
	void handle_setdataframe(Client *client, Decoder *dec);

	/////////////////////////////////////////
	int set_nonblock(int fd, bool enabled);
	bool is_safe(uint8_t b);
	void hexdump(const void *buf, size_t len);
private:
	h264_nalu_queue * m_nalu_queue; //store h264 nalu
	unsigned char m_sequence_header[1024]; // sps and pps (encapsulated as RTMP format)
	int m_sequence_header_len;
	int m_pps_len;
	unsigned char m_sei[1024];
	int m_sei_len;
	struct timeval m_start_tv; //the first frame timeval
	struct timeval m_prev_tv; //previous frame's timeval
	unsigned m_timestamp;  //
	amf_object_t m_metadata;
	Client *m_publisher;
	int m_listen_fd;
	std::vector<pollfd> m_poll_table; //file descriptors in poll
	std::vector<Client *> m_clients; // rtmp clients

	int m_port;
	char m_suffix[128];
	pthread_t m_loop_thread;
	bool m_thread_quit;
	bool m_drop;
};



#endif /* RTMP_SERVER_IMPL_H_ */
