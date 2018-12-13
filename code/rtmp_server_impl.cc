#include "rtmp_server_impl.h"
#include <string.h>


void *loop_thread_func(void *p)
{
	rtmp_server_cls *rtmp_server = (rtmp_server_cls*)p;
	rtmp_server->loop();
	return NULL;
}

rtmp_server_cls *rtmp_server_cls::create_rtmp_server(int port,const char *url_suffix)
{
	return new rtmp_server_cls(port,url_suffix);
}

rtmp_server_cls::rtmp_server_cls(int port,const char *url_suffix)
{
	m_nalu_queue = NULL;
	m_sequence_header_len = 0;
	m_pps_len = 0;
	m_start_tv.tv_sec = 0;
	m_start_tv.tv_usec = 0;
	m_prev_tv.tv_sec = 0;
	m_prev_tv.tv_usec = 0;
	m_timestamp = 0;
	m_publisher = NULL;
	m_listen_fd = -1;
	m_port = port;
	strcpy(m_suffix,url_suffix);
	m_loop_thread = -1;
	m_thread_quit = false;
	m_sei_len = 0;
	m_drop = false;
}

rs_errcode rtmp_server_cls::rs_start(void)
{

	m_nalu_queue = h264_nalu_queue_create();
	if(m_nalu_queue == NULL)
	{
		return RS_ERRCODE_NOMEM;
	}

	m_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (m_listen_fd < 0)
	{
		h264_nalu_queue_destroy(m_nalu_queue);
		m_nalu_queue = NULL;
		return RS_ERRCODE_NETSOCKERR;
	}

	int opt = 1;
	setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(m_port);
	sin.sin_addr.s_addr = INADDR_ANY;
	if (bind(m_listen_fd, (sockaddr *) &sin, sizeof(sin)) < 0)
	{
		h264_nalu_queue_destroy(m_nalu_queue);
		m_nalu_queue = NULL;
		close(m_listen_fd);
		m_listen_fd = -1;
		return RS_ERRCODE_NETBINDERR;
	}

	listen(m_listen_fd, 10);

	pollfd entry;
	entry.events = POLLIN;
	entry.revents = 0;
	entry.fd = m_listen_fd;
	m_poll_table.push_back(entry);
	m_clients.push_back(NULL);

	if(pthread_create(&m_loop_thread,NULL, loop_thread_func,this) != 0)
	{
		h264_nalu_queue_destroy(m_nalu_queue);
		m_nalu_queue = NULL;
		close(m_listen_fd);
		m_listen_fd = -1;
		return RS_ERRCODE_THREADERR;
	}

	return RS_ERRCODE_SUCCESS;
}

rs_errcode rtmp_server_cls::rs_stop(void)
{
	m_thread_quit = true;
	pthread_join(m_loop_thread,NULL);

	close(m_listen_fd);
	m_listen_fd = -1;

	m_poll_table.clear();
	m_clients.clear();

	h264_nalu_queue_destroy(m_nalu_queue);
	m_nalu_queue = NULL;

	return RS_ERRCODE_SUCCESS;
}

rtmp_server_cls::~rtmp_server_cls()
{

}

rs_status rtmp_server_cls::get_status(void)
{
	rs_status status = RS_STATUS_STOP;
	FOR_EACH(std::vector<Client *>, i, m_clients)
	{
		Client *client = *i;
		if ( (client != NULL) && (client->playing))
		{
			status = RS_STATUS_PLAY;
			break;
		}
	}

	return status;
}

rs_errcode rtmp_server_cls::push_frame(unsigned char *frame,int frame_len)
{
	if(m_nalu_queue == NULL)
	{
		return RS_ERRCODE_NOINIT;
	}
	//constuction rtmp msg
	unsigned char flag = 0;
	unsigned char *rtmp_msg = NULL;
	int rtmp_msg_len = 0;

	if((frame_len < 5) || (frame == NULL))
	{
		return RS_ERRCODE_PARAMERR;
	}

	bool have_play_request = false;
	FOR_EACH(std::vector<Client *>, i, m_clients)
	{
		Client *receiver = *i;
		if (receiver != NULL && receiver->playing)
		{
			have_play_request = true;
			break;
		}
	}

	if(!have_play_request)
	{
		return RS_ERRCODE_NOPLAYING;
	}

	int start_code_len = 0;
	//case 1: start code 0x00 00 00 01
	if( (frame[0]==0x00) && (frame[1]==0x00) &&
			(frame[2]==0x00) && (frame[3]==0x01) )
	{
		flag = frame[4];
		start_code_len = 4;
	}
	//case 2: start code 0x00 00 01
	else if( (frame[0]==0x00) && (frame[1]==0x00) &&
			(frame[2]==0x01) )
	{
		flag = frame[3];
		start_code_len = 3;
	}
	else
	{
		printf("error: invalid h264 frame, bad start code \n");
		return RS_ERRCODE_PARAMERR;
	}

	unsigned char body[1024];
	int i = 0;
	h264_frame_type frame_type = FT_UNKNOWN;

	switch(flag&0x1f)
	{
	case 6: //SEI
//		frame_type = FT_SEI;
//		if(m_sequence_header_len == 0)
//		{
//			printf("I frame !! warning: need first sps and pps \n");
//			return RS_ERRCODE_WAITSPS;
//		}
//		else
//		{
//			body[i++] = 0x17; //frame type
//			body[i++] = 0x01;//avc nalu
//			/**composition time **/
//			body[i++] = 0x00;
//			body[i++] = 0x00;
//			body[i++] = 0x00;
//			/*nalu len 4 bytes*/
//			body[i++] = ((frame_len-start_code_len) >> 24) & 0xff;
//			body[i++] = ((frame_len-start_code_len) >> 16) & 0xff;
//			body[i++] = ((frame_len-start_code_len) >> 8) & 0xff;
//			body[i++] = (frame_len-start_code_len) & 0xff;
//
//			m_sei_len = i + frame_len -start_code_len;
//			assert((unsigned)m_sei_len <= sizeof(m_sei));
//			memcpy(m_sei,body,i);
//			memcpy(&m_sei[i],&frame[start_code_len],frame_len-start_code_len);
//		}
		break;


	case 7: //sps
//		if(m_sequence_header_len == 0)
		{
			body[i++] = 0x17; //frame type
			body[i++] = 0x00;//avc sequence header
			/**composition time **/
			body[i++] = 0x00;
			body[i++] = 0x00;
			body[i++] = 0x00;
			/*AVCDecoderConfigurationRecord*/
			body[i++] = 0x01;
			body[i++] = frame[start_code_len+1];
			body[i++] = frame[start_code_len+2];
			body[i++] = frame[start_code_len+3];
			body[i++] = 0xff;

			body[i++]   = 0xe1; //sps number 0xe1&0x1f
			body[i++] = ((frame_len-start_code_len)>> 8) & 0xff; //sps len 2 bytes
			body[i++] = (frame_len-start_code_len) & 0xff;
			memcpy(&body[i],&frame[start_code_len],frame_len-start_code_len);
			i +=  frame_len-start_code_len;
			memcpy(m_sequence_header,body,i);
			m_sequence_header_len = i;
		}
		frame_type = FT_SPS;
		break;
	case 8: //pps
		frame_type = FT_PPS;
//		if(m_pps_len == 0)
		{
			body[i++]   = 0x01;
			body[i++] = ((frame_len-start_code_len) >> 8) & 0xff;
			body[i++] = (frame_len-start_code_len) & 0xff;
			memcpy(&body[i],&frame[start_code_len],frame_len-start_code_len);
			i +=  frame_len-start_code_len;
			memcpy(&m_sequence_header[m_sequence_header_len],body,i);
			m_pps_len = frame_len-start_code_len;
			m_sequence_header_len += i;
		}
		break;
	case 5: //i frame
		frame_type = FT_IFRAME;
		if(m_sequence_header_len == 0)
		{
			printf("I frame !! warning: need first sps and pps \n");
			return RS_ERRCODE_WAITSPS;
		}
		else
		{
			body[i++] = 0x17; //frame type
			body[i++] = 0x01;//avc nalu
			/**composition time **/
			body[i++] = 0x00;
			body[i++] = 0x00;
			body[i++] = 0x00;
			/*nalu len 4 bytes*/
			body[i++] = ((frame_len-start_code_len) >> 24) & 0xff;
			body[i++] = ((frame_len-start_code_len) >> 16) & 0xff;
			body[i++] = ((frame_len-start_code_len) >> 8) & 0xff;
			body[i++] = (frame_len-start_code_len) & 0xff;

			rtmp_msg_len = i + frame_len -start_code_len;
			rtmp_msg = (unsigned char*)malloc(rtmp_msg_len);
			if(rtmp_msg == NULL)
			{
				return RS_ERRCODE_NOMEM;
			}
			memcpy(rtmp_msg,body,i);
			memcpy(&rtmp_msg[i],&frame[start_code_len],frame_len-start_code_len);
		}
		break;
	case 1:// p or b frame
		frame_type = FT_NOIFRAME;
		if(m_sequence_header_len == 0)
		{
			printf("P&B frame !! warning: need first sps and pps \n");
			return RS_ERRCODE_WAITSPS;
		}
		else
		{
			body[i++] = 0x27; //frame type
			body[i++] = 0x01;//avc nalu
			/**composition time **/
			body[i++] = 0x00;
			body[i++] = 0x00;
			body[i++] = 0x00;
			/*nalu len 4 bytes*/
			body[i++] = ((frame_len-start_code_len) >> 24) & 0xff;
			body[i++] = ((frame_len-start_code_len) >> 16) & 0xff;
			body[i++] = ((frame_len-start_code_len) >> 8) & 0xff;
			body[i++] = (frame_len-start_code_len) & 0xff;

			rtmp_msg_len = i + frame_len - start_code_len;
			rtmp_msg = (unsigned char*)malloc(rtmp_msg_len);
			if(rtmp_msg == NULL)
			{
				return RS_ERRCODE_NOMEM;
			}
			memcpy(rtmp_msg,body,i);
			memcpy(&rtmp_msg[i],&frame[start_code_len],frame_len-start_code_len);
		}
		break;
	default:
		printf("error: unsupported frame type \n");
		hexdump(frame,frame_len);
		return RS_ERRCODE_PARAMERR;
	}

	//push s_nalu_queue
	if(rtmp_msg != NULL)
	{
		h264_nalu nalu;
		nalu.nalu_data = rtmp_msg;
		nalu.nalu_len = rtmp_msg_len;
		nalu.frame_type = frame_type;

		// frame rate
//		double percent = (double)m_nalu_queue->nalu_queue.size()/m_nalu_queue->max_len;
//		double frame_rate = (m_nalu_queue->max_frame_rate-m_nalu_queue->min_frame_rate)*percent +
//				m_nalu_queue->min_frame_rate;
//		double span = 1000/frame_rate;

#if 1
		if(m_prev_tv.tv_sec == 0)
		{
			gettimeofday(&m_prev_tv,NULL);
			m_timestamp = 0;
		}
		else
		{
			struct timeval tv_now;
			gettimeofday(&tv_now,NULL);

			int span = (tv_now.tv_sec-m_prev_tv.tv_sec)*1000 + (tv_now.tv_usec-m_prev_tv.tv_usec)/1000;
//			int ori = span;
			if(span < 1000/m_nalu_queue->max_frame_rate)
			{
				span = 1000/m_nalu_queue->max_frame_rate;
			}
			if(span > 1000/m_nalu_queue->min_frame_rate)
			{
				span = 1000/m_nalu_queue->min_frame_rate;
			}
			m_timestamp += span;
//			printf("origin_span:%d span:%d queue_size:%u \n",ori,span,m_nalu_queue->nalu_queue.size());
			/**
			 *  can't support extended timestamp
			 *  if timestamp > 3bytes. then begin from 0
			 */

			if(m_timestamp > 0xffffff)
			{
				m_timestamp = 0;
			}
			m_prev_tv = tv_now;
		}
#endif
		if(m_timestamp > 0xffffff)
		{
			m_timestamp = 0;
		}
		nalu.timestamp = m_timestamp;

		if((m_nalu_queue->nalu_queue.size() < (unsigned)m_nalu_queue->max_len) &&
				(nalu.frame_type == FT_IFRAME))
		{
			m_drop = false;
		}

		//drop frame until the next i frame
		if(!m_drop)
		{
			if(!h264_nalu_queue_push(m_nalu_queue,nalu))
			{
				free(nalu.nalu_data);
				nalu.nalu_data = NULL;
				m_drop = true;
			}
		}
	}

	return RS_ERRCODE_SUCCESS;
}

void rtmp_server_cls::loop(void)
{
	for (;;)
	{
		do_poll();
		if(m_thread_quit)
		{
			break;
		}
	}
}

size_t rtmp_server_cls::recv_all(int fd, void *buf, size_t len)
{
	size_t pos = 0;
	while (pos < len)
	{
		ssize_t bytes = recv(fd, (char *) buf + pos, len - pos, 0);
		if (bytes < 0)
		{
			if (errno == EAGAIN || errno == EINTR)
				continue;
			throw std::runtime_error(
				strf("unable to recv: %s", strerror(errno)));
		}
		if (bytes == 0)
			break;
		pos += bytes;
	}
	return pos;
}

size_t rtmp_server_cls::send_all(int fd, const void *buf, size_t len)
{
	size_t pos = 0;
	while (pos < len)
	{
		ssize_t written = send(fd, (const char *) buf + pos, len - pos, 0);
		if (written < 0)
		{
			if (errno == EAGAIN || errno == EINTR)
				continue;
			throw std::runtime_error(
				strf("unable to send: %s", strerror(errno)));
		}
		if (written == 0)
			break;
		pos += written;
	}
	return pos;
}

void rtmp_server_cls::try_to_send(Client *client)
{
	size_t len = client->send_queue.size();
	if (len > 4*1024)
		len = 4*1024;
	if(len == 0)
	{
		return;
	}
	ssize_t written = send(client->fd, client->send_queue.data(), len, 0);
	if (written < 0)
	{
		if (errno == EAGAIN || errno == EINTR)
			return;
		throw std::runtime_error(strf("unable to write to a client: %s",
						strerror(errno)));
	}
//	static struct timeval t1 = {0,0};
//	static struct timeval t2 = {0,0};
//	gettimeofday(&t2,NULL);
//	printf("success to send %d bytes, len:%d span %ld \n", written,len,
//			(t2.tv_sec-t1.tv_sec)*1000+(t2.tv_usec-t1.tv_usec)/1000);
//	t1 = t2;
	client->send_queue.erase(0, written);
}

void rtmp_server_cls::send_reply(Client *client, double txid, const AMFValue &reply,const AMFValue &status)
{
	if (txid <= 0.0)
		return;
	Encoder invoke;
	amf_write(&invoke, std::string("_result"));
	amf_write(&invoke, txid);
	amf_write(&invoke, reply);
	amf_write(&invoke, status);
	rtmp_send(client, MSG_INVOKE, CONTROL_ID, invoke.buf, 0, CHAN_RESULT);
}

void rtmp_server_cls::close_client(Client *client, size_t i)
{
	m_clients.erase(m_clients.begin() + i);
	m_poll_table.erase(m_poll_table.begin() + i);
	close(client->fd);

	if (client == m_publisher)
	{
		printf("publisher disconnected.\n");
		m_publisher = NULL;
		FOR_EACH(std::vector<Client *>, i, m_clients)
		{
			Client *client = *i;
			if (client != NULL)
			{
				client->ready = false;
			}
		}
	}

	delete client;
}

int rtmp_server_cls::set_nonblock(int fd, bool enabled)
{
	int flags = fcntl(fd, F_GETFL) & ~O_NONBLOCK;
	if (enabled) {
		flags |= O_NONBLOCK;
	}
	return fcntl(fd, F_SETFL, flags);
}
bool rtmp_server_cls::is_safe(uint8_t b)
{
	return b >= ' ' && b < 128;
}

void rtmp_server_cls::hexdump(const void *buf, size_t len)
{
	const uint8_t *data = (const uint8_t *) buf;
	for (size_t i = 0; i < len; i += 16)
	{
		for (int j = 0; j < 16; ++j)
		{
			if (i + j < len)
				debug("%.2x ", data[i + j]);
			else
				debug("   ");
		}
		for (int j = 0; j < 16; ++j)
		{
			if (i + j < len)
			{
				putc(is_safe(data[i + j]) ? data[i + j] : '.',
				     stdout);
			}
			else
			{
				putc(' ', stdout);
			}
		}
		putc('\n', stdout);
	}
}

void rtmp_server_cls::do_handshake(Client *client)
{
	Handshake serversig;
	Handshake clientsig;

	uint8_t c;
	if (recv_all(client->fd, &c, 1) < 1)
		return;
	if (c != HANDSHAKE_PLAINTEXT)
	{
		throw std::runtime_error("only plaintext handshake supported");
	}

	if (send_all(client->fd, &c, 1) < 1)
		return;

	memset(&serversig, 0, sizeof serversig);
	serversig.flags[0] = 0x03;
	for (int i = 0; i < RANDOM_LEN; ++i)
	{
		serversig.random[i] = rand();
	}

	if (send_all(client->fd, &serversig, sizeof serversig) < sizeof serversig)
		return;

	/* Echo client's signature back */
	if (recv_all(client->fd, &clientsig, sizeof serversig) < sizeof serversig)
		return;
	if (send_all(client->fd, &clientsig, sizeof serversig) < sizeof serversig)
		return;

	if (recv_all(client->fd, &clientsig, sizeof serversig) < sizeof serversig)
		return;
	if (memcmp(serversig.random, clientsig.random, RANDOM_LEN) != 0)
	{
		throw std::runtime_error("invalid handshake");
	}

	client->read_seq = 1 + sizeof serversig * 2;
	client->written_seq = 1 + sizeof serversig * 2;
}

void rtmp_server_cls::start_playback(Client *client)
{
	amf_object_t status;
	status.insert(std::make_pair("level", std::string("status")));
	status.insert(std::make_pair("code", std::string("NetStream.Play.Reset")));
	status.insert(std::make_pair("description", std::string("Resetting and playing stream.")));

	Encoder invoke;
	amf_write(&invoke, std::string("onStatus"));
	amf_write(&invoke, 0.0);
	amf_write_null(&invoke);
	amf_write(&invoke, status);
	rtmp_send(client, MSG_INVOKE, STREAM_ID, invoke.buf);

	status.clear();
	status.insert(std::make_pair("level", std::string("status")));
	status.insert(std::make_pair("code", std::string("NetStream.Play.Start")));
	status.insert(std::make_pair("description", std::string("Started playing.")));

	invoke.buf.clear();
	amf_write(&invoke, std::string("onStatus"));
	amf_write(&invoke, 0.0);
	amf_write_null(&invoke);
	amf_write(&invoke, status);
	rtmp_send(client, MSG_INVOKE, STREAM_ID, invoke.buf);

	invoke.buf.clear();
	amf_write(&invoke, std::string("|RtmpSampleAccess"));
	amf_write(&invoke, true);
	amf_write(&invoke, true);
	rtmp_send(client, MSG_NOTIFY, STREAM_ID, invoke.buf);

	client->playing = true;
	client->ready = false;

	if (m_publisher != NULL)
	{
		Encoder notify;
		amf_write(&notify, std::string("onMetaData"));
		amf_write_ecma(&notify, m_metadata);
		rtmp_send(client, MSG_NOTIFY, STREAM_ID, notify.buf);
	}
}

Client *rtmp_server_cls::new_client()
{
	sockaddr_in sin;
	socklen_t addrlen = sizeof sin;
	int fd = accept(m_listen_fd, (sockaddr *) &sin, &addrlen);
	if (fd < 0) {
		printf("Unable to accept a client: %s\n", strerror(errno));
		return NULL;
	}

	Client *client = new Client;
	client->playing = false;
	client->ready = false;
	client->fd = fd;
	client->written_seq = 0;
	client->read_seq = 0;
	client->chunk_len = DEFAULT_CHUNK_LEN;
	for (int i = 0; i < 64; ++i)
	{
		client->messages[i].timestamp = 0;
		client->messages[i].use_exttimestamp = false;
		client->messages[i].len = 0;
	}

	try
	{
		do_handshake(client);
	}
	catch (const std::runtime_error &e)
	{
		printf("handshake failed: %s\n", e.what());
		close(fd);
		delete client;
		return NULL;
	}

	set_nonblock(fd, true);


	pollfd entry;
	entry.events = POLLIN;
	entry.revents = 0;
	entry.fd = fd;
	m_poll_table.push_back(entry);
	m_clients.push_back(client);

	return client;
}

void rtmp_server_cls::recv_from_client(Client *client)
{
	std::string chunk(4096, 0);
	ssize_t got = recv(client->fd, &chunk[0], chunk.size(), 0);
	if (got == 0)
	{
		throw std::runtime_error("EOF from a client");
	}
	else if (got < 0)
	{
		if (errno == EAGAIN || errno == EINTR)
			return;
		throw std::runtime_error(strf("unable to read from a client: %s",
					      strerror(errno)));
	}
//	printf("recv from client %d \n",got);
	client->buf.append(chunk, 0, got);

	while (!client->buf.empty())
	{
		uint8_t flags = client->buf[0];

		static const size_t HEADER_LENGTH[] = {12, 8, 4, 1};
		size_t header_len = HEADER_LENGTH[flags >> 6];

		if (client->buf.size() < header_len)
		{
			/* need more data */
			break;
		}
		unsigned int ext_timestamp = 0;
		RTMP_Header header;
		memcpy(&header, client->buf.data(), header_len);

		RTMP_Message *msg = &client->messages[flags & 0x3f];

		if (header_len >= 8)
		{
			msg->len = load_be24(header.msg_len);
			if (msg->len < msg->buf.size())
			{
				throw std::runtime_error("invalid msg length");
			}
			msg->type = header.msg_type;
		}
		if (header_len >= 12)
		{
			msg->endpoint = load_le32(header.endpoint);
		}

		if (msg->len == 0)
		{
			throw std::runtime_error("message without a header");
		}
		size_t chunk = msg->len - msg->buf.size();
		if (chunk > client->chunk_len)
			chunk = client->chunk_len;

		if (client->buf.size() < header_len + chunk)
		{
			/* need more data */
			break;
		}

		if (header_len >= 4)
		{
			unsigned long ts = load_be24(header.timestamp);
			if (ts == 0xffffff) {
//				throw std::runtime_error("ext timestamp not supported");
				printf("info: extended timestamp !! \n");
				memcpy(&ext_timestamp, client->buf.data()+header_len, sizeof(ext_timestamp));
				msg->timestamp = load_be32(&ext_timestamp);
				msg->use_exttimestamp = true;
			}
			else
			{
				if (header_len < 12)
				{
					ts += msg->timestamp;
				}
				msg->timestamp = ts;
				msg->use_exttimestamp = false;
			}
		}

		if(ext_timestamp == 0)
		{
			msg->buf.append(client->buf, header_len, chunk);
			client->buf.erase(0, header_len + chunk);
		}
		else
		{
			msg->buf.append(client->buf,header_len+sizeof(ext_timestamp),chunk);
			client->buf.erase(0,header_len + chunk + sizeof(ext_timestamp));
		}

		if (msg->buf.size() == msg->len)
		{
			handle_message(client, msg);
			msg->buf.clear();
		}
	}
}

void rtmp_server_cls::handle_message(Client *client, RTMP_Message *msg)
{
	size_t pos = 0;

	switch (msg->type)
	{
	case MSG_BYTES_READ:
		if (pos + 4 > msg->buf.size())
		{
			throw std::runtime_error("Not enough data");
		}
		client->read_seq = load_be32(&msg->buf[pos]);
		debug("%d in queue\n",
			int(client->written_seq - client->read_seq));
		break;

	case MSG_SET_CHUNK:
		if (pos + 4 > msg->buf.size())
		{
			throw std::runtime_error("Not enough data");
		}
		client->chunk_len = load_be32(&msg->buf[pos]);
		debug("chunk size set to %zu\n", client->chunk_len);
		break;

	case MSG_INVOKE:
		{
			Decoder dec;
			dec.version = 0;
			dec.buf = msg->buf;
			dec.pos = 0;
			handle_invoke(client, msg, &dec);
		}
		break;

	case MSG_INVOKE3:
		{
			Decoder dec;
			dec.version = 0;
			dec.buf = msg->buf;
			dec.pos = 1;
			handle_invoke(client, msg, &dec);
		}
		break;

	case MSG_NOTIFY:
		{
			Decoder dec;
			dec.version = 0;
			dec.buf = msg->buf;
			dec.pos = 0;
			std::string type = amf_load_string(&dec);
			debug("notify %s\n", type.c_str());
			if (msg->endpoint == STREAM_ID)
			{
				if (type == "@setDataFrame")
				{
					handle_setdataframe(client, &dec);
				}
			}
		}
		break;

	case MSG_AUDIO:
		if (client != m_publisher)
		{
			throw std::runtime_error("not a publisher");
		}
		FOR_EACH(std::vector<Client *>, i, m_clients)
		{
			Client *receiver = *i;
			if (receiver != NULL && receiver->ready)
			{
				rtmp_send(receiver, MSG_AUDIO, STREAM_ID,
					  msg->buf, msg->timestamp);
			}
		}
		break;

	case MSG_VIDEO:
		{
			if (client != m_publisher)
			{
				throw std::runtime_error("not a publisher");
			}
			uint8_t flags = msg->buf[0];

			FOR_EACH(std::vector<Client *>, i, m_clients)
			{
				Client *receiver = *i;
				if (receiver != NULL && receiver->playing)
				{
					if (flags >> 4 == FLV_KEY_FRAME &&
						!receiver->ready)
					{
						std::string control;
						uint16_t type = htons(CONTROL_CLEAR_STREAM);
						control.append((char *) &type, 2);
						uint32_t stream = htonl(STREAM_ID);
						control.append((char *) &stream, 4);
						rtmp_send(receiver, MSG_USER_CONTROL, CONTROL_ID, control);
						receiver->ready = true;
					}
					if (receiver->ready)
					{
						rtmp_send(receiver, MSG_VIDEO,
							  STREAM_ID, msg->buf,
							  msg->timestamp,CHAN_STREAM,msg);
					}
				}
			}
		}
		break;

	case MSG_FLASH_VIDEO:
		throw std::runtime_error("streaming FLV not supported");
		break;

	default:
		debug("unhandled message: %02x\n", msg->type);
		hexdump(msg->buf.data(), msg->buf.size());
		break;
	}
}

void rtmp_server_cls::handle_invoke(Client *client, const RTMP_Message *msg, Decoder *dec)
{
	std::string method = amf_load_string(dec);
	double txid = amf_load_number(dec);

	debug("invoked %s\n", method.c_str());

	if (msg->endpoint == CONTROL_ID)
	{
		if (method == "connect")
		{
			handle_connect(client, txid, dec);
		}
		else if (method == "FCPublish")
		{
			handle_fcpublish(client, txid, dec);
		}
		else if (method == "createStream")
		{
			handle_createstream(client, txid, dec);
		}

	}
	else if (msg->endpoint == STREAM_ID)
	{
		if (method == "publish")
		{
			handle_publish(client, txid, dec);
		}
		else if (method == "play")
		{
			handle_play(client, txid, dec);
		}
		else if (method == "play2")
		{
			handle_play2(client, txid, dec);
		}
		else if (method == "pause")
		{
			handle_pause(client, txid, dec);
		}
	}
}

void rtmp_server_cls::handle_connect(Client *client, double txid, Decoder *dec)
{
	amf_object_t params = amf_load_object(dec);
	std::string app = get(params, std::string("app")).as_string();
	std::string ver = "(unknown)";
	AMFValue flashver = get(params, std::string("flashVer"));
	if (flashver.type() == AMF_STRING)
	{
		ver = flashver.as_string();
	}

	if (app != m_suffix)
	{
		throw std::runtime_error("Unsupported application: " + app);
	}

	printf("connect: %s (version %s)\n", app.c_str(), ver.c_str());

	amf_object_t version;
	version.insert(std::make_pair("fmsVer", std::string("FMS/4,5,1,484")));
	version.insert(std::make_pair("capabilities", 255.0));
	version.insert(std::make_pair("mode", 1.0));

	amf_object_t status;
	status.insert(std::make_pair("level", std::string("status")));
	status.insert(std::make_pair("code", std::string("NetConnection.Connect.Success")));
	status.insert(std::make_pair("description", std::string("Connection succeeded.")));
	/* report support for AMF3 */
	status.insert(std::make_pair("objectEncoding", 3.0));
	send_reply(client, txid, version, status);
/*
	uint32_t chunk_len = htonl(1024);
	std::string set_chunk((char *) &chunk_len, 4);
	rtmp_send(client, MSG_SET_CHUNK, CONTROL_ID, set_chunk, 0,
		  MEDIA_CHANNEL);

	client->chunk_len = 1024;
*/
}

void rtmp_server_cls::handle_fcpublish(Client *client, double txid, Decoder *dec)
{
	if (m_publisher != NULL)
	{
		throw std::runtime_error("Already have a publisher");
	}
	m_publisher = client;
	printf("publisher connected.\n");

	amf_load(dec); /* NULL */

	std::string path = amf_load_string(dec);
	debug("fcpublish %s\n", path.c_str());

	amf_object_t status;
	status.insert(std::make_pair("code", std::string("NetStream.Publish.Start")));
	status.insert(std::make_pair("description", path));

	Encoder invoke;
	amf_write(&invoke, std::string("onFCPublish"));
	amf_write(&invoke, 0.0);
	amf_write_null(&invoke);
	amf_write(&invoke, status);
	rtmp_send(client, MSG_INVOKE, CONTROL_ID, invoke.buf);

	send_reply(client, txid);
}

void rtmp_server_cls::handle_createstream(Client *client, double txid, Decoder *dec)
{
	send_reply(client, txid, AMFValue(), double(STREAM_ID));
}

void rtmp_server_cls::handle_publish(Client *client, double txid, Decoder *dec)
{
	amf_load(dec); /* NULL */

	std::string path = amf_load_string(dec);
	debug("publish %s\n", path.c_str());

	amf_object_t status;
	status.insert(std::make_pair("level", std::string("status")));
	status.insert(std::make_pair("code", std::string("NetStream.Publish.Start")));
	status.insert(std::make_pair("description", std::string("Stream is now published.")));
	status.insert(std::make_pair("details", path));

	Encoder invoke;
	amf_write(&invoke, std::string("onStatus"));
	amf_write(&invoke, 0.0);
	amf_write_null(&invoke);
	amf_write(&invoke, status);
	rtmp_send(client, MSG_INVOKE, STREAM_ID, invoke.buf);

	send_reply(client, txid);
}

void rtmp_server_cls::handle_play(Client *client, double txid, Decoder *dec)
{
	amf_load(dec); /* NULL */
	std::string path = amf_load_string(dec);
	debug("play %s\n", path.c_str());
	start_playback(client);
	send_reply(client, txid);
}

void rtmp_server_cls::handle_play2(Client *client, double txid, Decoder *dec)
{
	amf_load(dec); /* NULL */
	amf_object_t params = amf_load_object(dec);
	std::string path = get(params, std::string("streamName")).as_string();
	debug("play %s\n", path.c_str());
	start_playback(client);
	send_reply(client, txid);
}

void rtmp_server_cls::handle_pause(Client *client, double txid, Decoder *dec)
{
	amf_load(dec); /* NULL */

	bool paused = amf_load_boolean(dec);

	if (paused)
	{
		debug("pausing\n");

		amf_object_t status;
		status.insert(std::make_pair("level", std::string("status")));
		status.insert(std::make_pair("code", std::string("NetStream.Pause.Notify")));
		status.insert(std::make_pair("description", std::string("Pausing.")));

		Encoder invoke;
		amf_write(&invoke, std::string("onStatus"));
		amf_write(&invoke, 0.0);
		amf_write_null(&invoke);
		amf_write(&invoke, status);
		rtmp_send(client, MSG_INVOKE, STREAM_ID, invoke.buf);
		client->playing = false;
	}
	else
	{
		start_playback(client);
	}

	send_reply(client, txid);
}

void rtmp_server_cls::handle_setdataframe(Client *client, Decoder *dec)
{
	if (client != m_publisher)
	{
		throw std::runtime_error("not a publisher");
	}

	std::string type = amf_load_string(dec);
	if (type != "onMetaData")
	{
		throw std::runtime_error("can only set metadata");
	}

	m_metadata = amf_load_ecma(dec);

	Encoder notify;
	amf_write(&notify, std::string("onMetaData"));
	amf_write_ecma(&notify, m_metadata);

	FOR_EACH(std::vector<Client *>, i, m_clients)
	{
		Client *client = *i;
		if (client != NULL && client->playing)
		{
			rtmp_send(client, MSG_NOTIFY, STREAM_ID, notify.buf);
		}
	}
}


void rtmp_server_cls::rtmp_send(Client *client, uint8_t type, uint32_t endpoint,
		const std::string &buf, unsigned int timestamp,int channel_num,RTMP_Message *msg)
{
	if (endpoint == STREAM_ID)
	{
		/*
		 * For some unknown reason, stream-related msgs must be sent
		 * on a specific channel.
		 */
		channel_num = CHAN_STREAM;
	}

	RTMP_Header header;
	header.flags = (channel_num & 0x3f) | (0 << 6);
	header.msg_type = type;
	if((msg != NULL) && (msg->use_exttimestamp))
	{
		set_be24(header.timestamp, 0xffffff);
		set_be24(header.msg_len, buf.size());
		set_le32(header.endpoint, endpoint);

		client->send_queue.append((char *) &header, sizeof header);
		client->written_seq += sizeof header;

		//extended timestamp 4bytes
		uint32_t ext_timestamp;
		set_be32(&ext_timestamp,msg->timestamp);
		client->send_queue.append((char*)&ext_timestamp,sizeof(ext_timestamp));
		client->written_seq += sizeof(ext_timestamp);
	}
	else
	{
		set_be24(header.timestamp, timestamp);
		set_be24(header.msg_len, buf.size());
		set_le32(header.endpoint, endpoint);

		client->send_queue.append((char *) &header, sizeof header);
		client->written_seq += sizeof header;
	}
	size_t pos = 0;
	while (pos < buf.size())
	{
		if (pos)
		{
			uint8_t flags = (channel_num & 0x3f) | (3 << 6);
			client->send_queue += char(flags);

			client->written_seq += 1;
		}

		size_t chunk = buf.size() - pos;
		if (chunk > client->chunk_len)
			chunk = client->chunk_len;
		client->send_queue.append(buf, pos, chunk);

		client->written_seq += chunk;
		pos += chunk;
	}
	try
	{
		try_to_send(client);
	}
	catch (const std::runtime_error &e)
	{
		printf("close client,send msg to client error: %s \n", e.what());
		for(unsigned i=0; i<m_clients.size(); i++)
		{
			if(m_clients[i] == client)
			{
				close_client(client,i);
			}
		}
	}
}

void rtmp_server_cls::do_poll(void)
{
	for (size_t i = 0; i < m_poll_table.size(); ++i)
	{
		Client *client = m_clients[i];
		if (client != NULL)
		{
			if (!client->send_queue.empty())
			{
//				debug("waiting for pollout %lu\n",client->send_queue.size());
				m_poll_table[i].events = POLLIN | POLLOUT;
			}
			else
			{
				m_poll_table[i].events = POLLIN;
			}

		}
	}
	int poll_ret = poll(&m_poll_table[0], m_poll_table.size(), 20);
	if (poll_ret < 0)
	{
		if (errno == EAGAIN || errno == EINTR)
			return;
		throw std::runtime_error(strf("poll() failed: %s",
						strerror(errno)));
	}
	else if(poll_ret > 0)
	{
		for (size_t i = 0; i < m_poll_table.size(); ++i)
		{
			Client *client = m_clients[i];
			if (m_poll_table[i].revents & POLLOUT)
			{
				try
				{
					try_to_send(client);
				}
				catch (const std::runtime_error &e)
				{
					printf("client error: %s\n", e.what());
					close_client(client, i);
					--i;
					continue;
				}
			}
			if (m_poll_table[i].revents & POLLIN)
			{
				if (client == NULL)
				{
					new_client();
				}
				else try
				{
					recv_from_client(client);
				}
				catch (const std::runtime_error &e)
				{
					printf("client error: %s\n", e.what());
					close_client(client, i);
					--i;
				}
			}
		}
	}

	h264_nalu h264_nalu_block = h264_nalu_queue_pop(m_nalu_queue);
	if(h264_nalu_block.nalu_data != NULL)
	{
//		printf("%p \n",h264_nalu_block.nalu_data);
//		printf("%.02X \n",h264_nalu_block.nalu_data[0]);
		unsigned char flags = h264_nalu_block.nalu_data[0];
		FOR_EACH(std::vector<Client *>, i, m_clients)
		{
			Client *receiver = *i;
			if (receiver != NULL && receiver->playing)
			{
				if (flags >> 4 == FLV_KEY_FRAME &&
					!receiver->ready)
				{
					std::string control;
					uint16_t type = htons(CONTROL_CLEAR_STREAM);
					control.append((char *) &type, 2);
					uint32_t stream = htonl(STREAM_ID);
					control.append((char *) &stream, 4);
					rtmp_send(receiver, MSG_USER_CONTROL, CONTROL_ID, control);
					receiver->ready = true;
				}
				if (receiver->ready)
				{
					if(h264_nalu_block.frame_type == FT_IFRAME)
					{
						assert(m_sequence_header_len != 0);
						assert(m_pps_len != 0);
						//send sps pps
						std::string header_buf;
						header_buf.append((const char*)m_sequence_header,m_sequence_header_len);
						rtmp_send(receiver, MSG_VIDEO,STREAM_ID, header_buf,h264_nalu_block.timestamp);
						//if sei, send sei
						if(m_sei_len > 0)
						{
							std::string sei_buf;
							sei_buf.append((const char*)m_sei,m_sei_len);
							rtmp_send(receiver, MSG_VIDEO,STREAM_ID, sei_buf,h264_nalu_block.timestamp);
							m_sei_len = 0;
						}
					}

					std::string buf;
					buf.append((const char*)h264_nalu_block.nalu_data,h264_nalu_block.nalu_len);

					rtmp_send(receiver, MSG_VIDEO,STREAM_ID, buf,
						  h264_nalu_block.timestamp);
				}
			}
		}

		//release h264_nalu
		free(h264_nalu_block.nalu_data);
		h264_nalu_block.nalu_data = NULL;
	}
}

