
include ../config.MK
OBJS =  amf.o utils.o h264_nalu_queue.o tiny_rtmp_server.o rtmp_server_impl.o

libtiny_rtmp_server.so: $(OBJS)
	$(CXX) $(CXXFLAGS) -shared  -o ../bin/$@ $(OBJS)  -lpthread
%.o:%.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $<
clean:
	rm -f *.o ../bin/libtiny_rtmp_server.so

.PHONY: libtiny_rtmp_server.so clean
