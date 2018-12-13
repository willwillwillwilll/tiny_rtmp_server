
include ../config.MK

OBJS =  main.o

tiny_rtmp_server: $(OBJS)
	$(CXX) $(CXXFLAGS)  -o ../bin/$@ $(OBJS) -L../bin -ltiny_rtmp_server  -lpthread -Wl,-rpath=.
%.o:%.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $< -I../code
clean:
	rm -f *.o ../bin/tiny_rtmp_server

.PHONY: tiny_rtmp_server clean
