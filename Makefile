TARGET = tcp-block
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDLIBS = -lpcap

SRCS = main.cpp tcp_block.cpp

all: $(TARGET)

$(TARGET): $(SRCS) tcp_block.h my_struct.h
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
