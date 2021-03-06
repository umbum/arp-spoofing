CC       := g++
LDLIBS   := -lpcap
# CFLAGS   := -g


TARGET  := arp-spoofing
OBJECTS := $(patsubst %cpp,%o,$(wildcard src/*.cpp)) $(patsubst %c,%o,$(wildcard src/*.c))
HEADERS := $(wildcard src/*.h)

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(LDLIBS)

%.o: %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $< 

.PHONY: clean new
clean:
	rm -f $(OBJECTS) $(TARGET)

new:
	$(MAKE) clean
	$(MAKE)
