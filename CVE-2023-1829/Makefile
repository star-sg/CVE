.PHONY: all clean

TARGET=poc

SOURCES = $(wildcard src/*.c)
HEADERS = $(wildcard inc/*.h)
OBJECTS = $(patsubst src/%.c,obj/%.o,$(SOURCES))

CFLAGS= -I./inc
LDFLAGS= -Wall

all: obj $(TARGET) get_root

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ -lmnl -lnftnl -pthread
# strip $@

obj/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS) -lmnl -lnftnl

obj:
	mkdir obj

get_root: get_root_src/get_root.c
	$(CC) -o $@ $^

clean:
	rm -rf obj
	rm -f $(TARGET)
	rm -f get_root
