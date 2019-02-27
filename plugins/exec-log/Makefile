CFLAGS += -I../include -fno-PIE -fPIC -O3
LDFLAGS += -shared
# TODO: Windows
DSOSUF := .so

NAME:= exec-log
BIN := $(NAME)$(DSOSUF)

FILES := exec-log.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(FILES)
	$(CC) $(LDFLAGS) -o $(BIN) $(FILES)

clean:
	rm $(FILES)
	rm $(BIN)
