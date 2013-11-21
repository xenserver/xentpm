CC=gcc
CFLAGS+= -g  -I/include -Wall
LIBS+=  -lssl -ltspi
BASE= $(addsuffix /opt/xensource/tpm, $(prefix))
PLUGIN= $(addsuffix /etc/xapi.d/plugins/, $(prefix))

all:xentpm 

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

xentpm: xentpm.o takeOwnership.o getEndorsement.o generateAik.o challenge.o xenquote.o utils.o
	gcc -g -o $@ $^ $(CFLAGS) $(LIBS)  

clean:
	rm -rf *.o xentpm 

install:
	[ -d $(BASE) ] || mkdir -p $(BASE) 
	[ -d $(PLUGIN) ] || mkdir -p $(PLUGIN)
	cp -f config $(BASE)
	cp -f xentpm $(BASE)
	cp -f tpm $(PLUGIN)

