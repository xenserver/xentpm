CC=gcc
CFLAGS+= -g -Itrousers/include -Wall 
LIBS+=  -Ltrousers/lib -lssl -ltspi
BASE= $(addsuffix /opt/xensource/tpm, $(prefix))
PLUGIN= $(addsuffix /etc/xapi.d/plugins/, $(prefix))

all:xentpm 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

xentpm: xentpm.o takeOwnership.o getEndorsement.o generateAik.o challenge.o xenquote.o
	gcc -o $@ $^ $(CFLAGS) $(LIBS)  

clean:
	rm -rf *.o xentpm 

install:
	[ -d $(BASE) ] || mkdir -p $(BASE) 
	[ -d $(PLUGIN) ] || mkdir -p $(PLUGIN)
	cp -f xenaik.xml $(BASE)
	cp -f xentpm $(BASE)
	cp -f tpm $(PLUGIN)

