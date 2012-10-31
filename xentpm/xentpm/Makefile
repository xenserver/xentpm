CC=gcc
CFLAGS+= -g $(CPPFLAGS)
LIBS+= $(LDFLAGS) -lssl -ltspi
BASE= $(addsuffix /opt/tpm, $(prefix))
PLUGIN= $(addsuffix /etc/xapi.d/plugins/, $(prefix))

all:generateAik aikrespond xenquote

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

aikrespond: aikrespond.o	
	gcc -o $@ $^ $(CFLAGS) $(LIBS)  

generateAik: generateAik.o	
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

xenquote: xenquote.o	
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o generateAik aikchallange xenquote

install:
	[ -d $(BASE) ] || mkdir -p $(BASE) 
	[ -d $(PLUGIN) ] || mkdir -p $(PLUGIN)
	cp -f xenaik.xml $(BASE)
	cp -f generateAik  $(BASE)
	cp -f aikrespond  $(BASE)
	cp -f xenquote    $(BASE)
	cp -f tpm*       $(PLUGIN)

