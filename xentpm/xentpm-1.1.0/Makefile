CC=gcc
CFLAGS+= -g $(CPPFLAGS)
LIBS+= $(LDFLAGS) -lssl -ltspi
BASE= $(addsuffix /opt/tpm, $(prefix))
PLUGIN= $(addsuffix /etc/xapi.d/plugins/, $(prefix))

all:mkcert aikpublish aikrespond xenquote

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

mkcert: mkcert.o
	gcc -o $@ $^ $(CFLAGS)  $(LIBS)

aikrespond: aikrespond.o	
	gcc -o $@ $^ $(CFLAGS) $(LIBS)  

aikpublish: aikpublish.o	
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

xenquote: xenquote.o	
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o mkcert aikpublish aikchallange 

install:
	[ -d $(BASE) ] || mkdir -p $(BASE) 
	[ -d $(PLUGIN) ] || mkdir -p $(PLUGIN)
	cp -f xenaik.xml $BASE
	cp -f mkcert      $BASE
	cp -f aikpublish  $BASE
	cp -f aikrespond  $BASE
	cp -f xenquote    $BASE
	cp -f tpm*       $(PLUGIN)

