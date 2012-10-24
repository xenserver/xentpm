CC=gcc
CFLAGS+= -g $(CPPFLAGS)
LIBS+= $(LDFLAGS) -lssl -ltspi

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
	chmod +x setup.sh
	./setup.sh
