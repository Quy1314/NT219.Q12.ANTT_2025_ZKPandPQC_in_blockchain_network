JAVAHOME := /usr/lib/jvm/java-21-openjdk-amd64
CFLAGS := -fPIC -I$(JAVAHOME)/include -I$(JAVAHOME)/include/linux -I/usr/local/include
LDFLAGS := -shared -L/usr/local/lib -loqs -lcrypto

SRC := src/pqc_jni.c
OUT := libpqcjni.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(OUT)

clean:
	rm -f $(OUT)
