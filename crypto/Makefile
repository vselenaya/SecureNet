CC = gcc  # компилятор
CFLAGS = -Wall -Werror -Wextra -g  # флаги, с которыми компилируется код

OBJECTS1 = obj/client.o obj/aes.o obj/common.o obj/kex.o obj/keypair.o obj/secure_and_net.o
OBJECTS2 = obj/mim.o obj/aes.o obj/common.o obj/kex.o obj/keypair.o obj/secure_and_net.o
OBJECTS = obj/mim.o obj/client.o obj/aes.o obj/common.o obj/kex.o obj/keypair.o obj/secure_and_net.o
HEADERS = include/aes.h include/common.h include/kex.h include/keypair.h include/secure_and_net.h

OUTPUT1 = client  # как называется исполняемая программа
OUTPUT2 = mim

LIBS = -lssl -lcrypto -lm  # библиотеки OpenSSL (3.0 или старше!) и математические функции

$(OBJECTS): obj/%.o  : src/%.c $(HEADERS)  # компиляция
	gcc $(CFLAGS) -I include -c  $< -o $@

$(OUTPUT1): obj $(OBJECTS1)  # этап линковки в единую программу client
	gcc $(CFLAGS) -I include -o $@ $(OBJECTS1) $(LIBS)

$(OUTPUT2): obj $(OBJECTS2)  # этап линковки в единую программу mim
	gcc $(CFLAGS) -I include -o $@ $(OBJECTS2) $(LIBS)

project:
	make client
	make mim
	
obj: 
	mkdir -p obj

clean:
	rm -rf obj
	rm -rf $(OUTPUT1)
	rm -rf $(OUTPUT2)

clean_pem:
	rm -rf *.pem client_*_info*