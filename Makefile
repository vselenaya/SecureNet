CC = gcc  # компилятор
CFLAGS = -Wall -Werror -Wextra -g  # флаги, с которыми компилируется код

OBJECTS1 = obj/client.o obj/common.o
OBJECTS2 = obj/server.o obj/common.o
OBJECTS3 = obj/mim.o obj/common.o
OBJECTS = obj/mim.o obj/client.o obj/server.o obj/common.o
HEADERS = include/common.h

OUTPUT1 = client  # как называется исполняемая программа
OUTPUT2 = server
OUTPUT3 = mim

LIBS = -lssl -lcrypto -lm  # библиотеки: openssl (3.0 или старше!), libcrypto, lm (для math.h)

$(OBJECTS): obj/%.o  : src/%.c $(HEADERS)  # компиляция
	gcc $(CFLAGS) -I include -c  $< -o $@

$(OUTPUT1): obj $(OBJECTS1)  # этап линковки в единую программу client
	gcc $(CFLAGS) -I include -o $@ $(OBJECTS1) $(LIBS)

$(OUTPUT2): obj $(OBJECTS2)  # этап линковки в единую программу server
	gcc $(CFLAGS) -I include -o $@ $(OBJECTS2) $(LIBS)

$(OUTPUT3): obj $(OBJECTS3)  # этап линковки в единую программу mim
	gcc $(CFLAGS) -I include -o $@ $(OBJECTS3) $(LIBS)

project:
	make client
	make server
	make mim

obj: 
	mkdir -p obj

clean:
	rm -rf obj
	rm -f $(OUTPUT1)
	rm -f $(OUTPUT2)
	rm -f $(OUTPUT3)

cert_server:
	openssl genpkey -algorithm "Ed25519" -out "server_private.key"
	openssl req -new -x509 -days "365" -key "server_private.key" -out "server_cert.pem" -subj "/C=RU/L=SPb/O=SPbU/CN=spbu.ru" -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -addext "extendedKeyUsage = serverAuth, clientAuth"

cert_mim:
	openssl genpkey -algorithm "Ed25519" -out "mim_private.key"
	openssl req -new -x509 -days "365" -key "mim_private.key" -out "mim_cert.pem" -subj "/C=RU/L=SPb/O=SPbU/CN=spbu.ru" -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -addext "extendedKeyUsage = serverAuth, clientAuth"

# команды:
# make client - сборка программы клиента
# make server - сборка программы сервера
# make mim - сборка программы mim, реализующей атаку Man-in-the-middle
# make cert_server - получение (генерация) закрытого ключа и сертификата сервера
# make cert_mim - для mim