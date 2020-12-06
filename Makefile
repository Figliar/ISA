isabot: isabot.o almost_json_pars.o
	g++ -Wall -w -g -o isabot isabot.o almost_json_pars.o -lssl -lcrypto

isabot.o: isabot.cpp almost_json_pars.h
	g++ -Wall -w -g -c isabot.cpp

almost_json_pars.o: almost_json_pars.cpp almost_json_pars.h
	g++ -Wall -g -c almost_json_pars.cpp

clean :
	\rm -fr isabot isabot.o almost_json_pars.o

.PHONY: test

test:
	./arguments_test