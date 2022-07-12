server: engine/server.cpp engine/wsconnection.cpp engine/wsconnection.hpp
	clang++ -std=c++11 -lboost_system -lssl -lpthread -lcrypto -I./websocketpp -I./rapidjson/include -I/usr/local/include -o server engine/server.cpp engine/wsconnection.cpp -fpermissive

debug: engine/server.cpp engine/wsconnection.cpp engine/wsconnection.hpp
	clang++ -std=c++11 -g -v -lboost_system -I./websocketpp -I./rapidjson/include -I/usr/local/include -o server engine/server.cpp engine/wsconnection.cpp

clean:
	rm -f server
