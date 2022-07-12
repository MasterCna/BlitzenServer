#ifdef _WIN32
    #define _SCL_SECURE_NO_WARNINGS
#endif

#include <iostream> // cout, endl
#include <exception> // exception

#include "messagehandler.hpp"
#include "wsconnection.hpp"

using namespace std;
using namespace rapidjson;

int main(int argc, char* argv[])
{
    if (argc > 2) {
        std::cout << "usage: " << argv[0] << " <port>" << "\n";
        return 1;
    }
#ifdef WEB_SOCKET_WITH_TLS

    std::cout << "TLS-based Web Socket\n";

#endif
    in_port_t port = 4000;

    if (argc == 2) {
        port = std::stoi(argv[1]);
    }

    try 
    {
        WSConnection& conn = WSConnection::create_instance(port);
        conn.run();
    }
    catch (const char* exp) {
        std::cout << exp <<"\n";
    }
    catch (std::exception& exp) {
        std::cout << exp.what() << "\n";
    }
    catch (...) {
        std::cout << "operation failed, exiting..." << "\n";
    }

    return 0;
}

