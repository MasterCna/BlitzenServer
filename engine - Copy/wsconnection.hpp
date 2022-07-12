#ifndef __WS_H__
#define __WS_H__

#define WEB_SOCKET_WITH_TLS 1
#undef WEB_SOCKET_WITH_TLS
#ifndef WEB_SOCKET_WITH_TLS
#include <websocketpp/config/asio_no_tls.hpp>
#endif
#include <websocketpp/server.hpp>
#include <websocketpp/http/request.hpp>
#include <websocketpp/connection.hpp>
#ifdef WEB_SOCKET_WITH_TLS

#include <websocketpp/config/asio.hpp>

#endif
#include <set>
#include <map>
#include <vector>
#include "messagehandler.hpp"

typedef websocketpp::connection_hdl handler;
#ifndef WEB_SOCKET_WITH_TLS
typedef websocketpp::server<websocketpp::config::asio> server;

#else
 typedef websocketpp::server<websocketpp::config::asio_tls> server;

 typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;


#endif

enum class user_type { none, panel, client, server };
enum class invalid_error { nouser, invalidmsg };

struct SPingerData
{
    int thread_id;
   std::map<std::string, handler> m_ping_Handlers;
};

struct User {
    User() {};
    User(user_type usertype, std::string userid, handler hdl):
        type{usertype}, id{userid}, handler{hdl} {};

    User& operator= (const User& user) {
        if (this != &user) {
            this->id = user.id;
            this->type = user.type;
            this->handler = user.handler;
        }
        return *this;
    }

    std::string id;
    user_type type;
    handler handler;
};

struct ascending {
    bool operator() (const User& luser, const User& ruser) {
        return (luser.id < ruser.id);
    }
};

class WSConnection
{
public:
    static WSConnection& create_instance(in_port_t port);
    ~WSConnection() {};
    void run();
    int generate_id();
    std::string restore_session();
    void open_handler(handler hdl);
    void close_handler(handler hdl);
    void warn_invalid(handler userid, invalid_error erre = invalid_error::invalidmsg);
    User find_user(const User& client);
    bool user_exists(const User& user);
    bool validate_handler(handler vhdl);
    void authorize_user(const User& user);
    std::string client_leaves(const User& user);
    std::string client_join(std::string userid);
    std::string client_timeout(const User& user);
    bool validate_request(const int& requestid);
    bool validate_json(server::message_ptr raw_msg);
    user_type get_user_type(const std::string& utype);
	std::string get_user_type(const user_type& utype);
    void pong_timeout_handler(handler hdl, std::string payload);
    
	/*
     * start
    */
	void pong_handler(handler hdl, std::string payload);
	/*
     * end
	*/

	/*
     * start
    */
	bool ping_handler(handler hdl, std::string payload);
	/*
     * end
	*/

    void message_handler(handler hdl, server::message_ptr raw_msg);
    void broadcast(const user_type receivers, const std::string& data);

   
#ifdef WEB_SOCKET_WITH_TLS    
	/*
     * start
    */
    context_ptr on_tls_init(websocketpp::connection_hdl hdl);
    /*
     * end
    */
#endif 
private:
    Document json_schema;
    unsigned int port = 0;
    

    WSConnection(in_port_t iport);
    WSConnection(const WSConnection& copy);
    WSConnection& operator= (const WSConnection& assign);

    message_map client_requests;
    std::map<int, std::string> panel_requests;

    
    
//    std::set<handler, std::owner_less<handler>> reverse_queue;
//    std::set<handler> panel_rev_queue;
};

#endif
