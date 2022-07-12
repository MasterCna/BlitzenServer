#include <iostream> // cout, endl
#include <ctime> // time
#include <iterator> // advance
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "wsconnection.hpp"
pthread_t threads[5];

pthread_t g_last_thread;
std::vector<handler> g_vPingHandlers;
struct SPingerData *spd = (struct SPingerData *)malloc(sizeof(struct SPingerData));
server session;
bool g_pingEnabled = false;
std::map<handler, User, std::owner_less<handler>> user_queue;

#ifdef WEB_SOCKET_WITH_TLS 

context_ptr WSConnection::on_tls_init(websocketpp::connection_hdl hdl) {
          namespace asio = websocketpp::lib::asio;
     
    //      std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << "\n";
     //     std::cout << "using TLS mode: " <<  "Mozilla Intermediate" << "\n";
      
          context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);
      
          try {
                 ctx->set_options(asio::ssl::context::default_workarounds |
                                  asio::ssl::context::no_sslv2 |
                                  asio::ssl::context::no_sslv3 |
                                  asio::ssl::context::single_dh_use);
             
             ctx->set_password_callback(bind(&get_password));
             ctx->use_certificate_chain_file("server.pem");
             ctx->use_private_key_file("server.pem", asio::ssl::context::pem);
     
             // Example method of generating this file:
             // `openssl dhparam -out dh.pem 2048`
             // Mozilla Intermediate suggests 1024 as the minimum size to use
             // Mozilla Modern suggests 2048 as the minimum size to use.
             ctx->use_tmp_dh_file("dh.pem");
     
             std::string ciphers;
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
		if (SSL_CTX_set_cipher_list(ctx->native_handle() , ciphers.c_str()) != 1) {
                	 std::cout << "Error setting cipher list" << "\n";
             	}
         } catch (std::exception& e) {
             std::cout << "Exception: " << e.what() << "\n";
         }
         return ctx;
}

#endif 

WSConnection& WSConnection::create_instance(in_port_t port) {
    static WSConnection single(port);
    return single;
}

WSConnection::WSConnection(in_port_t iport): port{iport} {
    session.clear_access_channels(websocketpp::log::alevel::all);

    session.set_error_channels(websocketpp::log::elevel::all);
    session.set_access_channels(websocketpp::log::alevel::all);

    session.init_asio();

    session.set_message_handler(
        std::bind(
            &WSConnection::message_handler, this,
            std::placeholders::_1, std::placeholders::_2
        )
    );
    session.set_open_handler(
        std::bind(
            &WSConnection::open_handler, this,
            std::placeholders::_1
        )
    );
    session.set_close_handler(
        std::bind(
            &WSConnection::close_handler, this,
            std::placeholders::_1
        )
    );
    session.set_validate_handler(
        std::bind(
            &WSConnection::validate_handler, this,
            std::placeholders::_1
        )
    );
	
    session.set_ping_handler(
		std::bind(
		&WSConnection::ping_handler, this,
            std::placeholders::_1, std::placeholders::_2
		)
	);

    session.set_pong_handler(
		std::bind(
			&WSConnection::pong_handler, this,
            std::placeholders::_1, std::placeholders::_2
		)
	);
	
	session.set_pong_timeout_handler(
        std::bind(
            &WSConnection::pong_timeout_handler, this,
            std::placeholders::_1, std::placeholders::_2
        )
    );

    session.set_pong_timeout(5000);

#ifdef WEB_SOCKET_WITH_TLS
    /*
     * start
    */
    session.set_tls_init_handler(std::bind(&WSConnection::on_tls_init, this, std::placeholders::_1));
    /*
     * end
    */
#endif
    std::FILE* const schema = fopen("engine/schema.json", "r");
    char schema_buffer[4096];

    if (!schema) {
        throw("failed to open schema file");
    }

    FileReadStream file_stream(schema, schema_buffer, sizeof(schema_buffer));
    json_schema.ParseStream(file_stream);
    if (json_schema.HasParseError()) {
        throw("failed to parse schema file");
    }

    if (schema) {
        fclose(schema);
    }
}

void *ping_client(void *input)
 {
   websocketpp::lib::error_code ec;
    try
    {
        while(1)
        {
            sleep(10);
            std::map<handler, User, std::owner_less<handler>>::iterator it;

            for(it = user_queue.begin(); it != user_queue.end(); it++)
            {
               if((it->second).type == user_type::client)
               {
                    std::cout << "\nPining client " << (it->second).id << "\n";
                    session.ping((it->second).handler, "PING", ec);
               }
                
            }
        
        }
    }
    catch(std::exception e)
    {
    }

    pthread_exit(NULL);
}

void WSConnection::run() {
    
    // note: check for port availability
    std::cout << "listening on port " << port << "\n";
    session.set_reuse_addr(true);	
    // log: listening
    session.listen(websocketpp::lib::asio::ip::tcp::v4(), port);
    
    session.start_accept();
    session.run();
    
 
   
  
    

}



void WSConnection::message_handler(handler hdl, server::message_ptr message) 
{
    
 // std::cout << "LOGGING ... (message_handler) " << "Message payload = " << message->get_payload() << "\n";
  if (!validate_json(message)) { 
	warn_invalid(hdl); 
	return; 
  }
          std::cout << "\nINSIDE USER EXIT 1\n";
    std::string msg = message->get_payload();
    
	//std::cout << "LOGGING ... (message_handler) " << "original message: "  << msg << '\n';
	
	if (msg.empty()) { warn_invalid(hdl); return; }

    Document document;
    document.Parse(msg.c_str());
    Value requestid;
    std::string json;
    int responseid;
    int random;
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
std::cout << "\nINSIDE USER EXIT 2\n";
    if (document.HasParseError()) { warn_invalid(hdl); return; }

    const std::string category = document["category"].GetString();


    const std::string rawtype = document["usertype"].GetString();


    const std::string userid = document["userid"].GetString();
std::cout << "\nINSIDE USER EXIT 3\n";
    const user_type usertype = get_user_type(rawtype.c_str());
    User user(usertype, userid, hdl);
    document.RemoveMember("usertype");
std::cout << "\nINSIDE USER EXIT 4\n";

    if ("authorize" == category) {

           
         authorize_user(user); return;
     }
//    if (!user_exists(user)) { warn_unauthorized(hdl); return; }

    if (user_type::panel == usertype) {
        if (!document.HasMember("targetid")) { warn_invalid(hdl); return; }
        document.RemoveMember("userid");
        std::string targetid = document["targetid"].GetString();
        User target(user_type::client, targetid, hdl);
        random = generate_id();
        requestid.SetInt(random);
        panel_requests.insert(pair<int, std::string>(random, userid));
        document.AddMember("reqid", requestid, document.GetAllocator());
        document.Accept(writer);
        json = buffer.GetString();
  
        if (user_exists(target)) {
            User client = find_user(target);
            session.send(client.handler, json, websocketpp::frame::opcode::text);
        }
        else {
	  		// fixme: wrong error handling
	  		warn_invalid(hdl, invalid_error::nouser);
		}
    }
    else if (user_type::client == usertype) {
        if (!document.HasMember("reqid")) { warn_invalid(hdl); return; }
        if (!document["reqid"].IsInt()) { warn_invalid(hdl); return; }
std::cout << "\nINSIDE USER EXIT 7n";
        responseid = document["reqid"].GetInt();
        document.RemoveMember("reqid");
        document.Accept(writer);
        json = buffer.GetString();
        if ("basicinfo" == category) {
            broadcast(user_type::panel, json);
        } 
        else if (validate_request(responseid)) {
            std::string panelid = panel_requests[responseid];
            User panel(user_type::panel, panelid, hdl);
            User target = find_user(panel);
            std::cout << "\nINSIDE USER EXIT 8\n";
            session.send(target.handler, json, websocketpp::frame::opcode::text);
            std::cout << "\nINSIDE USER EXIT 9\n";
        }
        else { warn_invalid(hdl); }
    }
    else if (user_type::server == usertype) {
        warn_invalid(hdl);
    }
    else if (user_type::none == usertype) {
        warn_invalid(hdl);
    }
}

User WSConnection::find_user(const User& user) {
    User target;
    for (std::map<handler, User>::const_iterator candidate = user_queue.cbegin();
        candidate != user_queue.cend(); ++candidate) {
        if ((user.type == (candidate->second).type) && (user.id == (candidate->second).id)) {
            target = candidate->second;
        }
    }
    return target;
}

bool WSConnection::user_exists(const User& user) {
    bool presence = false;
    for (std::map<handler, User>::const_iterator candidate = user_queue.cbegin();
        candidate != user_queue.cend(); ++candidate) {
        if ((user.type == (candidate->second).type) && (user.id == (candidate->second).id)) {
            return true;
        }
    }
    return presence;
}

bool WSConnection::validate_request(const int& reqid) {
    std::map<int, std::string>::const_iterator request = panel_requests.find(reqid);
    return (request != panel_requests.cend()) ? true : false;
}

void WSConnection::warn_invalid(handler hdl, invalid_error erre) {
  std::string message{};

  //using namespace std::string_literals;
  
  switch(erre) {
  case invalid_error::invalidmsg:
    message = "invalid message";
    break;
  case invalid_error::nouser:
    message = "no such user";
    break;
  default:
    break;
  }
  
  session.send(hdl, message, websocketpp::frame::opcode::text);
}

/*
void WSConnection::warn_unauthorized(handler hdl) {
    const std::string message{"unauthorized access"};
    session.send(hdl, message, websocketpp::frame::opcode::text);
}
*/

bool WSConnection::validate_json(server::message_ptr raw_msg) {

    std::string json = raw_msg->get_payload();
    SchemaDocument doc(json_schema);
    SchemaValidator validator(doc);
    Reader reader;
    StringStream json_stream(json.c_str());


	//std::cout << "Before Json validation ... " << '\n';
    if (!reader.Parse(json_stream, validator)) {
		
	//	std::cout << "Inside Json validation ... " << '\n';
        // log: invalid json strucure
   //   std::cout << "invalid json structure" << "\n";
        return false;
    }

	//std::cout << "After Json validation ... " << '\n';
    /// std::cout << validator.GetInvalidSchemaKeyword() << "\n"; // BIG PROBLEM!!!!!
    
    if (validator.IsValid()) {
//		std::cout << "Jason is valid." << '\n';
        return true;
    }
    else {
        // log: invalid json strucure
//		std::cout << "Jason is INVALID." << '\n';
        return false;
    }
}

int WSConnection::generate_id() {
    // note: generate random id by std::urand
    srand(std::time(NULL));
    return (rand() % 100000) + 1;
}

std::string WSConnection::restore_session() {
    Document doc;
    Value object(kObjectType);
    Value clients_array(kArrayType);
    Document::AllocatorType& allocator = doc.GetAllocator();

    for (std::map<handler, User>::const_iterator user = user_queue.cbegin();
        user != user_queue.cend(); ++user) {
        if ((user->second).type == user_type::client) {
            Value client_id(kStringType);
            client_id.SetString((user->second).id.c_str(), (user->second).id.length(), allocator);
            clients_array.PushBack(client_id, allocator);
        }
    }

    object.AddMember("category", "onlineclients", allocator);
    object.AddMember("clients", clients_array, allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    object.Accept(writer);
    return buffer.GetString();
}

bool WSConnection::validate_handler(handler vhdl) 
{ 
	return true;
#ifdef NEVER_DEF
	websocketpp::server<websocketpp::config::asio_tls>::connection_ptr con = session.get_con_from_hdl(vhdl);
	auto& subp_requests = con->get_requested_subprotocols();

	for (const auto& elem : subp_requests) {
//		std::cout << "Requested: " << elem << "\n";
	}

	websocketpp::uri_ptr uri = con->get_uri();
	std::string s = con->get_request_header("Authorization");
	if (s.empty())
		return false;
    std::string query = uri->get_query(); // returns empty string if no query string set.
//	std::cout << "query: " << query << '\n';
    if (!query.empty()) {
        // Split the query parameter string here, if desired.
        // We assume we extracted a string called 'id' here.
		return true;
    }
	else
		return false;
#endif // NEVER_DEF
}

void WSConnection::open_handler(handler hdl) 
{
	
}

void WSConnection::close_handler(handler hdl) {

    std::map<handler, User>::const_iterator user = user_queue.find(hdl);
    if (user != user_queue.cend()) {
        if (user_type::client == (user->second).type) {
            broadcast(user_type::panel, client_leaves(user->second));
        }
        user_queue.erase(hdl);
//        reverse_queue.erase(hdl);
    }

	
/*
    // log: closing connection
    std::multiset<handler, std::owner_less<handler>> handler_queue;
    for_each (user_queue.cbegin(), user_queue.cend(),
        [&](const User user) { handler_queue.insert(user.handler); }
    );
    size_t index = std::distance(handler_queue.cbegin(), handler_queue.find(hdl));
    if (index > user_queue.size()) {
        std::cout << index << std::endl;
        throw ("index points to invalid address");
    }

    std::multiset<User>::iterator element = user_queue.begin();
    if (index > 0) { std::advance(element, index); }
    std::multiset<User>::const_iterator position = user_queue.find(*element);
    if (position != user_queue.cend()) {
        broadcast(user_type::panel, client_leaves(*position));
        user_queue.erase(*position);
    }
    else if (user_type::client == element->type) {
        std::cout << "unknown user left" << std:: endl;
    }
    // log: client removed from the queue
*/
}

void WSConnection::pong_timeout_handler(handler hdl, std::string payload) {
	std::map<handler, User>::const_iterator user = user_queue.find(hdl);
    

  if (user != user_queue.cend()) {
        if (user_type::client == (user->second).type) {
            broadcast(user_type::panel, client_timeout(user->second));
        }
       // pthread_cancel(g_last_thread);
        user_queue.erase(hdl);
    }

    
	else
    {
        // std::cout << "--------------------pong time out by end iterator!" << "\n";
    }
}


void WSConnection::pong_handler(handler hdl, std::string payload) {
    std::cout << "----------------------------------------------------------pong handler: " << payload << "\n";
}

bool WSConnection::ping_handler(handler hdl, std::string payload) {
    std::cout << "----------------------------------------------------------ping handler: " << payload << "\n";
	return true;
}
 
user_type WSConnection::get_user_type(const std::string& utype) {
    if ("panel" == utype) {
       
        return user_type::panel;
    }
    else if ("client" == utype) {
        return user_type::client;
    }
    else if ("server" == utype) {
        return user_type::server;
    }
    else {
        return user_type::none;
    }
}

std::string WSConnection::get_user_type(const user_type& utype) {
    if (user_type::panel == utype) {
        return "panel";
    }
    else if (user_type::client == utype) {
        return "client";
    }
    else if (user_type::server == utype) {
        return "server";
    }
    else {
        return "none";
    }
}

void WSConnection::broadcast(const user_type receivers, const std::string& data) {
    for (std::map<handler, User>::const_iterator user = user_queue.cbegin();
        user != user_queue.cend(); ++user) {
        if (receivers == (user->second).type) {
            session.send((user->second).handler, data, websocketpp::frame::opcode::text);
        }
    }
}

std::string WSConnection::client_leaves(const User& user) {
    Document document;
    Document::AllocatorType& allocator = document.GetAllocator();

    document.SetObject();
    Value clientid(kStringType);
    if (user.id.empty()) {
        const std::string noclient{"0"};
        clientid.SetString(noclient.c_str(), noclient.length(), allocator);
    }
    else {
        clientid.SetString(user.id.c_str(), user.id.length(), allocator);
    }

    document.AddMember("category", "clientleaves", allocator);
    document.AddMember("clientid", clientid, allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    document.Accept(writer);

    return buffer.GetString();
}

std::string WSConnection::client_join(std::string userid) {

    Document document;
    Document::AllocatorType& allocator = document.GetAllocator();

    document.SetObject();
  Value clientid(kStringType);
     clientid.SetString(userid.c_str(), userid.length(), allocator);
    document.AddMember("category", "clientjoin", allocator);
    document.AddMember("clientid", clientid, allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    document.Accept(writer);

    return buffer.GetString();
}

std::string WSConnection::client_timeout(const User& user) {
  Document document;
    Document::AllocatorType& allocator = document.GetAllocator();

    document.SetObject();
    Value clientid(kStringType);
    if (user.id.empty()) {
        const std::string noclient{"0"};
        clientid.SetString(noclient.c_str(), noclient.length(), allocator);
    }
    else {
        clientid.SetString(user.id.c_str(), user.id.length(), allocator);
    }

    document.AddMember("category", "client_timeout", allocator);
    document.AddMember("clientid", clientid, allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    document.Accept(writer);

    return buffer.GetString();
}

void WSConnection::authorize_user(const User& user) {
//    if (user_exists(user)) { warn_occupied(user.handler); return; }

    switch (user.type) {
    case user_type::panel:
        session.send(user.handler, restore_session(), websocketpp::frame::opcode::text);
        break;
    case user_type::client:
    {
        // Broadcast to panels
        broadcast(user_type::panel, client_join(user.id.c_str()));
    }
    
        break;
    case user_type::server:
        break;
    case user_type::none:
        break;
    default:
        break;
    }

    if (!user_exists(user)) {

        user_queue.insert(pair<handler, User>(user.handler, user));
          
         if(!g_pingEnabled)
         {
             pthread_t threadID;
             pthread_create(&threadID, NULL, ping_client, NULL);
             g_last_thread = threadID;
             g_pingEnabled = true;
         }

//        reverse_queue.insert(std::pair<handler, User>(user.handler, user));

    }
}

