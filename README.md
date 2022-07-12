# RLC Project


## Architecture

There are 3 endpoints in the architecture. 

* panel: gateway to give user the ability of controling user's device.
* server: controllers bidirectional requests and responses from/to panel and client.
* client: the agent sitting in user's system and responses to server requests.

Each component is connected to the adjacent endpoint through websocket protocol, RFC 6455. 


## Compile & Run

    sudo ./configure
    make
    ./wserver 4000
