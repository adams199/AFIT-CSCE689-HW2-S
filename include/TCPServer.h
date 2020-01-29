#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <list>
#include <memory>
#include <fstream>
#include "Server.h"
#include "FileDesc.h"
#include "TCPConn.h"

class TCPServer : public Server 
{
public:
   TCPServer();
   ~TCPServer();

   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();

   bool inWhitelist(std::string &ip_addr);

   void logMsg(std::string &Msg);

private:
   // Class to manage the server socket
   SocketFD _sockfd;

   // log file ofstream
   std::ofstream _server_log;
 
   // List of TCPConn objects to manage connections
   std::list<std::unique_ptr<TCPConn>> _connlist;
};


#endif
