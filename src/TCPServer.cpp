#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <strings.h>
#include <vector>
#include <iostream>
#include <memory>
#include <sstream>
#include <chrono>
#include "TCPServer.h"

TCPServer::TCPServer(){
   _server_log.open("server.log");
}


TCPServer::~TCPServer() {
   _server_log.close();
}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   struct sockaddr_in servaddr;

   std::string s("Server started.");
   logMsg(s);

   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::listenSvr() {

   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;
   int num_read = 0;

   // Start the server socket listening
   _sockfd.listenFD(5);

    
   while (online) {
      struct sockaddr_in cliaddr;
      socklen_t len = sizeof(cliaddr);

      if (_sockfd.hasData()) {
         TCPConn *new_conn = new TCPConn();
         if (!new_conn->accept(_sockfd)) {
            // _server_log.strerrLog("Data received on socket but failed to accept.");
            continue;
         }

         // Get their IP Address string to use in logging
         std::string ipaddr_str;
         new_conn->getIPAddrStr(ipaddr_str);
         if (!inWhitelist(ipaddr_str))
         {
            new_conn->sendText("This IP is not recognized by the whitelist.\n");
            new_conn->disconnect();
            logMsg(ipaddr_str += " not found. Disconnecting.");
         }
         
         else
         {
            std::cout << "***Got a connection***\n";

            _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));

            logMsg(ipaddr_str += " found. Connecting.");

            new_conn->sendText("Welcome to the CSCE 689 Server!\n");

            new_conn->startAuthentication();
            int test = new_conn->handleConnection();

            // log appropriately
            if (test == -1)
            {
               std::string ip, username(new_conn->getUsernameStr());
               new_conn->getIPAddrStr(ip);
               std::string msg = "Username: " + username + " with IP: " + ip + " not recognized.";
               logMsg(msg);
            }
            else if (test == -2)
            {
               std::string ip, username(new_conn->getUsernameStr());
               new_conn->getIPAddrStr(ip);
               std::string msg = "Username: " + username + " with IP: " + ip + " failed to enter password correctly.";
               logMsg(msg);
            }
            else
            {
               std::string ip, username(new_conn->getUsernameStr());
               new_conn->getIPAddrStr(ip);
               std::string msg = "Username: " + username + " with IP: " + ip + " logged in successfully.";
               logMsg(msg);            
            }
            

         }
      }

      // Loop through our connections, handling them
      std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
      while (tptr != _connlist.end())
      {
         // If the user lost connection
         if (!(*tptr)->isConnected()) {

            // Log it
            std::string ip, username((*tptr)->getUsernameStr());
            ((*tptr)->getIPAddrStr(ip));
            std::string msg = "Username: " + username + " with IP: " + ip + " disconnected.";
            logMsg(msg);
            

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue;
         }

         // Process any user inputs
         (*tptr)->handleConnection();

         // Increment our iterator
         tptr++;
      }

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   }
}


/**********************************************************************************************
 * inWhitelist - returns true if the ip_addr is in the whitelist, else false
 *
 **********************************************************************************************/

bool TCPServer::inWhitelist(std::string &ip_addr)
{
   /* Given class fd file cannot handle certain cases, lets use an fstream...

   // create the whitelist file FD and attempt to open
   FileFD* _whitelist = new FileFD("whitelist");
   if (!_whitelist->openFile(FileFD::fd_file_type::readfd))
         std::cout << "Could not open whitelist\n";

   // read all the lines from the whitelist and attempt to match to ip_addr
   std::string readIP;
   int moreLines = 0;
   while (moreLines != -1)
   {
      moreLines = _whitelist->readStr(readIP);
      if (readIP == ip_addr)
         return true;
   }
   return false; */

   // create the whitelist file FD and attempt to open
   std::ifstream whiteFile("whitelist");
   if(!whiteFile.is_open())
      std::cout << "Could not open whitelist\n";

   // read all the lines from the whitelist and attempt to match to ip_addr
   char readIP[20];
   while (!whiteFile.eof())
   {
      whiteFile.getline(readIP, 20);
      if (readIP == ip_addr)
         return true;
   }
   return false;

}


/**********************************************************************************************
 * logMsg - logs the message with the time stamp
 *
 **********************************************************************************************/
void TCPServer::logMsg(std::string &Msg)
{
   auto time = std::chrono::system_clock::now();
   std::time_t time_now = std::chrono::system_clock::to_time_t(time);
   _server_log << Msg << " " << std::ctime(&time_now)  << "\n";
   _server_log.flush();
}



/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {

   _sockfd.closeFD();
}


