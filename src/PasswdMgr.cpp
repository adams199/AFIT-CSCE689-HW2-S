#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <fstream>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> hash, salt;

   bool result = findUser(name, hash, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> hash, salt; // hash derived from the parameter passwd

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;
       
   hashArgon2(hash, passwd, salt);

   if (userhash == hash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {

   // great c classes are wrapped in weird custom classes not allowing reusibility
   std::fstream pwFile(_pwd_file.c_str());
   std::string uname;
   std::vector<uint8_t> newHash, oldSalt;
   
   getline(pwFile, uname);
   while(uname != "")
   {
      if (!uname.compare(name))
      {
         char hash[hashlen], salt[saltlen];
         int pos = pwFile.tellg();

         // read in the old hash and salt
         pwFile.read(hash, hashlen);
         pwFile.read(salt, saltlen);
         for(int i = 0; i < saltlen; i++)
            oldSalt.push_back(salt[i]);

         // make a new hash
         hashArgon2(newHash, passwd, oldSalt);
         for(int i = 0; i < hashlen; i++)
            hash[i] = newHash.at(i);
         
         // write over the old hash
         pwFile.seekg(pos);
         pwFile.write(hash, 32);
         pwFile.close();
         return true;
      }
      else
         getline(pwFile, uname);
   }
   return false;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   if((pwfile.readStr(name)) <= 0)
      return false;

   if((pwfile.readBytes(hash, hashlen)) == -1)
      return false;

   if((pwfile.readBytes(salt, saltlen)) == -1)
      return false;

   unsigned char temp; // read in last \n
   if((pwfile.readByte(temp)) == -1)
      return false;

   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   results += pwfile.writeFD(name);
   results += pwfile.writeByte('\n');
   results += pwfile.writeBytes(hash);
   results += pwfile.writeBytes(salt);
   results += pwfile.writeByte('\n');

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, const char *in_passwd, std::vector<uint8_t> &in_salt) {
   
   uint8_t hash[hashlen], salt[saltlen];
   uint32_t pwdlen = strlen(in_passwd);
   for(int i = 0; i < saltlen; i++)
      salt[i] = in_salt.at(i);

   uint32_t t_cost = 2;            // 1-pass computation
   uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
   uint32_t parallelism = 1;       // number of threads and lanes
   argon2i_hash_raw(t_cost, m_cost, parallelism, in_passwd, pwdlen, salt, saltlen, hash, hashlen);

   for(int i = 0; i < hashlen; i++)
      ret_hash.push_back(hash[i]);

}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   std::vector<uint8_t> hash, salt;

   if(findUser(name, hash, salt))
      return;

   salt.clear();
   hash.clear();

   FileFD pwfile(_pwd_file.c_str());
   if (!pwfile.openFile(FileFD::appendfd))
      throw pwfile_error("Could not open passwd file for appending");
   

   // if need to add, need to generate unique salt for user.
   srand(time(NULL));
   for(int i = 0; i < saltlen; i++)
      salt.push_back((rand() % (125-33)) + 33);

   hashArgon2(hash, passwd, salt);

   std::string sname = name;
   writeUser(pwfile, sname, hash, salt);

   pwfile.closeFD();

}

