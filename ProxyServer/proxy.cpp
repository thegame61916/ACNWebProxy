//Name: MOHIT SHARMA
//ROLL NO.: 201505508

#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <map>
#include <pthread.h>
#include <fstream>
#include <sys/stat.h>

using namespace std;


map<string, string> cache;
char dummy[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
char proxyOverloaded[] = "HTTP/1.1 503 too many requests for proxy.\r\n\r\n";
pthread_mutex_t lock;

#define MAX_DATA_SIZE 1000000
#define MAX_LISTEN_SIZE 300

sockaddr_in parsePortHostToHit(char *buffer, int *portToHit)
{
	char hostName[60] = {0};
	char port[6] = {0};	
	int i = 0;
	struct sockaddr_in hostToHit_addr;
	*portToHit = 80;
	struct hostent* host = NULL;	
	char *t = strstr(buffer, "Host: ") + 6;
	if(strstr(buffer,"iiit.ac.in"))
	{
		while(t && *t !='\r' && *t !='\n')
		{
			if(t && *t == ':')
			{
				t++;
				break;
			}
			hostName[i] = *t;
			i++;
			t++;
		}
		i = 0;
		while(t && *t !='\r' && *t !='\n')
		{
			port[i] = *t;
			i++;
			t++;
		}
		if(*port != '\0')
			*portToHit = atoi(port);
		if((host=gethostbyname(hostName)) == NULL)
		{
			printf("Hostname %s doesn't exist.\n", hostName);
			return hostToHit_addr;
		}
	}
	else
	{
		if((host=gethostbyname("proxy.iiit.ac.in")) == NULL)
		{
			printf("Hostname proxy.iiit.ac.in doesn't exist.\n");
			return hostToHit_addr;
		}
		*portToHit = 8080;
	}
	bzero((char*)&hostToHit_addr,sizeof(hostToHit_addr));
	hostToHit_addr.sin_port = htons(*portToHit);
	hostToHit_addr.sin_family=AF_INET;
	bcopy((char*)host->h_addr, (char*)&hostToHit_addr.sin_addr.s_addr, host->h_length);
	return hostToHit_addr;

}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(ctx);
}


void addToCache(string url, string resp)
{
	pthread_mutex_lock(&lock);
		string check = "200 OK";
		std::size_t success = resp.find("200 OK");
    	std::size_t html = resp.find("</html>");
    	std::size_t no_cache = resp.find("Cache-Control: no-cache");
    	std::size_t privat = resp.find("Cache-Control: private");
	  	if (success!=std::string::npos 
	  		&& html!=std::string::npos
	  		&& no_cache==std::string::npos 
	  		&& privat==std::string::npos)
	  	{
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!adding to cache: %s\n", url.c_str());
	  		cache[url] = resp;
	  	}
  	pthread_mutex_unlock(&lock);
}

string getURL(char *buffer)
{
	char t1[10], u[60], t2[500];
	sscanf(buffer,"%s %s %s",t1, u, t2);
	return string(u);
}

void normalRecv(int cf, int sf, char *msg)
{
	string url = getURL(msg);
	string response = "";
	if(cache.find(url) != cache.end())
	{
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!1Returning from cache:%s \n", cache[url].c_str());
		if(send(cf, cache[url].c_str(), cache[url].length(), 0) < 0)
		{
			printf("Unable to send msg to server.\n");
		}
		return;
	}
	while(1)
	{
		if(send(sf, msg, strlen(msg), 0) < 0)
		{
			printf("Unable to send msg to server.\n");
			return;
		}
		memset(msg,0, MAX_DATA_SIZE);
		response = "";
		while(recv(sf, msg, MAX_DATA_SIZE - 2, 0)>0)
		{
			response = response + string(msg);
			memset(msg,0, MAX_DATA_SIZE);
		}
		//printf("%s\n", response.c_str());
		addToCache(url, response);
		if(response.length() <=2)
			return;
		
		if(send(cf, response.c_str(), response.length(), 0) < 0)
		{
			printf("Unable to send msg to server.\n");
			return;
		}
		memset(msg,0, MAX_DATA_SIZE);
		if(recv(cf, msg, MAX_DATA_SIZE - 2, 0) <= 0)
		{
			printf("Unable to receive from client.\n");
			return;
		}
	}
}

void withSslRecv(SSL *connc, SSL *conns, char *msg)
{
	string response = "";
	string url = getURL(msg);
	if(cache.find(url) != cache.end())
	{
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Returning from cache:%s \n", url.c_str());
		if(SSL_write(connc, cache[url].c_str(), cache[url].length()) < 0)
		{
			printf("Unable to send msg to client.\n");
		}
		return;
	}
	while(1)
	{
		memset(msg,0, MAX_DATA_SIZE);
		if(SSL_read(connc, msg, MAX_DATA_SIZE - 2)<=0)
		{
			printf("Unable to receive from client.\n");
			return;
		}

		if(SSL_write(conns, msg, strlen(msg)) < 0)
		{
			printf("Unable to send msg to server.\n");
			return;
		}
		memset(msg,0, MAX_DATA_SIZE);
		response = "";
		while(SSL_read(conns, msg, MAX_DATA_SIZE - 2)>0)
		{
			response = response + string(msg);
			memset(msg,0, MAX_DATA_SIZE);
		}
		//printf("%s\n", response.c_str());
		addToCache(url, response);
		if(response.length() <= 2)
			return;
		
		if(SSL_write(connc, response.c_str(), response.length()) < 0)
		{
			printf("Unable to send msg to client.\n");
			return;
		}
	}
}

void *serveRequest(void *data)
{
	int serverSockFd = -1;
	string resp = "";
	int clientSockFd = *((int*)data);
	char msg[MAX_DATA_SIZE] = {0};
	int portToHit;
	memset(msg,0, MAX_DATA_SIZE);
   	while((recv(clientSockFd, msg, MAX_DATA_SIZE - 2, 0)) > 0)
	{
		resp = resp + string(msg);
		if(strstr(resp.c_str(), "\r\n\r\n"))
			break;
	}
	if(resp.length()<=2)
	{
		printf("Unable to recieve from browser.");
		return NULL;
	}
	memset(msg, 0, MAX_DATA_SIZE);
	strcpy(msg, resp.c_str());

	struct sockaddr_in hostToHit_addr = parsePortHostToHit(msg, &portToHit);

	if((serverSockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Unable to create the socket.\n");
		close(clientSockFd);
		return NULL;
	}
	if(connect(serverSockFd, (struct sockaddr*)&hostToHit_addr, sizeof(hostToHit_addr)) < 0)
   	{
	  		printf("Not able to connect to server.\n");
	  		close(clientSockFd);
	  		return NULL;
   	}
   	
   	if(portToHit != 443 && !strstr(msg,"https"))
   	{
   		printf("REQUEST:\n");
		printf("===============================\n");
   		printf("%s", msg);
   		normalRecv(clientSockFd, serverSockFd, msg);
   	}
   	else
   	{
   		printf("REQUEST SSL:\n");
		printf("===============================\n");
   		printf("%s", msg);
   		SSL_CTX *ctxs;
		SSL *conns;
		ctxs = SSL_CTX_new(SSLv23_client_method());
		conns = SSL_new(ctxs);
		SSL_set_fd(conns, serverSockFd);
		if(SSL_connect(conns) != 1)
		{
			SSL_shutdown(conns);
			SSL_free(conns);
		}

		SSL_CTX *ctxc;
		SSL *connc;
		ctxc = SSL_CTX_new(SSLv23_server_method());
		LoadCertificates(ctxc, "server.pem", "server.pem");
		connc = SSL_new(ctxc);
		SSL_set_fd(connc, clientSockFd);

   		send(clientSockFd, dummy, strlen(dummy), 0);
		if(SSL_accept(connc) != 1)
		{
			SSL_shutdown(connc);
			SSL_free(connc);
			printf("+++++++++++++++++++++++++++++++++Not Accepted\n");
		}
		else
		{
			printf("+++++++++++++++++++++++++++++++++Accepted\n");
		}

   		withSslRecv(connc, conns, msg);
   		
   		SSL_CTX_free(ctxs);
		SSL_shutdown(conns);
		SSL_free(conns);
		SSL_CTX_free(ctxc);
		SSL_shutdown(connc);
		SSL_free(connc);
   	}
   	close(clientSockFd);
	close(serverSockFd);
	
   	return NULL;
}

void startServer(int portMiddle)		//start the server and wait for clients to connect
{
	int serverSockFd = -1;
	int clientSockFd = -1;
	int middleSockFd = -1;
	unsigned int clientAddrSize =0;
   	struct sockaddr_in middleAddr, clientAddr;
   	int nRead = 0;
   	int yes = 1;
   	char *temp = NULL;
   	pid_t pid;
   	
   	
   	if((middleSockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Unable to create the socket.\n");
		return;
	}
   
   	memset(&middleAddr, 0, sizeof(middleAddr));
   	middleAddr.sin_family = AF_INET;
   	middleAddr.sin_addr.s_addr = INADDR_ANY;
   	middleAddr.sin_port = htons(portMiddle);
   
    if (setsockopt(middleSockFd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR), &yes, sizeof(yes)) == -1)  //To reuse the same port again
   	{
    		printf("Unable to set reuse option for socket.\n");
    		return;
	}
 
   	if(bind(middleSockFd, (struct sockaddr *)&middleAddr, sizeof(middleAddr)) < 0)
  	{
  		printf("Unable to bind.\n");
  		return;
  	}
   	listen(middleSockFd, MAX_LISTEN_SIZE);
   	clientAddrSize = sizeof(clientAddr);
	while(1)
	{
	   	if((clientSockFd = accept(middleSockFd, (struct sockaddr *)&clientAddr, &clientAddrSize)) < 0)
	   	{
	   		printf("Unable to accept client request.\n");
	   		return;
	   	}
   		pthread_t t;
   		pthread_create(&t, NULL, serveRequest, &clientSockFd);
	}
}

int main(int argc, char *argv[])
{
	SSL_load_error_strings ();
    ERR_load_BIO_strings();
  	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init ();
	if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("Mutex init failed\n");
        return 1;
    }
	startServer(atoi(argv[1]));
	ERR_free_strings();
	EVP_cleanup();	
   	return 0;
}
