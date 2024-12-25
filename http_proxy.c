// PA3 - http_proxy

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 4096
#define HEADERSIZE 1024
#define RESPONSESIZE 1048576
#define MAX_QUEUE_SIZE 5
#define PACKET_TRANSFER_TIMEOUT_S 1

pthread_mutex_t cache_lock;
int expiration_time_s;

// Wrapper for perror
void error(char* msg) 
{
    perror(msg);
    exit(1);
}
void warning(char* msg) 
{
    perror(msg);
}

// FNV-1a hashing function for 32-bit
uint32_t compute_hash(const char *str) 
{
    uint32_t hash = 2166136261u; // FNV offset basis
    while (*str) 
    {
        hash ^= (unsigned char)*str;
        hash *= 16777619u; // FNV prime
        str++;
    }

    return hash;
}

// Helper functions

void send_response(int sock, const char* response_code, const char* version, const char* content_type, unsigned long content_size, const char* contents)
{
    char header[HEADERSIZE];

    // ---- Generate header ----

    // Put response code
    strcpy(header, version);
    strcat(header, " ");
    strcat(header, response_code);
    strcat(header, "\r\n");

    // Put content type
    strcat(header, "Content-Type: ");
    strcat(header, content_type);
    strcat(header, "\r\n");

    // Put content length
    strcat(header, "Content-Length: ");
    
    char content_size_str[10];
    snprintf(content_size_str, 10, "%ld", content_size);

    strcat(header, content_size_str);
    strcat(header, "\r\n\r\n");

    // ---- File Contents ----

    char* response = (char*) malloc(HEADERSIZE + content_size + 1);

    memcpy(response, header, HEADERSIZE); // Copy the header
    memcpy(response + strlen(header), contents, content_size); // Append the body

    send(sock, response, HEADERSIZE + content_size + 1, 0);

    free(response);
}

void send_request(int sock, const char* method, const char* path, const char* version, const char* hostname, const char* body)
{
    char header[HEADERSIZE];

    // ---- Generate header ----

    // Put response code
    strcpy(header, method);
    strcat(header, " ");
    strcat(header, path);
    strcat(header, " ");
    strcat(header, version);
    strcat(header, "\r\n");

    // Put hostname
    strcat(header, "Host: ");
    strcat(header, hostname);
    strcat(header, "\r\n");

    // ---- Optional Body ----

    if (body != NULL)
    {
        strcat(header, "\r\n\r\n");
        strcat(header, body);
    }

    send(sock, header, HEADERSIZE + 1, 0);
}

void* handle_connection(void* sock_desc)
{
    char buf[BUFSIZE];

    int totalSize = 0;

    int sock = *(int *) sock_desc;

    int received = recv(sock, buf, BUFSIZE - 1, 0);
    buf[received] = '\0';

    // Parse the http request
    
    char method[16], hostname[256], url[256], version[16];
    int port = 80;
    char* body = NULL;

    // Parse the GET request line
    sscanf(buf, "%15s %255s %15s", method, url, version);

    char* host_header = strstr(buf, "Host: ");
    host_header += 6;

    // Don't include next header lines
    char* host_end = strstr(host_header, "\r\n");
    if (host_end != NULL) *host_end = '\0';

    char* portstr = strchr(host_header, ':');
    
    // Check if port is specified
    if (portstr) 
    {
        *portstr = '\0';  // Don't include port in hostname
        port = atoi(portstr + 1);
    }

    strncpy(hostname, host_header, sizeof(hostname) - 1);

    // Find the optional body starting from after the end of the host line
    char *body_start = strstr(host_end + 2, "\r\n\r\n");
    
    if (body_start) 
    {
        body_start += 4;  // Skip the empty line separating headers from the body
        body = body_start;  // Body starts after the headers
    }

    // Lowercase the url
    for (int i = 0; url[i]; i++) url[i] = tolower( (unsigned char) url[i] );

    printf("Server received the following request:\n%s %s %s\n", method, url, version);
    printf("Host %s requested over port %d\n", hostname, port);

    // Check for method error
    if (strcmp(method, "GET") != 0)
    {
        printf("A method other than GET was requested\n\n");

        const char* errmsg = "<!DOCTYPE html><html><body><h1>400 Bad Request</h1></body></html>";

        send_response(sock, "400 Bad Request", version, "text/html", strlen(errmsg), errmsg);
        close(sock);
        free(sock_desc);
        pthread_exit(NULL);
    }

    // Check for non-existant host server

    struct hostent *host_entry;

    host_entry = gethostbyname(hostname);

    if (!host_entry) 
    {
        printf("Host server cannot be found\n\n");

        const char* errmsg = "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>";

        send_response(sock, "404 Not Found", version, "text/html", strlen(errmsg), errmsg);
        close(sock);
        free(sock_desc);
        pthread_exit(NULL);
    }

    char *server_address = inet_ntoa(*(struct in_addr *) host_entry -> h_addr_list[0]);

    printf("Resolved IP address for %s: %s\n", hostname, server_address);

    // Check if domain or ip is on block list

    FILE *blocklist = fopen("blocklist", "r");

    char line[256];

    while (fgets(line, sizeof(line), blocklist)) 
    {
        // Remove newline if exists
        line[strcspn(line, "\n")] = '\0';

        // Check if this is the same as domain or ip of requested web server
        if (strcmp(line, hostname) == 0 || strcmp(line, server_address) == 0) 
        {
            printf("%s is blocked\n\n", hostname);

            const char* errmsg = "<!DOCTYPE html><html><body><h1>403 Forbidden</h1></body></html>";

            send_response(sock, "403 Forbidden", version, "text/html", strlen(errmsg), errmsg);
            fclose(blocklist);
            close(sock);
            free(sock_desc);
            pthread_exit(NULL);
        }
    }

    fclose(blocklist);
    
    // Check if cached file exists

    uint32_t hash = compute_hash(url);

    char filepath[15]; // 8 hex digits + null terminator
    snprintf(filepath, sizeof(filepath), "cache/%08X", hash);

    printf("Checking cached file %s...\n", filepath);

    struct stat cache_stat;

    int cache_hit = 0;

    pthread_mutex_lock(&cache_lock);

    // Check if cache exists
    if (stat(filepath, &cache_stat) >= 0)
    {
        time_t current_time = time(NULL);
        
        // Check if cache is expired
        if (current_time - cache_stat.st_mtime < expiration_time_s)
        {
            cache_hit = 1;
            printf("Cached file exists, sending to client.\n");

            FILE *file = fopen(filepath, "rb");

            // Get size of cached file
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            fseek(file, 0, SEEK_SET);

            char *reply = (char *) malloc(file_size);

            size_t read = fread(reply, 1, file_size, file);

            send(sock, reply, read, 0);

            fclose(file);
        }
        else
        {
            printf("Cached file has expired.\n");
            remove(filepath);
        }
    }

    pthread_mutex_unlock(&cache_lock);

    // If cache was found, can just exit
    if (cache_hit)
    {
        close(sock);
        free(sock_desc);

        printf("Cached response sent, closing socket connection with client.\n\n");

        pthread_exit(NULL);
    }

    // Parse file path from url

    char* path = (char*) malloc(strlen(url) + 1);

    char* temp_path = url;
    char* protocol_end = strstr(temp_path, "://");

    if (protocol_end != NULL) temp_path = protocol_end + 3; // Skip past the scheme

    char* path_start = strchr(temp_path, '/');

    // Make sure url actually includes path, if not default to "/"
    if (path_start != NULL) strcpy(path, path_start);
    else strcpy(path, "/");

    printf("Requested path is %s\n", path);

    // Establish new connection with HTTP web server

    int new_sock;
    struct sockaddr_in server_addr;

    new_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (new_sock < 0)
    {
        printf("Connection with host couldn't be established\n\n");

        const char* errmsg = "<!DOCTYPE html><html><body><h1>500 Internal Server Error</h1></body></html>";

        send_response(sock, "500 Internal Server Error", version, "text/html", strlen(errmsg), errmsg);
        free(path);
        close(new_sock);
        close(sock);
        free(sock_desc);
        pthread_exit(NULL);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(server_address);

    if (connect(new_sock, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0)
    {
        printf("Connection with host couldn't be established\n\n");

        const char* errmsg = "<!DOCTYPE html><html><body><h1>500 Internal Server Error</h1></body></html>";

        send_response(sock, "500 Internal Server Error", version, "text/html", strlen(errmsg), errmsg);
        free(path);
        close(new_sock);
        close(sock);
        free(sock_desc);
        pthread_exit(NULL);
    }

    printf("Connection established with %s, sending %s request for %s...\n", hostname, method, path);

    send_request(new_sock, method, path, version, hostname, body);

    free(path);

    char* reply = (char*) malloc(RESPONSESIZE);

    // Get response from server
    received = recv(new_sock, reply, RESPONSESIZE - 1, 0);

    if (received < 0)
    {
        printf("Failed to receive response from server\n\n");

        const char* errmsg = "<!DOCTYPE html><html><body><h1>500 Internal Server Error</h1></body></html>";

        send_response(sock, "500 Internal Server Error", version, "text/html", strlen(errmsg), errmsg);
        free(reply);
        close(new_sock);
        close(sock);
        free(sock_desc);
        pthread_exit(NULL);
    }

    reply[received] = '\0';

    close(new_sock);

    printf("Request received, forwarding response...\n");

    // Relay response to client
    send(sock, reply, received + 1, 0);

    // Save cached file

    // check if file is dynamic in which case don't cache
    if (!strchr(path, '?'))
    {
        printf("Caching response...\n");

        pthread_mutex_lock(&cache_lock);

        FILE *file = fopen(filepath, "wb");

        size_t written = fwrite(reply, 1, received + 1, file);

        if (written != received + 1)
        {
            printf("Failed to cache response.\n");
            remove(filepath);
        }
        
        fclose(file);

        pthread_mutex_unlock(&cache_lock);
    }

    free(reply);

    close(sock);
    free(sock_desc);
    
    printf("Response sent, closing socket connection with client.\n\n");

    return NULL;
}

int main(int argc, char **argv)
{
    int sockfd;                         // Socket
    int portnum;                        // Port to listen on
    int clientlen;                      // Byte size of client's address

    struct sockaddr_in serveraddr;      // Server addr
    struct sockaddr_in clientaddr;      // Client addr

    char *clientaddr_str;               // Dotted decimal host addr string
    int optval;                         // Flag value for setsockopt
    
    char buf[BUFSIZE];                  // Message buf
    int n;                              // Message byte size

    // Check command line arguments
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <port> <expiration time (in seconds)>\n", argv[0]);
        exit(1);
    }

    portnum = atoi(argv[1]);
    expiration_time_s = atoi(argv[2]);

    // Set default value in case of failure
    if (expiration_time_s == 0)
        expiration_time_s = 60;

    if (pthread_mutex_init(&cache_lock, NULL) != 0) 
        error("ERROR initializing cache lock mutex"); 

    // socket: create the parent socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) 
        error("ERROR opening socket");

    /* setsockopt: Handy debugging trick that lets us rerun the server immediately after we kill it; 
    * otherwise we have to wait about 20 secs. Eliminates "ERROR on binding: Address already in use" error. */
    optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int)) < 0)
    {
        close(sockfd);
        error("ERROR in setsockopt");
    }

    // Build the server's Internet address
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short) portnum);

    // Bind socket to specified port
    if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
    {
        close(sockfd);
        error("ERROR on binding");
    }

    printf("Listening on port %d...\n", portnum);

    listen(sockfd, MAX_QUEUE_SIZE);

    clientlen = sizeof(clientaddr);
  
    // Receive HTTP requests in infinite loop
    while (1)
    {
        int* new_sock = malloc(sizeof(int));
        
        *new_sock = accept(sockfd, (struct sockaddr *) &clientaddr, &clientlen);

        if (*new_sock < 0)
        {
            warning("ERROR on accept");
            continue;
        }
    
        // Convert sockaddr to IPv4 string
        clientaddr_str = inet_ntoa(clientaddr.sin_addr);

        if (clientaddr_str == NULL)
        {
            warning("ERROR on inet_ntoa");
            continue;
        }

        printf("Connected to client at %s through port %d\n", clientaddr_str, portnum);

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_connection, (void *) new_sock) != 0)
        {
            warning("Error on pthread_create");
            close(*new_sock);
            free(new_sock);
        }

        pthread_detach(thread);

        printf("Connection being handled by thread %u\n", (int) thread);

        printf("\n");
    }

    printf("Closing socket connection...\n");
    close(sockfd);

    pthread_mutex_destroy(&cache_lock);
    
    return 0;
}
