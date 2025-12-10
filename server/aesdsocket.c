#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PORT 9000
#define DATA_FILE "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024

static volatile sig_atomic_t g_signal_received = 0;
static int g_server_fd = -1;
static int g_client_fd = -1;

/**
 * Signal handler for SIGINT and SIGTERM
 */
void signal_handler(int sig)
{
    (void)sig;
    g_signal_received = 1;
    syslog(LOG_INFO, "Caught signal, exiting");
}

/**
 * Setup signal handlers
 */
void setup_signal_handlers(void)
{
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/**
 * Cleanup function to close sockets and delete data file
 */
void cleanup(void)
{
    if (g_client_fd >= 0) {
        close(g_client_fd);
        g_client_fd = -1;
    }
    
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    
    if (unlink(DATA_FILE) == 0) {
        syslog(LOG_INFO, "Deleted data file %s", DATA_FILE);
    }
    
    closelog();
}

/**
 * Read data from socket until newline is found
 * Returns dynamically allocated buffer with the complete packet (including newline)
 * Returns NULL on error or if connection closed
 */
char *receive_packet(int sockfd)
{
    char *buffer = NULL;
    size_t buffer_size = BUFFER_SIZE;
    size_t total_received = 0;
    ssize_t bytes_received;
    char *newline_pos = NULL;
    
    buffer = malloc(buffer_size);
    if (!buffer) {
        syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
        return NULL;
    }
    
    while (1) {
        if (g_signal_received) {
            free(buffer);
            return NULL;
        }
        
        if (total_received >= buffer_size - 1) {
            size_t new_size = buffer_size * 2;
            char *new_buffer = realloc(buffer, new_size);
            if (!new_buffer) {
                syslog(LOG_ERR, "realloc failed: %s", strerror(errno));
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
            buffer_size = new_size;
        }
        
        bytes_received = recv(sockfd, buffer + total_received, 
                             buffer_size - total_received - 1, 0);
        
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                // Connection closed
                free(buffer);
                return NULL;
            }
            if (errno == EINTR) {
                if (g_signal_received) {
                    free(buffer);
                    return NULL;
                }
                continue;
            }
            syslog(LOG_ERR, "recv failed: %s", strerror(errno));
            free(buffer);
            return NULL;
        }
        
        total_received += bytes_received;
        buffer[total_received] = '\0';
        
        // Check for newline
        newline_pos = strchr(buffer, '\n');
        if (newline_pos) {
            // Found complete packet
            break;
        }
    }
    
    return buffer;
}

/**
 * Append data to file
 */
int append_to_file(const char *data, size_t len)
{
    FILE *fp = fopen(DATA_FILE, "a");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open %s for appending: %s", 
               DATA_FILE, strerror(errno));
        return -1;
    }
    
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    
    if (written != len) {
        syslog(LOG_ERR, "Failed to write complete data to %s", DATA_FILE);
        return -1;
    }
    
    return 0;
}

/**
 * Read entire file and send to client
 */
int send_file_contents(int sockfd)
{
    FILE *fp = fopen(DATA_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open %s for reading: %s", 
               DATA_FILE, strerror(errno));
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < 0) {
        syslog(LOG_ERR, "Failed to get file size: %s", strerror(errno));
        fclose(fp);
        return -1;
    }
    
    // Allocate buffer for file contents
    char *file_buffer = malloc(file_size);
    if (!file_buffer) {
        syslog(LOG_ERR, "malloc failed for file buffer: %s", strerror(errno));
        fclose(fp);
        return -1;
    }
    
    size_t bytes_read = fread(file_buffer, 1, file_size, fp);
    fclose(fp);
    
    if (bytes_read != (size_t)file_size) {
        syslog(LOG_ERR, "Failed to read complete file");
        free(file_buffer);
        return -1;
    }
    
    // Send file contents
    ssize_t total_sent = 0;
    while (total_sent < file_size) {
        if (g_signal_received) {
            free(file_buffer);
            return -1;
        }
        
        ssize_t bytes_sent = send(sockfd, file_buffer + total_sent, 
                                  file_size - total_sent, 0);
        if (bytes_sent < 0) {
            if (errno == EINTR) {
                if (g_signal_received) {
                    free(file_buffer);
                    return -1;
                }
                continue;
            }
            syslog(LOG_ERR, "send failed: %s", strerror(errno));
            free(file_buffer);
            return -1;
        }
        total_sent += bytes_sent;
    }
    
    free(file_buffer);
    return 0;
}

/**
 * Handle client connection
 */
void handle_client(int client_fd, struct sockaddr_in *client_addr)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, INET_ADDRSTRLEN);
    
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);
    
    while (!g_signal_received) {
        char *packet = receive_packet(client_fd);
        if (!packet) {
            // Connection closed or error
            break;
        }
        
        // Append packet to file
        size_t packet_len = strlen(packet);
        if (append_to_file(packet, packet_len) != 0) {
            free(packet);
            break;
        }
        
        // Send full file contents back to client
        if (send_file_contents(client_fd) != 0) {
            free(packet);
            break;
        }
        
        free(packet);
    }
    
    syslog(LOG_INFO, "Closed connection from %s", client_ip);
    close(client_fd);
}

/**
 * Daemonize the process
 */
int daemonize(void)
{
    pid_t pid = fork();
    
    if (pid < 0) {
        syslog(LOG_ERR, "fork failed: %s", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        // Parent process exits
        exit(0);
    }
    
    // Child process continues
    if (setsid() < 0) {
        syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
        return -1;
    }
    
    // Fork again to ensure we're not a session leader
    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "second fork failed: %s", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        // Parent process exits
        exit(0);
    }
    
    // Change to root directory
    if (chdir("/") < 0) {
        syslog(LOG_ERR, "chdir failed: %s", strerror(errno));
        return -1;
    }
    
    // Close file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect to /dev/null
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
    
    return 0;
}

int main(int argc, char *argv[])
{
    int daemon_mode = 0;
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                daemon_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                return -1;
        }
    }
    
    // Open syslog
    openlog("aesdsocket", LOG_PID, LOG_USER);
    
    // Setup signal handlers
    setup_signal_handlers();
    
    // Create socket
    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        syslog(LOG_ERR, "socket creation failed: %s", strerror(errno));
        cleanup();
        return -1;
    }
    
    // Set socket option to reuse address
    int opt_val = 1;
    if (setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, 
                   sizeof(opt_val)) < 0) {
        syslog(LOG_ERR, "setsockopt failed: %s", strerror(errno));
        cleanup();
        return -1;
    }
    
    // Bind socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(g_server_fd, (struct sockaddr *)&server_addr, 
             sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "bind failed: %s", strerror(errno));
        cleanup();
        return -1;
    }
    
    // Listen
    if (listen(g_server_fd, 5) < 0) {
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        cleanup();
        return -1;
    }
    
    // Daemonize if requested
    if (daemon_mode) {
        if (daemonize() < 0) {
            cleanup();
            return -1;
        }
    }
    
    // Main loop: accept connections
    while (!g_signal_received) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        g_client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, 
                            &client_addr_len);
        
        if (g_client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (g_signal_received) {
                break;
            }
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            continue;
        }
        
        handle_client(g_client_fd, &client_addr);
        g_client_fd = -1;
    }
    
    // Cleanup
    cleanup();
    
    return 0;
}
