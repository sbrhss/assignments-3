#define _GNU_SOURCE
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
#include <pthread.h>
#include <time.h>

#define PORT 9000
#define DATA_FILE "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024
#define TIMESTAMP_INTERVAL 10

static volatile sig_atomic_t g_signal_received = 0;
static int g_server_fd = -1;

// Mutex for synchronizing file writes
static pthread_mutex_t g_file_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread management structures
struct thread_node {
    pthread_t thread_id;
    int client_fd;
    struct sockaddr_in client_addr;
    struct thread_node *next;
};

// Head of the thread list
static struct thread_node *g_thread_list_head = NULL;
static pthread_mutex_t g_thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Signal handler for SIGINT and SIGTERM
 */
void signal_handler(int sig)
{
    (void)sig;
    g_signal_received = 1;
    syslog(LOG_INFO, "Caught signal, exiting");
    // Close server socket to wake up accept()
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
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
 * Add thread node to the list
 */
void add_thread_node(struct thread_node *node)
{
    pthread_mutex_lock(&g_thread_list_mutex);
    node->next = g_thread_list_head;
    g_thread_list_head = node;
    pthread_mutex_unlock(&g_thread_list_mutex);
}

/**
 * Remove thread node from the list
 * Note: This is called by cleanup() to remove completed threads
 */
void remove_thread_node(pthread_t thread_id)
{
    pthread_mutex_lock(&g_thread_list_mutex);
    struct thread_node *current = g_thread_list_head;
    struct thread_node *prev = NULL;
    
    while (current != NULL) {
        if (pthread_equal(current->thread_id, thread_id)) {
            if (prev == NULL) {
                g_thread_list_head = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            break;
        }
        prev = current;
        current = current->next;
    }
    pthread_mutex_unlock(&g_thread_list_mutex);
}

/**
 * Clean up completed threads (non-blocking)
 * This should be called periodically in the main loop to free completed threads
 */
void cleanup_completed_threads(void)
{
    pthread_mutex_lock(&g_thread_list_mutex);
    struct thread_node *current = g_thread_list_head;
    struct thread_node *prev = NULL;
    
    while (current != NULL) {
        void *retval;
        // Try to join the thread without blocking
        int result = pthread_tryjoin_np(current->thread_id, &retval);
        if (result == 0) {
            // Thread has completed, remove it from the list
            struct thread_node *next = current->next;
            if (prev == NULL) {
                g_thread_list_head = next;
            } else {
                prev->next = next;
            }
            free(current);
            current = next;
        } else {
            // Thread is still running, move to next
            prev = current;
            current = current->next;
        }
    }
    pthread_mutex_unlock(&g_thread_list_mutex);
}

/**
 * Cleanup function to close sockets and delete data file
 */
void cleanup(void)
{
    // Close server socket first to wake up accept() and prevent new connections
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    
    // Close all client sockets to wake up threads blocked in recv()
    // This helps threads exit promptly when shutdown is requested
    if (g_thread_list_head != NULL) {
        if (pthread_mutex_lock(&g_thread_list_mutex) == 0) {
            struct thread_node *current = g_thread_list_head;
            while (current != NULL) {
                // Close client socket to wake up thread blocked in recv()
                // It's safe to close even if already closed by the thread
                if (current->client_fd >= 0) {
                    close(current->client_fd);
                    current->client_fd = -1;  // Mark as closed
                }
                current = current->next;
            }
            pthread_mutex_unlock(&g_thread_list_mutex);
        }
    }
    
    // Wait for all threads to complete (only if threads were created)
    if (g_thread_list_head != NULL) {
        if (pthread_mutex_lock(&g_thread_list_mutex) == 0) {
            struct thread_node *current = g_thread_list_head;
            while (current != NULL) {
                struct thread_node *next = current->next;
                void *retval;
                pthread_join(current->thread_id, &retval);
                free(current);
                current = next;
            }
            g_thread_list_head = NULL;
            pthread_mutex_unlock(&g_thread_list_mutex);
        }
    }
    
    unlink(DATA_FILE);
    
    // Destroy mutexes (safe even if not used)
    pthread_mutex_destroy(&g_file_mutex);
    pthread_mutex_destroy(&g_thread_list_mutex);
    
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
 * Append data to file (thread-safe with mutex)
 */
int append_to_file(const char *data, size_t len)
{
    pthread_mutex_lock(&g_file_mutex);
    
    FILE *fp = fopen(DATA_FILE, "a");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open %s for appending: %s", 
               DATA_FILE, strerror(errno));
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }
    
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    
    pthread_mutex_unlock(&g_file_mutex);
    
    if (written != len) {
        syslog(LOG_ERR, "Failed to write complete data to %s", DATA_FILE);
        return -1;
    }
    
    return 0;
}

/**
 * Read entire file and send to client (thread-safe with mutex)
 */
int send_file_contents(int sockfd)
{
    pthread_mutex_lock(&g_file_mutex);
    
    FILE *fp = fopen(DATA_FILE, "r");
    if (!fp) {
        // File doesn't exist yet - that's okay, send nothing
        if (errno == ENOENT) {
            pthread_mutex_unlock(&g_file_mutex);
            return 0;
        }
        syslog(LOG_ERR, "Failed to open %s for reading: %s", 
               DATA_FILE, strerror(errno));
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < 0) {
        syslog(LOG_ERR, "Failed to get file size: %s", strerror(errno));
        fclose(fp);
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }
    
    // Handle empty file
    if (file_size == 0) {
        fclose(fp);
        pthread_mutex_unlock(&g_file_mutex);
        return 0;
    }
    
    // Allocate buffer for file contents
    char *file_buffer = malloc(file_size);
    if (!file_buffer) {
        syslog(LOG_ERR, "malloc failed for file buffer: %s", strerror(errno));
        fclose(fp);
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }
    
    size_t bytes_read = fread(file_buffer, 1, file_size, fp);
    fclose(fp);
    
    pthread_mutex_unlock(&g_file_mutex);
    
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
 * Thread function to handle client connection
 */
void *handle_client_thread(void *arg)
{
    struct thread_node *node = (struct thread_node *)arg;
    int client_fd = node->client_fd;
    struct sockaddr_in *client_addr = &node->client_addr;
    char client_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, INET_ADDRSTRLEN);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);
    
    while (!g_signal_received) {
        char *packet = receive_packet(client_fd);
        if (!packet) {
            // Connection closed or error
            break;
        }
        
        // Append packet to file (with mutex protection)
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
    // Close client socket (safe even if already closed by cleanup)
    if (client_fd >= 0) {
        close(client_fd);
    }
    
    // Thread node will be removed and freed by cleanup()
    return node;
}

/**
 * Thread function to write timestamp every 10 seconds
 */
void *timestamp_thread(void *arg)
{
    (void)arg;
    
    while (!g_signal_received) {
        // Use interruptible sleep - check signal every second
        for (int i = 0; i < TIMESTAMP_INTERVAL && !g_signal_received; i++) {
            sleep(1);
        }
        
        if (g_signal_received) {
            break;
        }
        
        time_t now;
        struct tm *tm_info;
        char timestamp_str[256];
        
        time(&now);
        tm_info = localtime(&now);
        
        // Format: timestamp:time where time is RFC 2822 compliant
        // RFC 2822 format: "%a, %d %b %Y %T %z"
        strftime(timestamp_str, sizeof(timestamp_str), "timestamp:%a, %d %b %Y %T %z\n", tm_info);
        
        // Append timestamp to file (with mutex protection)
        size_t len = strlen(timestamp_str);
        append_to_file(timestamp_str, len);
    }
    
    return NULL;
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
    
    // Delete data file if it exists (start fresh)
    unlink(DATA_FILE);
    
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
    
    // Start timestamp thread
    pthread_t timestamp_tid;
    if (pthread_create(&timestamp_tid, NULL, timestamp_thread, NULL) != 0) {
        syslog(LOG_ERR, "Failed to create timestamp thread: %s", strerror(errno));
        cleanup();
        return -1;
    }
    
    // Main loop: accept connections
    while (!g_signal_received) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, 
                              &client_addr_len);
        
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (g_signal_received || g_server_fd < 0) {
                break;
            }
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            continue;
        }
        
        // Create thread node for this connection
        struct thread_node *node = malloc(sizeof(struct thread_node));
        if (!node) {
            syslog(LOG_ERR, "malloc failed for thread node: %s", strerror(errno));
            close(client_fd);
            continue;
        }
        
        node->client_fd = client_fd;
        node->client_addr = client_addr;
        node->next = NULL;
        
        // Create thread for this connection
        if (pthread_create(&node->thread_id, NULL, handle_client_thread, node) != 0) {
            syslog(LOG_ERR, "Failed to create thread: %s", strerror(errno));
            free(node);
            close(client_fd);
            continue;
        }
        
        // Add thread to list
        add_thread_node(node);
        
        // Clean up any completed threads (as recommended by assignment)
        // This ensures threads are freed after starting the next thread
        cleanup_completed_threads();
    }
    
    // Wait for timestamp thread to complete
    pthread_join(timestamp_tid, NULL);
    
    // Cleanup (will join all client threads)
    cleanup();
    
    return 0;
}
