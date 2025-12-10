
#define _GNU_SOURCE // for pthread_tryjoin_np

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>  // for time(), localtime_r(), struct tm

/* Network configuration */
#define PORT "9000"
#define BACKLOG 10

/* File configuration */
#define FILE_NAME "/var/tmp/aesdsocketdata"
#define FILE_MODE 0644  // rw-r--r--

/* Buffer sizes */
#define RECV_BUF_SIZE 131072      // 128KB - maximum packet size
#define INITIAL_PACKET_CAP 1024   // Initial packet buffer capacity
#define RECV_CHUNK_SIZE 512       // Chunk size for receiving data

/* Timestamp thread configuration */
#define TIMESTAMP_INTERVAL_SEC 10  // Write timestamp every 10 seconds

volatile sig_atomic_t stop_program = 0;

typedef struct {
    int new_fd;
    char client_ip[INET6_ADDRSTRLEN];
    int daemon_mode;
} thread_variable_t;

typedef struct thread_node {
    pthread_t tid;
    struct thread_node *next;
    thread_variable_t *tdata;
} thread_node_t;

/* Global list head and mutex */
static thread_node_t *thread_list_head = NULL;
static pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex for file access */
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Listening socket (global to be closed from signal handler) */
static int listen_fd = -1;

/**
 * Signal handler for SIGINT and SIGTERM.
 * Sets the global stop flag and closes the listening socket to interrupt accept().
 * This allows graceful shutdown of the server.
 */
void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        stop_program = 1;
        if (listen_fd != -1) {
            /* Closing the listening socket will interrupt accept() */
            close(listen_fd);
            listen_fd = -1;
        }
    }
}

/**
 * Helper function to extract the IP address from a sockaddr structure.
 * Supports both IPv4 and IPv6 addresses.
 * 
 * @param sa Pointer to sockaddr structure (IPv4 or IPv6)
 * @return Pointer to the IP address within the sockaddr structure
 */
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
 * Append a packet to the data file.
 * The packet buffer should contain data up to and including a newline '\n'.
 * This function strips any preceding '\r' before '\n' (converts CRLF to LF).
 * Thread-safe: uses file_mutex to ensure atomic file operations.
 * 
 * @param buf Buffer containing the packet data (must include '\n')
 * @param len Length of the buffer
 * @return 0 on success, -1 on error
 */
static int append_packet_to_file(const char *buf, size_t len)
{
    if (len == 0) return 0;

    /* Determine actual write length: strip preceding '\r' if present */
    size_t write_len = len;
    if (write_len >= 2 && buf[write_len - 2] == '\r' && buf[write_len - 1] == '\n') {
        /* Replace CRLF with LF only -> write_len decreases by 1 */
        write_len = write_len - 1;
    }

    /* Acquire file mutex while appending to ensure thread-safe file access */
    if (pthread_mutex_lock(&file_mutex) != 0) {
        syslog(LOG_ERR, "pthread_mutex_lock file_mutex failed");
        return -1;
    }

    int fd = open(FILE_NAME, O_WRONLY | O_CREAT | O_APPEND, FILE_MODE);
    if (fd == -1) {
        syslog(LOG_ERR, "open append file failed: %s", strerror(errno));
        pthread_mutex_unlock(&file_mutex);
        return -1;
    }

    ssize_t w = write(fd, buf, write_len);
    if (w == -1 || (size_t)w != write_len) {
        syslog(LOG_ERR, "write to file failed: %s", strerror(errno));
        close(fd);
        pthread_mutex_unlock(&file_mutex);
        return -1;
    }

    close(fd);
    pthread_mutex_unlock(&file_mutex);
    return 0;
}

/**
 * Read the entire data file into a heap-allocated buffer.
 * Thread-safe: uses file_mutex to ensure consistent file reading.
 * 
 * @param size_out Pointer to store the file size (set to 0 if file doesn't exist)
 * @return Pointer to allocated buffer containing file contents (caller must free()),
 *         or NULL if file doesn't exist or on error
 */
static char *read_entire_file(size_t *size_out)
{
    *size_out = 0;
    struct stat st;
    if (stat(FILE_NAME, &st) == -1) {
        if (errno == ENOENT) {
            return NULL; // file doesn't exist
        }
        syslog(LOG_ERR, "stat failed: %s", strerror(errno));
        return NULL;
    }
    size_t fsize = (size_t)st.st_size;
    if (fsize == 0) {
        return NULL;
    }

    char *buf = malloc(fsize);
    if (!buf) {
        syslog(LOG_ERR, "malloc failed for read_entire_file");
        return NULL;
    }

    /* Ensure we read a consistent view: lock file mutex */
    if (pthread_mutex_lock(&file_mutex) != 0) {
        syslog(LOG_ERR, "pthread_mutex_lock file_mutex failed");
        free(buf);
        return NULL;
    }

    int fd = open(FILE_NAME, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "open for read failed: %s", strerror(errno));
        pthread_mutex_unlock(&file_mutex);
        free(buf);
        return NULL;
    }

    ssize_t r = read(fd, buf, fsize);
    if (r == -1 || (size_t)r != fsize) {
        syslog(LOG_ERR, "read file failed: %s", strerror(errno));
        close(fd);
        pthread_mutex_unlock(&file_mutex);
        free(buf);
        return NULL;
    }

    close(fd);
    pthread_mutex_unlock(&file_mutex);

    *size_out = fsize;
    return buf;
}

/**
 * Timestamp thread routine.
 * Periodically writes a timestamp entry to the data file every TIMESTAMP_INTERVAL_SEC seconds.
 * Thread-safe: uses file_mutex for file access.
 * 
 * @param arg Unused (required by pthread interface)
 * @return NULL (never returns normally, exits via pthread_exit)
 */
void *timestamp_thread(void *arg)
{
    (void)arg;
    while (!stop_program)
    {
        sleep(TIMESTAMP_INTERVAL_SEC);

        /* Check again after sleep in case stop_program was set during sleep */
        if (stop_program) break;

        /* Get current time and format it */
        time_t t = time(NULL);
        struct tm tm_info;
        localtime_r(&t, &tm_info);

        char timebuf[128];
        strftime(timebuf, sizeof(timebuf),
                 "%a, %d %b %Y %H:%M:%S %z",
                 &tm_info);

        /* Format the timestamp entry */
        char outbuf[256];
        int len = snprintf(outbuf, sizeof(outbuf),
                           "timestamp:%s\n", timebuf);

        if (len <= 0 || len >= (int)sizeof(outbuf)) {
            syslog(LOG_ERR, "timestamp snprintf error");
            continue;
        }

        /* Append timestamp to file (thread-safe) */
        pthread_mutex_lock(&file_mutex);

        int fd = open(FILE_NAME, O_WRONLY | O_CREAT | O_APPEND, FILE_MODE);
        if (fd == -1) {
            syslog(LOG_ERR, "open timestamp file: %s", strerror(errno));
            pthread_mutex_unlock(&file_mutex);
            continue;
        }

        ssize_t w = write(fd, outbuf, len);
        if (w == -1 || (size_t)w != (size_t)len) {
            syslog(LOG_ERR, "write timestamp failed: %s", strerror(errno));
        }
        close(fd);

        pthread_mutex_unlock(&file_mutex);
    }
    pthread_exit(NULL);
}

/**
 * Worker thread routine for handling client connections.
 * 
 * Protocol:
 * 1. Receive data from client until a newline '\n' is found (packet complete)
 * 2. Append the received packet to the data file
 * 3. Read the entire data file and send it back to the client
 * 4. Close the connection and exit
 * 
 * @param arg Pointer to thread_variable_t containing connection info
 * @return NULL (exits via pthread_exit)
 */
static void *connection_handler(void *arg)
{
    thread_variable_t *tdata = (thread_variable_t*)arg;
    int client_fd = tdata->new_fd;

    /* Receive until newline '\n' is found (packet completes). Read in chunks. */
    char *packet_buf = NULL;
    size_t packet_cap = INITIAL_PACKET_CAP;
    size_t packet_len = 0;
    packet_buf = malloc(packet_cap);
    if (!packet_buf) {
        syslog(LOG_ERR, "malloc packet_buf failed");
        close(client_fd);
        free(tdata);
        pthread_exit(NULL);
    }

    bool packet_complete = false;
    while (!packet_complete && !stop_program) {
        char chunk[RECV_CHUNK_SIZE];
        ssize_t recvd = recv(client_fd, chunk, sizeof(chunk), 0);
        if (recvd == 0) {
            /* Connection closed by client before newline */
            break;
        } else if (recvd < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "recv error from %s: %s", tdata->client_ip, strerror(errno));
            break;
        } else {
            /* append chunk to packet buffer */
            if (packet_len + (size_t)recvd > packet_cap) {
                size_t newcap = packet_cap * 2;
                while (newcap < packet_len + (size_t)recvd) newcap *= 2;
                char *tmp = realloc(packet_buf, newcap);
                if (!tmp) {
                    syslog(LOG_ERR, "realloc failed");
                    break;
                }
                packet_buf = tmp;
                packet_cap = newcap;
            }
            memcpy(packet_buf + packet_len, chunk, recvd);
            packet_len += recvd;

            /* check if newline present */
            for (size_t i = packet_len - recvd; i < packet_len; ++i) {
                if (packet_buf[i] == '\n') {
                    packet_complete = true;
                    /* truncate after newline (keep newline) */
                    packet_len = i + 1;
                    break;
                }
            }
            /* If packet length grows beyond RECV_BUF_SIZE, refuse further growth */
            if (packet_len >= (size_t)RECV_BUF_SIZE) {
                /* drop the rest of the packet */
                packet_len = RECV_BUF_SIZE - 1;
                packet_buf[packet_len] = '\n';
                packet_complete = true;
                break;
            }
        }
    }

    /* If we received at least 1 byte and found newline, append to file */
    if (packet_len > 0) {
        /* Ensure packet_buf is not null-terminated in file; we write exact bytes */
        if (append_packet_to_file(packet_buf, packet_len) != 0) {
            syslog(LOG_ERR, "Failed to append packet from %s", tdata->client_ip);
        }
    }

    free(packet_buf);

    /* Read full file (while holding lock inside read_entire_file) */
    size_t file_size = 0;
    char *file_contents = read_entire_file(&file_size);
    if (file_contents && file_size > 0) {
        /* Send file in loop until all bytes sent (handle partial sends) */
        size_t sent = 0;
        while (sent < file_size && !stop_program) {
            ssize_t s = send(client_fd, file_contents + sent, file_size - sent, 0);
            if (s < 0) {
                if (errno == EINTR) continue;
                syslog(LOG_ERR, "send error to %s: %s", tdata->client_ip, strerror(errno));
                break;
            }
            sent += (size_t)s;
        }
        free(file_contents);
    }
    /* If file empty or missing, send nothing (valid per spec) */

    /* Log connection closure */
    syslog(LOG_INFO, "Closed connection from %s", tdata->client_ip);
    if (!tdata->daemon_mode) {
        printf("Close Cnx From %s\n", tdata->client_ip);
    }

    close(client_fd);

    /* Note: DO NOT free tdata here. The main thread allocates tdata per connection
     * and will free it after joining the thread. Freeing here would cause a
     * double-free error.
     */
    pthread_exit(NULL);
    return NULL;
}

/**
 * Add a created thread and its data to the thread list.
 * Thread-safe: uses thread_list_mutex for list manipulation.
 * 
 * @param tid Thread ID to track
 * @param tdata Thread data associated with this thread
 */
static void add_thread_node(pthread_t tid, thread_variable_t *tdata)
{
    thread_node_t *node = malloc(sizeof(thread_node_t));
    if (!node) {
        syslog(LOG_ERR, "malloc thread node failed");
        return;
    }
    node->tid = tid;
    node->tdata = tdata;
    node->next = NULL;

    pthread_mutex_lock(&thread_list_mutex);
    node->next = thread_list_head;
    thread_list_head = node;
    pthread_mutex_unlock(&thread_list_mutex);
}

/**
 * Reap finished threads using pthread_tryjoin_np() (non-blocking join).
 * Iterates through the thread list and attempts to join any finished threads.
 * Frees thread node and its thread_variable_t after successful join.
 * Thread-safe: uses thread_list_mutex for list manipulation.
 */
static void reap_finished_threads(void)
{
    pthread_mutex_lock(&thread_list_mutex);
    thread_node_t **pp = &thread_list_head;
    while (*pp) {
        thread_node_t *node = *pp;
        int jrv = pthread_tryjoin_np(node->tid, NULL);
        if (jrv == 0) {
            /* thread finished and joined */
            *pp = node->next;
            /* free thread data */
            if (node->tdata) free(node->tdata);
            free(node);
            /* pp remains the same (already updated) */
        } else if (jrv == EBUSY) {
            /* thread still running, move to next */
            pp = &node->next;
        } else {
            /* Some error occurred (unlikely), log and remove to avoid leak */
            syslog(LOG_ERR, "pthread_tryjoin_np returned %d for tid (removing): %s", jrv, strerror(jrv));
            *pp = node->next;
            if (node->tdata) free(node->tdata);
            free(node);
        }
    }
    pthread_mutex_unlock(&thread_list_mutex);
}

/**
 * Main function for the AESD socket server.
 * 
 * Usage: aesdsocket [-d]
 *   -d: Run in daemon mode (background process)
 * 
 * The server:
 * - Listens on port 9000 for incoming connections
 * - Spawns a worker thread for each connection
 * - Appends received packets to /var/tmp/aesdsocketdata
 * - Sends the entire file contents back to clients
 * - Runs a timestamp thread that writes timestamps every 10 seconds
 * - Handles SIGINT and SIGTERM for graceful shutdown
 */
int main(int argc, char *argv[])
{
    struct addrinfo hints, *res, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    int rv;
    int yes = 1;
    struct sigaction sa;
    int daemon_mode = 0;
    pthread_t timestamp_tid;
    int timestamp_started = 0;

    openlog(NULL, LOG_PID, LOG_USER);

    /* Parse command line arguments */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-d") == 0) {
            daemon_mode = 1;
        }
    }

    /* Setup signal handling for graceful shutdown.
     * Note: No SA_RESTART flag so accept() will return EINTR when signal arrives.
     */
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        syslog(LOG_ERR, "sigaction SIGINT failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        syslog(LOG_ERR, "sigaction SIGTERM failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Prepare address info for getaddrinfo.
     * AF_UNSPEC allows IPv4 or IPv6, AI_PASSIVE means bind to wildcard address.
     */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &res)) != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    /* Create and bind socket (try each address from getaddrinfo) */
    for (p = res; p != NULL; p = p->ai_next) {
        listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listen_fd == -1) {
            continue;  /* Try next address */
        }
        
        /* Enable SO_REUSEADDR to allow binding to recently closed ports */
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            syslog(LOG_WARNING, "setsockopt SO_REUSEADDR failed: %s", strerror(errno));
            /* Continue anyway - not critical */
        }
        
        if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(listen_fd);
            listen_fd = -1;
            continue;  /* Try next address */
        }
        break;  /* Successfully bound */
    }
    freeaddrinfo(res);

    if (p == NULL) {
        syslog(LOG_ERR, "Failed to bind to any address");
        exit(EXIT_FAILURE);
    }

    /* Start listening for incoming connections */
    if (listen(listen_fd, BACKLOG) == -1) {
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    /* Daemonize if requested (after socket setup, before accepting connections).
     * Double-fork technique ensures the daemon is not a session leader.
     */
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "fork failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            /* Parent exits immediately */
            exit(EXIT_SUCCESS);
        }
        /* First child continues */
        if (setsid() < 0) {
            syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        /* Second fork to ensure we're not a session leader */
        pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "second fork failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            exit(EXIT_SUCCESS);
        }
        
        /* Second child (daemon) continues */
        chdir("/");  /* Change to root directory */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        /* Redirect stdio to /dev/null */
        open("/dev/null", O_RDONLY);
        open("/dev/null", O_WRONLY);
        open("/dev/null", O_WRONLY);
        syslog(LOG_INFO, "Daemon started successfully");
    } else {
        printf("Server : Waiting for Connection on port %s ...\n", PORT);
    }

    /* Start timestamp thread - writes timestamp to file every 10 seconds */
    int ts_ret = pthread_create(&timestamp_tid, NULL, timestamp_thread, NULL);
    if (ts_ret != 0) {
        syslog(LOG_ERR, "pthread_create timestamp thread failed: %s", strerror(ts_ret));
        close(listen_fd);
        exit(EXIT_FAILURE);
    }
    timestamp_started = 1;

    /* Adjust receive buffer size (optional optimization) */
    int rcvbuf = RECV_BUF_SIZE;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1) {
        syslog(LOG_WARNING, "setsockopt SO_RCVBUF failed: %s", strerror(errno));
        /* Continue anyway - not critical */
    }

    /* Remove any existing data file (start fresh) */
    remove(FILE_NAME);

    /* Main accept loop - accept connections and spawn worker threads */
    while (!stop_program) {
        sin_size = sizeof their_addr;
        int new_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            if (errno == EINTR && stop_program) {
                /* Interrupted by signal and stop requested - exit loop */
                break;
            }
            /* Other errors (e.g., EAGAIN) - continue and try again */
            continue;
        }

        /* Get client IP address for logging */
        char client_ip[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),
                  client_ip, sizeof client_ip);

        if (!daemon_mode) {
            printf("Server Getting Cnx From %s\n", client_ip);
        }
        syslog(LOG_INFO, "Accepted connection from %s", client_ip);

        /* Allocate per-connection thread data */
        thread_variable_t *tdata = malloc(sizeof(thread_variable_t));
        if (!tdata) {
            syslog(LOG_ERR, "malloc failed for thread data");
            close(new_fd);
            continue;
        }
        tdata->new_fd = new_fd;
        tdata->daemon_mode = daemon_mode;
        strncpy(tdata->client_ip, client_ip, sizeof(tdata->client_ip));
        tdata->client_ip[sizeof(tdata->client_ip)-1] = '\0';

        /* Create a joinable worker thread */
        pthread_t tid;
        int cr = pthread_create(&tid, NULL, connection_handler, (void*)tdata);
        if (cr != 0) {
            syslog(LOG_ERR, "pthread_create failed: %s", strerror(cr));
            close(new_fd);
            free(tdata);
            continue;
        }
        /* Add to linked list for future join/cleanup */
        add_thread_node(tid, tdata);

        /* Reap finished threads (non-blocking) to avoid memory leak */
        reap_finished_threads();
    }

    /* Primary shutdown: stop accepting, join remaining threads */
    syslog(LOG_INFO, "Server shutting down, cleaning up threads");
    
    /* Close listen socket if still open (already closed by signal handler if signaled) */
    if (listen_fd != -1) {
        close(listen_fd);
        listen_fd = -1;
    }

    /* Join remaining worker threads (blocking joins) */
    pthread_mutex_lock(&thread_list_mutex);
    thread_node_t *node = thread_list_head;
    thread_list_head = NULL;
    pthread_mutex_unlock(&thread_list_mutex);

    while (node) {
        thread_node_t *next = node->next;
        /* Wait for thread to finish (blocking join) */
        pthread_join(node->tid, NULL);
        if (node->tdata) free(node->tdata);
        free(node);
        node = next;
    }

    /* Join timestamp thread if it was started */
    if (timestamp_started) {
        pthread_join(timestamp_tid, NULL);
    }

    /* Clean up: remove data file */
    remove(FILE_NAME);

    /* Destroy mutexes */
    pthread_mutex_destroy(&thread_list_mutex);
    pthread_mutex_destroy(&file_mutex);
    
    /* Close syslog */
    closelog();

    return 0;
}