#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#define NUM_ARGS 3 // Program name + writefile + writestr

int main(int argc, char *argv[]) {
    FILE *file;
    const char *writefile;
    const char *writestr;

    openlog("writer_app", LOG_PID | LOG_CONS, LOG_USER);

    if (argc != NUM_ARGS) {
        syslog(LOG_ERR, "Error: Invalid number of arguments. Expected %d, got %d.", NUM_ARGS - 1, argc - 1);
        fprintf(stderr, "Usage: %s <writefile> <writestr>\n", argv[0]);
        closelog();
        return 1;
    }

    writefile = argv[1];
    writestr = argv[2];

    syslog(LOG_DEBUG, "Writing \"%s\" to %s", writestr, writefile);

    file = fopen(writefile, "w");

    if (file == NULL) {
        syslog(LOG_ERR, "Error: Could not open or create file %s. %s", writefile, strerror(errno));
        closelog();
        return 1;
    }

    if (fprintf(file, "%s", writestr) < 0) {
        syslog(LOG_ERR, "Error writing string to file %s: %s", writefile, strerror(errno));
        fclose(file);
        closelog();
        return 1;
    }

    fclose(file);
    closelog();

    return 0; // Success
}
