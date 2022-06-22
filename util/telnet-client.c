/*
 * Sean Middleditch
 * sean@sourcemud.org
 *
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law. 
 */

#if !defined(_BSD_SOURCE)
    #define _BSD_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <termios.h>
#include <unistd.h>

/* MOD: add regex */
#include <regex.h>

#ifdef HAVE_ZLIB
    #include "zlib.h"
#endif

#include "libtelnet.h"

static struct termios orig_tios;
static telnet_t *     telnet;
static int            do_echo;

static const telnet_telopt_t telopts[] = {
    {TELNET_TELOPT_ECHO, TELNET_WONT, TELNET_DO},
    {TELNET_TELOPT_TTYPE, TELNET_WILL, TELNET_DONT},
    {TELNET_TELOPT_COMPRESS2, TELNET_WONT, TELNET_DO},
    {TELNET_TELOPT_MSSP, TELNET_WONT, TELNET_DO},
    {-1, 0, 0}};

typedef struct trendnet_commands
{
    char * buffer; /*!< command to be sent */
    int    size;   /*!< =buffer size */
} trendnet_commands;

static const trendnet_commands cmds[] = {
    {"", 0},
    {"admin\n", 6},
    {"enable\n", 7},
    {"admin\n", 6},
    {"admin\n", 6},
    {"show mac-address-table\n", 23},
    // {"configure terminal\n", 19},
    // {"interface range gigabitethernet1/0/ 8\n", 38},
    // {"poe enable\n", 38},
    // {"exit\n", 5},
    // {"exit\n", 5},
    {"exit\n", 5},
    {"\0", -1}};

static const trendnet_commands prmpt[] = {
    {"\r\r\n", 3},
    {"TI-PG102i login: ", 17},
    {"TI-PG102i>", 10},
    {"user:", 5},
    {"password:", 9},
    {"TI-PG102i#", 10},
    {"TI-PG102i#", 10},
    // {"TI-PG102i(config)#", 18},
    // {"TI-PG102i(config-if-range)#", 27},
    // {"TI-PG102i(config-if-range)#", 27},
    // {"TI-PG102i(config)#", 18},
    {"TI-PG102i#", 10},
    {"\0", -1}};

const char mac_table[12 + 1][128];

char       termBuffer[1024] = {0};
regex_t    mac_regex;
size_t     nmatch = 7;
regmatch_t pmatch[7];
int        cmd_num    = 0;
uint8_t    prmpt_flag = 0;

static const void _cleanup(void)
{
    tcsetattr(STDOUT_FILENO, TCSADRAIN, &orig_tios);
}

static void _input(char * buffer, int size)
{
    static char crlf[] = {'\r', '\n'};
    int         i;

    for(i = 0; i != size; ++i)
    {
        /* if we got a CR or LF, replace with CRLF
		 * NOTE that usually you'd get a CR in UNIX, but in raw
		 * mode we get LF instead (not sure why)
		 */
        if(buffer[i] == '\r' || buffer[i] == '\n')
        {
            if(do_echo)
                printf("\r\n");
            telnet_send(telnet, crlf, 2);
        }
        else
        {
            if(do_echo)
                putchar(buffer[i]);
            telnet_send(telnet, buffer + i, 1);
        }
    }
    fflush(stdout);
}

static void _send(int sock, const char * buffer, size_t size)
{
    int rs;

    /* send data */
    while(size > 0)
    {
        if((rs = send(sock, buffer, size, 0)) == -1)
        {
            fprintf(stderr, "send() failed: %s\n", strerror(errno));
            exit(1);
        }
        else if(rs == 0)
        {
            fprintf(stderr, "send() unexpectedly returned 0\n");
            exit(1);
        }

        /* update pointer and size to see if we've got more to send */
        buffer += rs;
        size -= rs;
    }
}

static void _event_handler(telnet_t * telnet, telnet_event_t * ev,
                           void * user_data)
{
    int sock  = *(int *)user_data;
    /* MOD: regex debug */
    int value = -1;

    switch(ev->type)
    {
        /* data received */
        case TELNET_EV_DATA_PRMPT:
        {
            /* TODO: deubg */

            // printf("\r\n<");
            // for(int i = 0; i < ev->data.size; i++)
            // {
            //     printf("%02X", ev->data.buffer[i]);
            // }
            // printf(">");
            uint8_t match = 1;
            // char *  tempBuffer = malloc(ev->data.size + 1);
            memset(termBuffer, 0, sizeof(termBuffer));
            memcpy(termBuffer, ev->data.buffer, ev->data.size);

            // size_t start = 0;
            // while(start < sizeof(termBuffer))
            // {
            //     // printf("\r\nstart=%d", start);
            //     value = regexec(&mac_regex, termBuffer + start, nmatch, pmatch, 0);

            //     if(0 == value)
            //     {
            //         // for(int m = 0; m < nmatch; m++)
            //         // {
            //         //     printf("\r\npmatch[%d]=\"%.*s\"", m, pmatch[m].rm_eo - pmatch[m].rm_so, &termBuffer[pmatch[m].rm_so]);
            //         // }
            //         char address[128] = {0};
            //         char port[128]    = {0};
            //         memcpy(address, &termBuffer[pmatch[1].rm_so], pmatch[1].rm_eo - pmatch[1].rm_so);
            //         memcpy(port, &termBuffer[pmatch[6].rm_so], pmatch[6].rm_eo - pmatch[6].rm_so);

            //         int port_num = atoi(port);
            //         if(0 != strcmp(address, mac_table[port_num]))
            //         {
            //             printf("\r\nNEW MAC=\"%s\", port=%d", address, port_num);
            //             memcpy(mac_table[port_num], address, sizeof(mac_table[port_num]));

            //             for(int mac = 0; mac < 13; mac++)
            //             {
            //                 if(mac != port_num && 0 == strcmp(mac_table[mac], mac_table[port_num]))
            //                 {
            //                     memset(mac_table[mac], 0, sizeof(mac_table[mac]));
            //                     printf("\r\nMOVED MAC=\"%s\", port=%d->%d", address, mac, port_num);
            //                 }
            //             }
            //         }

            //         start += pmatch[0].rm_eo;
            //         // printf("\r\nupdated start=%d", start);
            //     }
            //     else
            //     {
            //         start = sizeof(termBuffer);
            //         // printf("\r\nEND=%d", start);
            //         break;
            //     }
            // }
            // printf("\r\nend processing termBuffer");

            for(int c = 0; c < prmpt[cmd_num].size; c++)
            {
                if(prmpt[cmd_num].buffer[c] != ev->data.buffer[c])
                {
                    match = 0;
                    break;
                }
            }

            if(1 == match && 0 == prmpt_flag)
            {
                prmpt_flag = 1;
            }
        }
        break;
        case TELNET_EV_DATA:
        {
            // printf("\r\nTELNET_EV_DATA");
            size_t start = 0;
            while(start < strlen(termBuffer))
            {
                printf("\r\nstart=%d", start);
                value = regexec(&mac_regex, &termBuffer[start], nmatch, pmatch, 0);
                if(strlen(&termBuffer[start]) >= 40)
                {
                    // printf("\r\n<");
                    // for(int i = 0; i < 40; i++)
                    // {
                    //     printf("%02X|%c ", termBuffer[start + i], termBuffer[start + i]);
                    // }
                    // printf(">");
                    printf("\r\n<");
                    for(int i = 0; i < 40; i++)
                    {
                        printf("%c", termBuffer[start + i], termBuffer[start + i]);
                    }
                    printf(">");
                }

                if(0 == value)
                {
                    for(int m = 0; m < nmatch; m++)
                    {
                        printf("\r\npmatch[%d]=\"%.*s\"", m, pmatch[m].rm_eo - pmatch[m].rm_so, &termBuffer[pmatch[m].rm_so]);
                    }
                    char address[128] = {0};
                    char port[128]    = {0};
                    memcpy(address, &termBuffer[pmatch[1].rm_so], pmatch[1].rm_eo - pmatch[1].rm_so);
                    memcpy(port, &termBuffer[pmatch[6].rm_so], pmatch[6].rm_eo - pmatch[6].rm_so);

                    int port_num = atoi(port);
                    if(0 != strcmp(address, mac_table[port_num]))
                    {
                        printf("\r\nNEW MAC=\"%s\", port=%d", address, port_num);
                        memcpy(mac_table[port_num], address, sizeof(mac_table[port_num]));

                        for(int mac = 0; mac < 13; mac++)
                        {
                            if(mac != port_num && 0 == strcmp(mac_table[mac], mac_table[port_num]))
                            {
                                memset(mac_table[mac], 0, sizeof(mac_table[mac]));
                                printf("\r\nMOVED MAC=\"%s\", port=%d->%d", address, mac, port_num);
                            }
                        }
                    }

                    start += pmatch[0].rm_eo + 2;
                    printf("\r\nupdated start=%d", start);
                }
                else
                {
                    start = strlen(termBuffer);
                    printf("\r\nEND=%d\r\n", start);
                    break;
                }
            }

            if(ev->data.size && fwrite(ev->data.buffer, 1, ev->data.size, stdout) != ev->data.size)
            {
                fprintf(stderr, "ERROR: Could not write complete buffer to stdout");
            }
            if(0 == value)
            {
                printf("\r\n>%s", pmatch[0]);
            }
            fflush(stdout);
        }

        break;
        /* data must be sent */
        case TELNET_EV_SEND:
            _send(sock, ev->data.buffer, ev->data.size);
            break;
        /* request to enable remote feature (or receipt) */
        case TELNET_EV_WILL:
            /* we'll agree to turn off our echo if server wants us to stop */
            if(ev->neg.telopt == TELNET_TELOPT_ECHO)
                do_echo = 0;
            break;
        /* notification of disabling remote feature (or receipt) */
        case TELNET_EV_WONT:
            if(ev->neg.telopt == TELNET_TELOPT_ECHO)
                do_echo = 1;
            break;
        /* request to enable local feature (or receipt) */
        case TELNET_EV_DO:
            break;
        /* demand to disable local feature (or receipt) */
        case TELNET_EV_DONT:
            break;
        /* respond to TTYPE commands */
        case TELNET_EV_TTYPE:
            /* respond with our terminal type, if requested */
            if(ev->ttype.cmd == TELNET_TTYPE_SEND)
            {
                telnet_ttype_is(telnet, getenv("TERM"));
            }
            break;
        /* respond to particular subnegotiations */
        case TELNET_EV_SUBNEGOTIATION:
            break;
        /* error */
        case TELNET_EV_ERROR:
            fprintf(stderr, "ERROR: %s\n", ev->error.msg);
            exit(1);
        default:
            /* ignore */
            break;
    }
}

int main(int argc, char ** argv)
{
    char               buffer[512];
    char               tbuffer[512];
    char               rbuffer[512];
    int                rs;
    int                sock;
    struct sockaddr_in addr;
    struct pollfd      pfd[2];
    struct addrinfo *  ai;
    struct addrinfo    hints;
    struct termios     tios;
    const char *       servname;
    const char *       hostname;

    /* check usage */
    if(argc < 2)
    {
        fprintf(stderr, "Usage:\n ./telnet-client <host> [port]\n");
        return 1;
    }

    /* process arguments */
    servname = (argc < 3) ? "23" : argv[2];
    hostname = argv[1];

    /* look up server host */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if((rs = getaddrinfo(hostname, servname, &hints, &ai)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for %s: %s\n", hostname,
                gai_strerror(rs));
        return 1;
    }

    /* create server socket */
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        return 1;
    }

    /* bind server socket */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        close(sock);
        return 1;
    }

    /* connect */
    if(connect(sock, ai->ai_addr, ai->ai_addrlen) == -1)
    {
        fprintf(stderr, "connect() failed: %s\n", strerror(errno));
        close(sock);
        return 1;
    }

    /* free address lookup info */
    freeaddrinfo(ai);

    /* get current terminal settings, set raw mode, make sure we
	 * register atexit handler to restore terminal settings
	 */
    tcgetattr(STDOUT_FILENO, &orig_tios);
    atexit(_cleanup);
    tios = orig_tios;
    cfmakeraw(&tios);
    tcsetattr(STDOUT_FILENO, TCSADRAIN, &tios);

    /* set input echoing on by default */
    do_echo = 1;

    /* initialize telnet box */
    telnet = telnet_init(telopts, _event_handler, 0, &sock);

    /* initialize poll descriptors */
    memset(pfd, 0, sizeof(pfd));
    pfd[0].fd     = STDIN_FILENO;
    pfd[0].events = POLLIN;
    pfd[1].fd     = sock;
    pfd[1].events = POLLIN;
    int reti;

    // reti = regcomp(&mac_regex, "(([0-9A-F]{2}:){5}([0-9A-F]{2})) +([A-Za-z]+) +([0-9]) +([0-9]+)$", REG_EXTENDED);
    reti = regcomp(&mac_regex, "(([0-9A-F]{2}:){5}([0-9A-F]{2})) +([A-Za-z]+) +([0-9]) +([0-9]+)", REG_EXTENDED | REG_NEWLINE);
    if(reti)
    {
        fprintf(stderr, "Could not compile regex\n");
        exit(1);
    }
    /* loop while both connections are open */
    while(poll(pfd, 2, -1) != -1)
    {
        /* read from stdin */
        if(pfd[0].revents & (POLLIN | POLLERR | POLLHUP))
        {
            if((rs = read(STDIN_FILENO, tbuffer, sizeof(tbuffer))) > 0)
            {
                _input(tbuffer, rs);
            }
            else if(rs == 0)
            {
                break;
            }
            else
            {
                fprintf(stderr, "recv(server) failed: %s\n",
                        strerror(errno));
                exit(1);
            }
        }
        /* read from client */
        if(pfd[1].revents & (POLLIN | POLLERR | POLLHUP))
        {
            if((rs = recv(sock, rbuffer, sizeof(rbuffer), 0)) > 0)
            {
                telnet_recv(telnet, rbuffer, rs);
            }
            else if(rs == 0)
            {
                break;
            }
            else
            {
                fprintf(stderr, "recv(client) failed: %s\n",
                        strerror(errno));
                exit(1);
            }
        }

        if(1 == prmpt_flag)
        {
            /* read from cmds */
            if(0 <= cmds[cmd_num].size)
            {
                _input(cmds[cmd_num].buffer, cmds[cmd_num].size);
                /* TODO: debug */

                // printf("\r\n%s", cmds[cmd_num].buffer);
                cmd_num++;
                prmpt_flag = 0;
            }
        }
    }

    for(int mac = 0; mac < 13; mac++)
    {
        printf("\r\nMAC=\"%s\", port=%d", mac_table[mac], mac);
    }
    printf("\r\n");
    /* clean up */
    regfree(&mac_regex);
    telnet_free(telnet);
    close(sock);

    return 0;
}

// (mkdir -p build && cd build && cmake .. && make) && clear && ./build/util/telnet-client 192.168.10.200 23
/*
Total Entries: 3
MAC Address        Type      VLAN  Port
-----------------  --------  ----  ----
00:E0:4C:68:A1:74  Dynamic   1     10
00:0C:C8:05:CA:00  Dynamic   1     8
D8:EB:97:C9:4A:ED  Static    1     CPU


******************* Multicast Group ****************
Total entries: 0.

Group  IP        Server IP        Status    VLAN  Ports
---------------  ---------------  --------  ----  ---------------------------------------
*/