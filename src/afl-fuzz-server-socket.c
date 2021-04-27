/*
   american fuzzy lop++ - socket_mode implementation
   ---------------------------------------------------------------

   Copyright 2021 by Airbus CyberSecurity - Flavian Dola

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<pthread.h>
#include "config.h"
#include "afl-fuzz.h"


#define CLOSE_SOCKET(sock)({if (sock != -1) {close(sock); sock = -1;} })

#define SZ_BUF 80
#define SA struct sockaddr

unsigned char *afl_area_ptr = NULL;
unsigned long afl_prev_loc = 0;
int isSocketServerRunning = 0;
pthread_t socketServer_thread_id;
int sockfd = -1;
int connfd = -1;




void reset_prev_loc()
{
    afl_prev_loc = 0;
}


int afl_setup(afl_forkserver_t* fsrv) {

    afl_area_ptr = (unsigned char *)fsrv->trace_bits;
    //memset(fsrv->trace_bits, 0, MAP_SIZE);
    return 1;
}



void afl_maybe_log(afl_forkserver_t* fsrv, unsigned long cur_loc) {

  if (afl_area_ptr == NULL) {
        afl_setup(fsrv);
  }
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  unsigned long afl_idx = cur_loc ^ afl_prev_loc;
  afl_idx &= fsrv->map_size - 1;
  //SAYF("0x%08X - 0x%04X\n", cur_loc, afl_idx);
  afl_area_ptr[afl_idx]++;
  afl_prev_loc = cur_loc >> 1;
}



void get_exec_addr(afl_forkserver_t* fsrv)
{
    char buff[SZ_BUF];
    int r = 0;

    for (;;) {
        bzero(buff, SZ_BUF);
        r = read(connfd, buff, 4);
        //SAYF("From client: 0x%08X\n", *(unsigned long*)buff);

        if (r != 4) {
            break;
        }

        if (*(unsigned long*)buff == 0)
        {
            //SAYF("Server Exit...\n");
            break;
        }

        afl_maybe_log(fsrv, *(unsigned long*) buff);
    }

}





void *server_handler(void* arg)
{

    int len;
    struct sockaddr_in servaddr, cli;
    int enable = 1;

    afl_forkserver_t* fsrv = (afl_forkserver_t*)arg;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        FATAL("socket creation failed!");
    }
    else {
        SAYF("Socket successfully created..\n");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        FATAL("setsockopt(SO_REUSEADDR) failed");
    }

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(fsrv->socket_port);

    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        CLOSE_SOCKET(sockfd);
        FATAL("socket bind failed...\n");
    }
    else {
        SAYF("Socket successfully binded..\n");
    }

    if ((listen(sockfd, 5)) != 0) {
        CLOSE_SOCKET(sockfd);
        FATAL("Listen failed...\n");
    }
    else {
        SAYF("Server listening..\n");
    }
    len = sizeof(cli);

    isSocketServerRunning = 1;
    while (isSocketServerRunning)
    {
        // Accept the data packet from client and verification
        connfd = accept(sockfd, (SA*)&cli, &len);
        if (connfd < 0) {
            CLOSE_SOCKET(sockfd);
            FATAL("server acccept failed...\n");
        }
        else
        {
            //SAYF("server acccept the client...\n");
            ;;
        }

        // work with received address (code coverage)
        get_exec_addr(fsrv);
        CLOSE_SOCKET(connfd);
    }

    CLOSE_SOCKET(sockfd);

    return NULL;
}

int start_server_tcp(afl_forkserver_t *fsrv)
{
    return pthread_create( &socketServer_thread_id , NULL ,  server_handler , (void*) fsrv);
}


void stop_server_tcp()
{
    //SAYF("Stopping Server TCP...\n");
    isSocketServerRunning = 0;

    CLOSE_SOCKET(connfd);
    CLOSE_SOCKET(sockfd);

    sleep(1);
    pthread_cancel(socketServer_thread_id);
    //SAYF("Server TCP stopped!\n");
}
