/*
   american fuzzy lop++ - socket_mode header
   ---------------------------------------------------------------

   Copyright 2021 by Airbus CyberSecurity - Flavian Dola

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/


#ifndef _SOCKET_SERVER_H
#define _SOCKET_SERVER_H

#include <pthread.h>
#include "forkserver.h"


void reset_prev_loc();
int start_server_tcp(afl_forkserver_t *fsrv);
void stop_server_tcp();

#endif

