#!/usr/bin/python2

"""
Copyright 2021 by Airbus CyberSecurity - Flavian Dola

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import socket
import struct
import os
import signal
import time

LOG_FILE = "/tmp/afl_ghidra_bridge.log"
LOG_F = None

SOCK_GHIDRA = None

CONFIG = "\x02"
STOP = "\xff"



def force_crash():
    os.kill(os.getpid(), signal.SIGSEGV)



def close_all():
    global SOCK_GHIDRA
    global LOG_F

    if SOCK_GHIDRA is not None:
        try:
            SOCK_GHIDRA.shutdown(socket.SHUT_RDWR)
        except:
            pass
        SOCK_GHIDRA.close()
        SOCK_GHIDRA = None

    if LOG_F is not None:
        LOG_F.close()
        LOG_F = None

    return



def connect_ghidra(ghidra_host, ghidra_port):
    global SOCK_GHIDRA
    global LOG_F

    if SOCK_GHIDRA is not None:
        return True

    SOCK_GHIDRA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCK_GHIDRA.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        SOCK_GHIDRA.connect((ghidra_host, ghidra_port))
    except Exception as e:
        LOG_F.write("Error on connect to Ghidra host: %s\n" % str(e))
        LOG_F.flush()
        return False

    return True





def main():
    global LOG_F
    global SOCK_GHIDRA

    LOG_F = open(LOG_FILE, "a")

    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Enable debug tracing")
    parser.add_argument('-H', '--ghidra-host', default=True, type=str, help="Ghidra host")
    parser.add_argument('-P', '--ghidra-port', default=True, type=int, help="Ghidra port")
    parser.add_argument('-a', '--afl-host', default=False, type=str, help="AFL host")
    parser.add_argument('-p', '--afl-port', default=False, type=int, help="AFL port")
    parser.add_argument('-i', '--input-file', default=False, type=str, help="Input testcase file")
    parser.add_argument('-s', '--stop', default=False, action="store_true", help="Stop ghidra emulation")
    args = parser.parse_args()




    if args.stop:
        r = connect_ghidra(args.ghidra_host, args.ghidra_port)
        if not r:
            return

        SOCK_GHIDRA.sendall(STOP+"STOP")
        return

    elif (args.afl_host is not None) & (args.afl_port is not None) & (args.input_file is not None):
        f = open(args.input_file, "rb")
        data_input = f.read()
        f.close()

        """
        # Optimize fuzz => skip bad size input
        if len(data_input) != 8:
            close_all()
            return
        """

        r = connect_ghidra(args.ghidra_host, args.ghidra_port)
        if not r:
            return

        config_frame = CONFIG
        config_frame += struct.pack("B", len(args.afl_host))
        config_frame += args.afl_host
        config_frame += struct.pack("<H", args.afl_port)
        config_frame += struct.pack("<H", len(data_input[:0xf000]))
        config_frame += data_input[:0xf000]

        LOG_F.write("Send config: %s\n" % config_frame.encode("hex"))
        LOG_F.flush()

        SOCK_GHIDRA.sendall(config_frame)


        while True:
            data = SOCK_GHIDRA.recv(1024)
            if data == "END":
                # Ghidra emulation finished
                #LOG_F.write("Ghidra emulation end\n")
                #LOG_F.flush()
                break

            if data == "CRASH":
                # Ghidra emulation crash
                # simulate crash
                LOG_F.write("Ghidra emulation crash\n")
                LOG_F.flush()
                close_all()
                force_crash()
                time.sleep(10)
        return

    else:
        print("Bad args")
        return


if __name__ == '__main__':
    main()
    close_all()
