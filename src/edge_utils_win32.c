/**
 * (C) 2007-20 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifdef WIN32

#include "edge_utils_win32.h"
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

/* ************************************** */

static DWORD* tunReadThread(LPVOID lpArg) {
  struct tunread_arg *arg = (struct tunread_arg*)lpArg;

  while(*arg->keep_running)
	  edge_read_from_tap(arg->eee);

  return((DWORD*)NULL);
}

/* ************************************** */

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
HANDLE startTunReadThread(struct tunread_arg *arg) {
  DWORD dwThreadId;

  return(CreateThread(NULL,         /* security attributes */
		      0,            /* use default stack size */
		      (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
		      (void*)arg,   /* argument to thread function */
		      0,            /* thread creation flags */
		      &dwThreadId)); /* thread id out */
}

/* ************************************** */

int get_all_local_addresses_win32(n2n_sock_t *local_socks, uint8_t *num_addrs, uint8_t max_addrs) {
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    ULONG outBufLen = 15000;
    DWORD dwRetVal = 0;
    uint8_t count = 0;

    *num_addrs = 0;

    pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
    if (pAddresses == NULL) {
        return -1;
    }

    dwRetVal = GetAdaptersAddresses(AF_INET,
                                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                    NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
        if (pAddresses == NULL) {
            return -1;
        }
        dwRetVal = GetAdaptersAddresses(AF_INET,
                                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                        NULL, pAddresses, &outBufLen);
    }

    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses && count < max_addrs) {
            pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast && count < max_addrs) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
                    uint32_t ip = ntohl(addr->sin_addr.s_addr);

                    /* Skip loopback */
                    if ((ip & 0xFF000000) == 0x7F000000) {
                        pUnicast = pUnicast->Next;
                        continue;
                    }

                    /* Check if it's a private IP */
                    if ((ip & 0xFF000000) == 0x0A000000 ||      /* 10.0.0.0/8 */
                        (ip & 0xFFF00000) == 0xAC100000 ||      /* 172.16.0.0/12 */
                        (ip & 0xFFFF0000) == 0xC0A80000) {      /* 192.168.0.0/16 */

                        local_socks[count].family = AF_INET;
                        memcpy(local_socks[count].addr.v4, &addr->sin_addr.s_addr, 4);
                        local_socks[count].port = 0;
                        count++;
                    }
                }
                pUnicast = pUnicast->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    free(pAddresses);
    *num_addrs = count;

    if (count == 0) {
        return -1;
    }

    return 0;
}
#endif

