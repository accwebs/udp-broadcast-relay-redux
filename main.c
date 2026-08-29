/*
******************************************************************
udp-broadcast-relay-redux
    Relays UDP broadcasts to other networks, forging
    the sender address.

Copyright (c) 2017 UDP Broadcast Relay Redux Contributors
  <github.com/udp-redux/udp-broadcast-relay-redux>
Copyright (c) 2003 Joachim Breitner <mail@joachim-breitner.de>
Copyright (C) 2002 Nathan O'Sullivan

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
******************************************************************
*/

#define MAXIFS    256
#define MAXMULTICAST 256
#define MAXTARGETS 256
#define DPRINT  if (debug) printf
#define IPHEADER_LEN 20
#define UDPHEADER_LEN 8
#define HEADER_LEN (IPHEADER_LEN + UDPHEADER_LEN)
#define TTL_ID_OFFSET 64

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#ifdef __FreeBSD__
#include <net/if.h>
#include <net/if_dl.h>
#else
#include <linux/if.h>
#endif
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

/* list of addresses and interface numbers on local machine */
struct Iface {
    char* name;
    struct in_addr dstaddr;
    struct in_addr ifaddr;
    int ifindex;
    int raw_socket;
};
static struct Iface ifs[MAXIFS];

/* A parsed -t entry: either global (ifaceName == NULL) or scoped to one
 * --dev interface name. */
struct TargetOverride {
    const char* ifaceName;
    struct in_addr addr;
};
static struct TargetOverride targetOverrides[MAXTARGETS];
static size_t targetOverridesNum = 0;

/* Where we forge our packets */
static u_char gram[4096]=
{
    0x45,    0x00,    0x00,    0x26,
    0x12,    0x34,    0x00,    0x00,
    0xFF,    0x11,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0x00,    0x12,    0x00,    0x00,
    '1','2','3','4','5','6','7','8','9','0'
};

void inet_ntoa2(struct in_addr in, char* chr, int len) {
    char* from = inet_ntoa(in);
    strncpy(chr, from, len);
}

/* Parses the -t cli argument */
struct TargetOverride parse_target_override(const char* const argValue) {
    // Optional "iface:" prefix, split on the first ':'.
    // Codebase is IPv4-only, so no address contains a colon.
    struct TargetOverride result;
    char* ifaceName = NULL;
    const char* addressStr = argValue;
    const char* colon = strchr(argValue, ':');
    if (colon != NULL) {
        size_t ifaceLen = colon - argValue;
        ifaceName = malloc(ifaceLen + 1);
        if (ifaceName == NULL) {
            perror("malloc");
            exit(1);
        }
        memcpy(ifaceName, argValue, ifaceLen);
        ifaceName[ifaceLen] = '\0';
        addressStr = colon + 1;
    }
    struct in_addr converted;
    if (inet_aton(addressStr, &converted) == 0) {
        fprintf (stderr,"invalid target IP address: %s\n", addressStr);
        exit(1);
    }
    result.ifaceName = ifaceName;
    result.addr = converted;
    return result;
}

/* Resolve a -t override address for a specific outgoing interface.
 * 255.255.255.255 means "this interface's broadcast/peer address"
 * (iface->dstaddr, populated at startup); anything else is used verbatim. */
struct in_addr resolve_target_addr_override(const struct in_addr target_addr_override,
                                            const struct Iface* const iface) {
    if (target_addr_override.s_addr == INADDR_BROADCAST) {
        // rewrite to new interface broadcast addr if user specified 255.255.255.255
        return iface->dstaddr;
    }
    // else use the specified value verbatim
    return target_addr_override;
}

/* Append addr to out[*count], bounds-checked against cap. */
void push_addr(struct in_addr* const out, size_t* const count, const size_t cap,
              const struct in_addr addr) {
    if (*count >= cap) {
        perror("to_addresses_out too small");
        exit(1);
    }
    out[(*count)++] = addr;
}

/* Determine target address(es) for this outgoing interface.
 * Entries qualified to this interface's name fully replace the bare fallback
 * (and the default resolution) for it; absent those, bare entries apply;
 * absent those, fall through to the default resolution below, unchanged from before. */
size_t resolve_to_addresses(const struct in_addr rcv_inaddr,
                            const struct Iface* const from_iface,
                            const struct Iface* const to_iface,
                            struct in_addr* const to_addresses_out,
                            const size_t to_addresses_out_len) {
    size_t to_addresses_counter = 0;
    for (size_t iOv = 0; iOv < targetOverridesNum; iOv++) {
        if (targetOverrides[iOv].ifaceName != NULL
            && to_iface->name != NULL
            && strcmp(targetOverrides[iOv].ifaceName, to_iface->name) == 0) {
            push_addr(to_addresses_out, &to_addresses_counter, to_addresses_out_len,
                resolve_target_addr_override(targetOverrides[iOv].addr, to_iface));
        }
    }
    if (to_addresses_counter == 0) {
        for (size_t iOv = 0; iOv < targetOverridesNum; iOv++) {
            if (targetOverrides[iOv].ifaceName == NULL) {
                push_addr(to_addresses_out, &to_addresses_counter, to_addresses_out_len,
                    resolve_target_addr_override(targetOverrides[iOv].addr, to_iface));
            }
        }
    }
    if (to_addresses_counter == 0) {
        if (rcv_inaddr.s_addr == INADDR_BROADCAST
            || rcv_inaddr.s_addr == from_iface->dstaddr.s_addr) {
            // Received on interface broadcast address -- rewrite to new interface broadcast addr
            push_addr(to_addresses_out, &to_addresses_counter, to_addresses_out_len, to_iface->dstaddr);
        }
        else {
            // Send to whatever IP it was originally to
            push_addr(to_addresses_out, &to_addresses_counter, to_addresses_out_len, rcv_inaddr);
        }
    }
    return to_addresses_counter;
}

int main(int argc,char **argv) {
    /* Debugging, forking, other settings */
    int debug = 0, forking = 0;
    u_int16_t port = 0;
    u_char id = 0;
    char* multicastAddrs[MAXMULTICAST];
    int multicastAddrsNum = 0;
    char* interfaceNames[MAXIFS];
    int interfaceNamesNum = 0;
    in_addr_t spoof_addr = 0;

    /* Address broadcast packet was sent from */
    struct sockaddr_in rcv_addr;
    struct msghdr rcv_msg;
    struct iovec iov;
    iov.iov_base = gram + HEADER_LEN;
    iov.iov_len = 4006 - HEADER_LEN - 1;
    u_char pkt_infos[16384];
    rcv_msg.msg_name = &rcv_addr;
    rcv_msg.msg_namelen = sizeof(rcv_addr);
    rcv_msg.msg_iov = &iov;
    rcv_msg.msg_iovlen = 1;
    rcv_msg.msg_control = pkt_infos;
    rcv_msg.msg_controllen = sizeof(pkt_infos);

    if(argc < 2) {
        fprintf(stderr,"usage: %s [-d] [-f] [-s IP] [-t [iface:]IP]... [--id id] [--port udp-port] [--dev dev1]... [--multicast ip]...\n\n",*argv);
        fprintf(stderr,"This program listens for broadcast  packets  on the  specified UDP port\n"
            "and then forwards them to each other given interface.  Packets are sent\n"
            "such that they appear to have come from the original broadcaster, resp.\n"
            "from the spoofing IP in case -s is used.  When using multiple instances\n"
            "for the same port on the same network, they must have a different id.\n\n"
            "    -d      enables debugging\n"
            "    -f      forces forking to background\n"
            "    -s IP   sets the source IP of forwarded packets; otherwise the\n"
            "            original sender's address is used.\n"
            "            Setting to 1.1.1.1 uses outgoing interface address and broadcast port.\n"
            "            (helps in some rare cases)\n"
            "            Setting to 1.1.1.2 uses outgoing interface address and source port.\n"
            "            (helps in some rare cases)\n"
            "    -t      sets the destination IP of forwarded packets; otherwise the\n"
            "            original target is used.\n"
            "            Setting to 255.255.255.255 uses the broadcast address of the\n"
            "            outgoing interface.\n"
            "            Can be repeated. Qualify with iface:IP (e.g. -t tun0:10.0.0.2)\n"
            "            to apply only to packets sent out that --dev interface; a\n"
            "            qualified -t fully replaces the default/-t fallback for that\n"
            "            interface, and multiple -t for the same interface each send a\n"
            "            copy. An unqualified -t IP applies to any interface with no\n"
            "            qualified entry of its own.\n"
            "\n"
        );
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-d") == 0) {
            DPRINT ("Debugging Mode enabled\n");
            debug = 1;
        }
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-d") == 0) {
            // Already handled
        } else if (strcmp(argv[i],"-f") == 0) {
            DPRINT ("Forking Mode enabled\n");
            forking = 1;
        }
        else if (strcmp(argv[i],"-s") == 0) {
            /* INADDR_NONE is a valid IP address (-1 = 255.255.255.255),
             * so inet_pton() would be a better choice. But in this case it
             * does not matter. */
            i++;
            spoof_addr = inet_addr(argv[i]);
            if (spoof_addr == INADDR_NONE) {
                fprintf (stderr,"invalid source IP address: %s\n", argv[i]);
                exit(1);
            }
            DPRINT ("Outgoing source IP set to %s\n", argv[i]);
        }
        else if (strcmp(argv[i],"-t") == 0) {
            i++;
            const struct TargetOverride parsed = parse_target_override(argv[i]);
            if (targetOverridesNum >= MAXTARGETS) {
                fprintf (stderr,"too many -t targets (max %i)\n", MAXTARGETS);
                exit(1);
            }
            targetOverrides[targetOverridesNum] = parsed;
            targetOverridesNum++;
            if (parsed.ifaceName) {
                DPRINT ("Outgoing target IP for %s set to %s\n", parsed.ifaceName, inet_ntoa(parsed.addr));
            } else {
                DPRINT ("Outgoing target IP set to %s\n", inet_ntoa(parsed.addr));
            }
        }
        else if (strcmp(argv[i],"--id") == 0) {
            i++;
            id = atoi(argv[i]);
            DPRINT ("ID set to %i\n", id);
        }
        else if (strcmp(argv[i],"--port") == 0) {
            i++;
            port = atoi(argv[i]);
            DPRINT ("Port set to %i\n", port);
        }
        else if (strcmp(argv[i],"--dev") == 0) {
            i++;
            interfaceNames[interfaceNamesNum] = argv[i];
            interfaceNamesNum++;
        }
        else if (strcmp(argv[i],"--multicast") == 0) {
            i++;
            multicastAddrs[multicastAddrsNum] = argv[i];
            multicastAddrsNum++;
        }
        else if (strncmp(argv[i], "-", 1) == 0) {
            fprintf (stderr, "Unknown arg: %s\n", argv[i]);
            exit(1);
        }
        else {
            break;
        }
    }

    if (id < 1 || id > 99)
    {
        fprintf (stderr,"ID argument %i not between 1 and 99\n",id);
        exit(1);
    }
    if (port < 1 || port > 65535) {
        fprintf (stderr,"Port argument not valid\n");
        exit(1);
    }

    u_char ttl = id+TTL_ID_OFFSET;

    DPRINT ("ID: %i (ttl: %i), Port %i\n",id,ttl,port);

    /* We need to find out what IP's are bound to this host - set up a temporary socket to do so */
    int fd;
     if((fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0)
    {
          perror("socket");
        fprintf(stderr,"You must be root to create a raw socket\n");
          exit(1);
      };

    /* For each interface on the command line */
    int maxifs = 0;
    for (int i = 0; i < interfaceNamesNum; i++) {
        struct Iface* iface = &ifs[maxifs];
        iface->name = interfaceNames[i];

        struct ifreq basereq;
        strncpy(basereq.ifr_name,interfaceNames[i],IFNAMSIZ);

        /* Request index for this interface */
        {
            #ifdef ___APPLE__
                /*
                TODO: Supposedly this works for all OS, including non-Apple,
                and could replace the code below
                */
                iface->ifindex = if_nametoindex(interfaceNames[i]);
            #else
                struct ifreq req;
                memcpy(&req, &basereq, sizeof(req));
                if (ioctl(fd,SIOCGIFINDEX, &req) < 0) {
                    perror("ioctl(SIOCGIFINDEX)");
                    exit(1);
                }
                #ifdef __FreeBSD__
                iface->ifindex = req.ifr_index;
                #else
                iface->ifindex = req.ifr_ifindex;
                #endif
            #endif
        }

        /* Request flags for this interface */
        short ifFlags;
        {
            struct ifreq req;
            memcpy(&req, &basereq, sizeof(req));
            if (ioctl(fd,SIOCGIFFLAGS, &req) < 0) {
                perror("ioctl(SIOCGIFFLAGS)");
                exit(1);
            }
            ifFlags = req.ifr_flags;
        }

        /* if the interface is not up or a loopback, ignore it */
        if ((ifFlags & IFF_UP) == 0 || (ifFlags & IFF_LOOPBACK)) {
            continue;
        }

        /* Get local IP for interface */
        {
            struct ifreq req;
            memcpy(&req, &basereq, sizeof(req));
            if (ioctl(fd,SIOCGIFADDR, &req) < 0) {
                perror("ioctl(SIOCGIFADDR)");
                exit(1);
            }
            memcpy(
                &iface->ifaddr,
                &((struct sockaddr_in *)&req.ifr_addr)->sin_addr,
                sizeof(struct in_addr)
            );
        }

        /* Get broadcast address for interface */
        {
            struct ifreq req;
            memcpy(&req, &basereq, sizeof(req));
            if (ifFlags & IFF_BROADCAST) {
                if (ioctl(fd,SIOCGIFBRDADDR, &req) < 0) {
                    perror("ioctl(SIOCGIFBRDADDR)");
                    exit(1);
                }
                memcpy(
                    &iface->dstaddr,
                    &((struct sockaddr_in *)&req.ifr_broadaddr)->sin_addr,
                    sizeof(struct in_addr)
                );
            } else {
                if (ioctl(fd,SIOCGIFDSTADDR, &req) < 0) {
                    perror("ioctl(SIOCGIFBRDADDR)");
                    exit(1);
                }
                memcpy(
                    &iface->dstaddr,
                    &((struct sockaddr_in *)&req.ifr_dstaddr)->sin_addr,
                    sizeof(struct in_addr)
                );
            }
        }

        char ifaddr[255];
        inet_ntoa2(iface->ifaddr, ifaddr, sizeof(ifaddr));
        char dstaddr[255];
        inet_ntoa2(iface->dstaddr, dstaddr, sizeof(dstaddr));

        DPRINT(
            "%s: %i / %s / %s\n",
            basereq.ifr_name,
            iface->ifindex,
            ifaddr,
            dstaddr
        );

        // Set up a one raw socket per interface for sending our packets through
        if((iface->raw_socket = socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0) {
            perror("socket");
            exit(1);
        }
        {
            int yes = 1;
            int no = 0;
            if (setsockopt(iface->raw_socket, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes))<0) {
                perror("setsockopt SO_BROADCAST");
                exit(1);
            }
            if (setsockopt(iface->raw_socket, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes))<0) {
                perror("setsockopt IP_HDRINCL");
                exit(1);
            }
            if (setsockopt(iface->raw_socket, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))<0) {
                perror("setsockopt SO_REUSEPORT");
                exit(1);
            }
            #ifdef __FreeBSD__
                if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no))) < 0) {
                    perror("setsockopt IP_MULTICAST_LOOP");
                }
                if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_IF, &iface->ifaddr, sizeof(iface->ifaddr))) < 0) {
                    perror("setsockopt IP_MULTICAST_IF");
                }
                int setttl = ttl;
                if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_TTL, &setttl, sizeof(setttl))) < 0) {
                    perror("setsockopt IP_MULTICAST_TTL");
                }
            #else
                // bind socket to dedicated NIC (override routing table)
                if (setsockopt(iface->raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interfaceNames[i], strlen(interfaceNames[i])+1)<0)
                {
                    perror("setsockopt SO_BINDTODEVICE");
                    exit(1);
                };
            #endif
        }

        /* ... and count it */
        maxifs++;
    }

    DPRINT("found %i interfaces total\n",maxifs);

    /* Free our allocated buffer and close the socket */
    close(fd);

    /* Create our broadcast receiving socket */
    int rcv;
    {
        if((rcv=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
          {
              perror("socket");
              exit(1);
          }
        int yes = 1;
        if(setsockopt(rcv, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes))<0){
            perror("SO_BROADCAST on rcv");
            exit(1);
        };
        if (setsockopt(rcv, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))<0) {
            perror("SO_REUSEPORT on rcv");
            exit(1);
        }
        #ifdef __FreeBSD__
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes))<0){
                perror("IP_RECVTTL on rcv");
                exit(1);
            };
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVIF, &yes, sizeof(yes))<0){
                perror("IP_RECVIF on rcv");
                exit(1);
            };
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes))<0){
                perror("IP_RECVDSTADDR on rcv");
                exit(1);
            };
        #else
            if(setsockopt(rcv, SOL_IP, IP_RECVTTL, &yes, sizeof(yes))<0){
                perror("IP_RECVTTL on rcv");
                exit(1);
            };
            if(setsockopt(rcv, SOL_IP, IP_PKTINFO, &yes, sizeof(yes))<0){
                perror("IP_PKTINFO on rcv");
                exit(1);
            };
        #endif
        for (int i = 0; i < multicastAddrsNum; i++) {
            for (int x = 0; x < maxifs; x++) {
                struct ip_mreq mreq;
                memset(&mreq, 0, sizeof(struct ip_mreq));
                mreq.imr_interface.s_addr = ifs[x].ifaddr.s_addr;
                mreq.imr_multiaddr.s_addr = inet_addr(multicastAddrs[i]);
                DPRINT("IP_ADD_MEMBERSHIP:\t\t%s %s\n",inet_ntoa(ifs[x].ifaddr),multicastAddrs[i]);
                if(setsockopt(rcv, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))<0){
                    perror("IP_ADD_MEMBERSHIP on rcv");
                    exit(1);
                }
            }
        }

        struct sockaddr_in bind_addr;
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(port);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        if(bind(rcv, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            perror("bind");
            fprintf(stderr,"rcv bind\n");
            exit(1);
        }
    }

    DPRINT("Done Initializing\n\n");

    /* Fork to background */
    if (! debug) {
        if (forking && fork())
        exit(0);
        fclose(stdin);
        fclose(stdout);
        fclose(stderr);
    }

    for (;;) /* endless loop */
    {
        /* Receive a broadcast packet */
        int len = recvmsg(rcv,&rcv_msg,0);
        if (len <= 0) continue;    /* ignore broken packets */

        /* Find the ttl and the receiving interface */
        struct cmsghdr *cmsg;
        int rcv_ttl = 0;
        int rcv_ifindex = 0;
        struct in_addr rcv_inaddr;
        int foundRcvIf = 0;
        int foundRcvIp = 0;
        if (rcv_msg.msg_controllen > 0) {
            for (cmsg=CMSG_FIRSTHDR(&rcv_msg);cmsg;cmsg=CMSG_NXTHDR(&rcv_msg,cmsg)) {
                #ifdef __FreeBSD__
                    if (cmsg->cmsg_type==IP_RECVTTL) {
                        rcv_ttl = *(int *)CMSG_DATA(cmsg);
                    }
                    if (cmsg->cmsg_type==IP_RECVDSTADDR) {
                        rcv_inaddr=*((struct in_addr *)CMSG_DATA(cmsg));
                        foundRcvIp = 1;
                    }
                    if (cmsg->cmsg_type==IP_RECVIF) {
                        rcv_ifindex=((struct sockaddr_dl *)CMSG_DATA(cmsg))->sdl_index;
                        foundRcvIf = 1;
                    }
                #else
                    if (cmsg->cmsg_type==IP_TTL) {
                        rcv_ttl = *(int *)CMSG_DATA(cmsg);
                    }
                    if (cmsg->cmsg_type==IP_PKTINFO) {
                        rcv_ifindex=((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_ifindex;
                        foundRcvIf = 1;
                        rcv_inaddr=((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_addr;
                        foundRcvIp = 1;
                    }
                #endif
            }
        }

        if (!foundRcvIp) {
            perror("Source IP not found on incoming packet\n");
            continue;
        }
        if (!foundRcvIf) {
            perror("Interface not found on incoming packet\n");
            continue;
        }
        if (!rcv_ttl) {
            perror("TTL not found on incoming packet\n");
            continue;
        }

        struct Iface* fromIface = NULL;
        for (int iIf = 0; iIf < maxifs; iIf++) {
            if (ifs[iIf].ifindex == rcv_ifindex) {
                fromIface = &ifs[iIf];
            }
        }

        struct in_addr origFromAddress = rcv_addr.sin_addr;
        u_short origFromPort = ntohs(rcv_addr.sin_port);
        struct in_addr origToAddress = rcv_inaddr;
        u_short origToPort = port;

        gram[HEADER_LEN + len] = 0;

        char origFromAddressStr[255];
        inet_ntoa2(origFromAddress, origFromAddressStr, sizeof(origFromAddressStr));
        char origToAddressStr[255];
        inet_ntoa2(origToAddress, origToAddressStr, sizeof(origToAddressStr));
        DPRINT("<- [ %s:%d -> %s:%d (iface=%d len=%i ttl=%i)\n",
            origFromAddressStr, origFromPort,
            origToAddressStr, origToPort,
            rcv_ifindex, len, rcv_ttl
        );

        if (rcv_ttl == ttl) {
            DPRINT("Echo (Ignored)\n\n");
            continue;
        }
        if (!fromIface) {
            DPRINT("Not from managed iface\n\n");
            continue;
        }

        /* Iterate through our interfaces and send packet to each one */
        for (int iIf = 0; iIf < maxifs; iIf++) {
            struct Iface* iface = &ifs[iIf];

            /* no bounces, please */
            if (iface == fromIface) {
                continue;
            }

            struct in_addr fromAddress;
            u_short fromPort;
            if (spoof_addr == inet_addr("1.1.1.1")) {
                fromAddress = iface->ifaddr;
                fromPort = port;
            } else if (spoof_addr == inet_addr("1.1.1.2")) {
                fromAddress = iface->ifaddr;
                fromPort = origFromPort;
            } else if (spoof_addr) {
                fromAddress.s_addr = spoof_addr;
                fromPort = origFromPort;
            } else {
                fromAddress = origFromAddress;
                fromPort = origFromPort;
            }

            // resolve where to send this packet (based on -t option(s) used)
            struct in_addr toAddresses[MAXTARGETS];
            const size_t toAddressesNum = resolve_to_addresses(rcv_inaddr, fromIface, iface,
                toAddresses, MAXTARGETS);

            for (size_t iTo = 0; iTo < toAddressesNum; iTo++) {
                const struct in_addr toAddress = toAddresses[iTo];
                u_short toPort = origToPort;

                char fromAddressStr[255];
                inet_ntoa2(fromAddress, fromAddressStr, sizeof(fromAddressStr));
                char toAddressStr[255];
                inet_ntoa2(toAddress, toAddressStr, sizeof(toAddressStr));
                DPRINT (
                    "-> [ %s:%d -> %s:%d (iface=%d)\n",
                    fromAddressStr, fromPort,
                    toAddressStr, toPort,
                    iface->ifindex
                );

                /* Send the packet */
                gram[8] = ttl;
                memcpy(gram+12, &fromAddress.s_addr, 4);
                memcpy(gram+16, &toAddress.s_addr, 4);
                *(u_short*)(gram+20)=htons(fromPort);
                *(u_short*)(gram+22)=htons(toPort);
                #if (defined __FreeBSD__ && __FreeBSD__ <= 10) || defined __APPLE__
                *(u_short*)(gram+24)=htons(UDPHEADER_LEN + len);
                *(u_short*)(gram+2)=HEADER_LEN + len;
                #else
                *(u_short*)(gram+24)=htons(UDPHEADER_LEN + len);
                *(u_short*)(gram+2)=htons(HEADER_LEN + len);
                #endif
                struct sockaddr_in sendAddr;
                sendAddr.sin_family = AF_INET;
                sendAddr.sin_port = htons(toPort);
                sendAddr.sin_addr = toAddress;

                if (sendto(
                    iface->raw_socket,
                    &gram,
                    HEADER_LEN+len,
                    0,
                    (struct sockaddr*)&sendAddr,
                    sizeof(sendAddr)
                ) < 0) {
                    perror("sendto");
                }
            }
        }
        DPRINT ("\n");
    }
}
