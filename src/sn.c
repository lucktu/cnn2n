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

/* Supernode for n2n-2.x */

#include "n2n.h"
#include "header_encryption.h"

/** Load the list of allowed communities. Existing/previous ones will be removed
 *
 */
static int load_allowed_sn_community(n2n_sn_t *sss, char *path) {
  char buffer[4096], *line;
  FILE *fd = fopen(path, "r");
  struct sn_community *s, *tmp;
  uint32_t num_communities = 0;

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "File %s not found", path);
    return -1;
  }

  HASH_ITER(hh, sss->communities, s, tmp) {
    HASH_DEL(sss->communities, s);
    if (NULL != s->header_encryption_ctx)
      free (s->header_encryption_ctx);
    free(s);
  }

  while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
    int len = strlen(line);

    if((len < 2) || line[0] == '#')
      continue;

    len--;
    while(len > 0) {
      if((line[len] == '\n') || (line[len] == '\r')) {
	line[len] = '\0';
	len--;
      } else
	break;
    }

    s = (struct sn_community*)calloc(1,sizeof(struct sn_community));

    if(s == NULL) {
      traceEvent(TRACE_ERROR, "Failed to allocate memory for community");
      fclose(fd);
      return -1;
    }

    strncpy((char*)s->community, line, N2N_COMMUNITY_SIZE-1);
    s->community[N2N_COMMUNITY_SIZE-1] = '\0';
    /* we do not know if header encryption is used in this community,
     * first packet will show. just in case, setup the key.           */
    s->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
    packet_header_setup_key (s->community, &(s->header_encryption_ctx), &(s->header_iv_ctx));
    HASH_ADD_STR(sss->communities, community, s);

    num_communities++;
    traceEvent(TRACE_INFO, "Added allowed community '%s' [total: %u]",
		 (char*)s->community, num_communities);
  }

  fclose(fd);

  traceEvent(TRACE_NORMAL, "Loaded %u communities from %s",
	     num_communities, path);

  /* No new communities will be allowed */
  sss->lock_communities = 1;

  return(0);
}


/* *************************************************** */

/** Help message to print if the command line arguments are not valid. */
static void help() {
	print_n2n_version();

	printf("Usage: supernode -l <local port>\n"
	       "   or: supernode <config file> (see supernode.conf)\n");
	printf("\n");
	printf("-l <listen port>         | Main listen UDP port (through it, the other edges make the initial contact)\n");
	printf("-c <file>                | File containing the allowed communities\n");
#if defined(N2N_HAVE_DAEMON)
	printf("-f                       | Run in foreground\n");
#endif /* #if defined(N2N_HAVE_DAEMON) */
#ifndef WIN32
	printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped\n");
	printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped\n");
#endif /* ifndef WIN32 */
	printf("-t <mgmt port>           | Management UDP port. It can be set when you run multiple supernodes on a machine (default = %d)\n", N2N_SN_MGMT_PORT);
	printf("-v                       | Increase verbosity. Can be used multiple times\n");
	printf("-h                       | This help message\n");
    printf("-------------------------- new features from ntop's n2n_v2.8.0 --- by github.com/lucktu/cnn2n new2 --------------------------\n");
	printf("-a <net/bit>             | Set an automatically assigned subnet for edges (default = 172.17.12.0/24)\n");
	printf("-L <file>                | File associated with rate limiting configuration\n");
	exit(1);
}

/* *************************************************** */

static int setOption(int optkey, char *_optarg, n2n_sn_t *sss) {
	//traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

	switch (optkey) {
		case 'l': /* local-port */
			sss->lport = atoi(_optarg);
			break;

		case 't': /* mgmt-port */
			sss->mport = atoi(_optarg);
			break;

		case 'a': {
			dec_ip_str_t ip_str = {'\0'};
			in_addr_t net;
			uint8_t bitlen;

			if (sscanf(_optarg, "%15[^/]/%hhu", ip_str, &bitlen) != 2) {
				traceEvent(TRACE_ERROR, "Bad net/bit format '%s'. See -h.", _optarg);
				return -1;
			}

			net = inet_addr(ip_str);
			if ((net < 0) || (net == INADDR_NONE) || (net == INADDR_ANY)) {
				traceEvent(TRACE_WARNING, "Bad network '%s' in '%s', Use default: '%s/%d'",
				           ip_str, _optarg,
				           N2N_SN_AUTO_IP_NET_ADDR_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
				break;
			}

			if (bitlen > 32) {
				traceEvent(TRACE_WARNING, "Bad prefix '%hhu' in '%s', Use default: '%s/%d'",
				           bitlen, _optarg,
				           N2N_SN_AUTO_IP_NET_ADDR_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
				break;
			}

			traceEvent(TRACE_NORMAL, "The subnet of auto ip service is: '%s/%hhu'.", ip_str, bitlen);

			sss->auto_ip_addr.net_addr = ntohl(net);
			sss->auto_ip_addr.net_bitlen = bitlen;

			break;
		}

#ifndef WIN32
		case 'u': /* unprivileged uid */
			sss->userid = atoi(_optarg);
			break;

		case 'g': /* unprivileged uid */
			sss->groupid = atoi(_optarg);
			break;
#endif

		case 'c': /* community file */
			load_allowed_sn_community(sss, _optarg);
			break;

		case 'f': /* foreground */
			sss->daemon = 0;
			break;

		case 'h': /* help */
			help();
			break;

		case 'v': /* verbose */
			setTraceLevel(getTraceLevel() + 1);
			break;

		case 'L': /* rate limit config */
			strncpy(sss->rate_limit_config_path, _optarg, sizeof(sss->rate_limit_config_path) - 1);
			sss->rate_limit_config_path[sizeof(sss->rate_limit_config_path) - 1] = '\0';
			break;

		default:
			traceEvent(TRACE_WARNING, "Unknown option -%c: Ignored.", (char) optkey);
			return (-1);
	}

	return (0);
}


/* *********************************************** */

static const struct option long_options[] = {
		{"communities", required_argument, NULL, 'c'},
		{"foreground",  no_argument,       NULL, 'f'},
		{"local-port",  required_argument, NULL, 'l'},
		{"mgmt-port",   required_argument, NULL, 't'},
		{"auto_ip",     required_argument, NULL, 'a'},
		{"rate-limit",  required_argument, NULL, 'L'},
		{"help",        no_argument,       NULL, 'h'},
		{"verbose",     no_argument,       NULL, 'v'},
		{NULL, 0,                          NULL, 0}
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI(int argc, char * const argv[], n2n_sn_t *sss) {
  u_char c;

  while((c = getopt_long(argc, argv, "fl:u:g:t:a:c:vhL:",
			 long_options, NULL)) != '?') {
    if(c == 255) break;
    setOption(c, optarg, sss);
  }

  return 0;
}

/* *************************************************** */

static char *trim(char *s) {
  char *end;

  if(s == NULL) return NULL;

  while(isspace(s[0]) || (s[0] == '"') || (s[0] == '\''))
    s++;

  if(s[0] == 0) return s;

  end = &s[strlen(s) - 1];
  while(end > s
	&& (isspace(end[0])|| (end[0] == '"') || (end[0] == '\'')))
    end--;
  end[1] = 0;

  return s;
}

/* *************************************************** */

/* parse the configuration file */
static int loadFromFile(const char *path, n2n_sn_t *sss) {
  char buffer[4096], *line, *key, *value;
  u_int line_len, opt_name_len;
  FILE *fd;
  const struct option *opt;

  fd = fopen(path, "r");

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "Config file %s not found", path);
    return -1;
  }

  while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {

    line = trim(line);
    value = NULL;

    if((line_len = strlen(line)) < 2 || line[0] == '#')
      continue;

    if(!strncmp(line, "--", 2)) { /* long opt */
      key = &line[2], line_len -= 2;

      opt = long_options;
      while(opt->name != NULL) {
	opt_name_len = strlen(opt->name);

	if(!strncmp(key, opt->name, opt_name_len)
	   && (line_len <= opt_name_len
	       || key[opt_name_len] == '\0'
	       || key[opt_name_len] == ' '
	       || key[opt_name_len] == '=')) {
	  if(line_len > opt_name_len)	  key[opt_name_len] = '\0';
	  if(line_len > opt_name_len + 1) value = trim(&key[opt_name_len + 1]);

	  // traceEvent(TRACE_NORMAL, "long key: %s value: %s", key, value);
	  setOption(opt->val, value, sss);
	  break;
	}

	opt++;
      }
    } else if(line[0] == '-') { /* short opt */
      key = &line[1], line_len--;
      if(line_len > 1) key[1] = '\0';
      if(line_len > 2) value = trim(&key[2]);

      // traceEvent(TRACE_NORMAL, "key: %c value: %s", key[0], value);
      setOption(key[0], value, sss);
    } else {
      traceEvent(TRACE_WARNING, "Skipping unrecognized line: %s", line);
      continue;
    }
  }

  fclose(fd);

  return 0;
}

/* *************************************************** */

static int keep_running;

static void sigproc(int sig) {
  switch(sig) {
  case SIGINT:
  case SIGTERM:
    traceEvent(TRACE_NORMAL, "Signal received: shutting down");
    keep_running = 0;
    break;
  case SIGHUP:
    traceEvent(TRACE_NORMAL, "SIGHUP received: ignoring (no reload implemented)");
    break;
  default:
    break;
  }
}

/* *************************************************** */

int main(int argc, char * const argv[]) {
  n2n_sn_t sss;
  int rc = 0;

  /* INITIALIZE FIRST - this sets defaults and zeros the structure */
  rc = sn_init(&sss);
  if(rc != 0) {
    traceEvent(TRACE_ERROR, "Failed to initialize supernode");
    exit(1);
  }

  /* THEN parse command line arguments to override defaults */
  if(argc > 1) {
    if(argv[1][0] != '-') {
      /* Config file has been supplied */
      rc = loadFromFile(argv[1], &sss);
      if(rc != 0) {
        traceEvent(TRACE_ERROR, "Failed to load config file %s", argv[1]);
        exit(1);
      }
    } else {
      /* Load from command line */
      rc = loadFromCLI(argc, argv, &sss);
      if(rc != 0) {
        traceEvent(TRACE_ERROR, "Failed to load command line options");
        exit(1);
      }
    }
  }

  /* Load initial rate limit configuration */
  if (strlen(sss.rate_limit_config_path) > 0) {
    parse_rate_limit_config(&sss);
  }

#ifndef WIN32
  struct sigaction sa;

  /* Setup signal handlers */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigproc;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if(sigaction(SIGINT, &sa, NULL) == -1) {
    traceEvent(TRACE_ERROR, "Failed to set SIGINT handler");
    exit(1);
  }

  if(sigaction(SIGTERM, &sa, NULL) == -1) {
    traceEvent(TRACE_ERROR, "Failed to set SIGTERM handler");
    exit(1);
  }

  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);
#endif

  if (sss.lport == 0) {
    traceEvent(TRACE_ERROR, "Error: Listen port is required (-l <port>)");
    help();
  }

  if(sss.daemon) {
#ifndef WIN32
    int pid;

    if((pid = fork()) != 0) {
      if(pid == -1) {
        traceEvent(TRACE_ERROR, "Failed to fork daemon process");
        exit(1);
      } else {
        traceEvent(TRACE_NORMAL, "Parent process exiting (daemon started in background with pid %d)", pid);
        exit(0);
      }
    }

    setsid();
    chdir("/");
    umask(0);

    /* Redirect standard files to /dev/null */
    freopen( "/dev/null", "r", stdin);
    freopen( "/dev/null", "w", stdout);
    freopen( "/dev/null", "w", stderr);
#endif
  }

  /* *** Open UDP socket *** */
  sss.sock = open_socket(sss.lport, 1 /* bind_any */);
  if(-1 == sss.sock) {
    traceEvent(TRACE_ERROR, "Failed to open main socket on port %d", sss.lport);
    exit(-2);
  }

  sss.mgmt_sock = open_socket(sss.mport, 0);
  if(-1 == sss.mgmt_sock) {
    traceEvent(TRACE_ERROR, "Failed to open management socket on port %d", sss.mport);
    exit(-2);
  }

  keep_running = 1;
  run_sn_loop(&sss, &keep_running);

  return(0);
}
