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

#include "n2n.h"
#include "sys/stat.h"

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)
#define RATE_LIMIT_ADJUSTMENT_FACTOR 1.05

/* Community traffic statistics structure */
struct community_traffic_stats {
    uint64_t tokens;                /* Current token count (bytes) */
    time_t last_token_refill;       /* Last token refill time */
    uint64_t instant_bps;           /* Instant traffic (bytes/sec) - 5 second average */
    uint64_t total_bytes;           /* Total traffic */
    uint64_t last_24h_bytes;        /* 24-hour traffic */
    uint64_t current_minute_bytes;  /* Current minute accumulator */
    uint64_t bytes_history[1440];   /* 24-hour history (1-minute buckets) */
    time_t base_timestamp;          /* Base timestamp for calculating bucket validity */
    time_t stats_start_time;        /* Statistics start time */
    uint64_t recent_seconds[5];     /* Last 5 seconds bytes for calculating average rate */
    n2n_community_t community_name; /* Community name identifier */
    int history_idx;                /* Current history index */
    int recent_seconds_idx;         /* Current second index */
    time_t last_second_update;      /* Last second update time */
    time_t last_minute_update;      /* Last minute update time */
};

/* Rate limiting rule structure */
struct rate_limit_rule {
    n2n_community_t community_name;  /* Community name, "*" for all */
    uint64_t max_24h_bytes;          /* Maximum 24-hour traffic */
    uint64_t rate_limit_bps;         /* Rate limit (bytes/sec), 0 = unlimited */
    struct rate_limit_rule *next;    /* Linked list pointer */
};

/* Check if the address is a private IP */
static int is_private_ip(const n2n_sock_t *sock) {
    if (sock->family != AF_INET) return 0;

    uint32_t ip = ntohl(*(uint32_t*)sock->addr.v4);

    /* 10.0.0.0/8 */
    if ((ip & 0xFF000000) == 0x0A000000) return 1;
    /* 172.16.0.0/12 */
    if ((ip & 0xFFF00000) == 0xAC100000) return 1;
    /* 192.168.0.0/16 */
    if ((ip & 0xFFFF0000) == 0xC0A80000) return 1;

    return 0;
}

static int try_forward(n2n_sn_t * sss,
		       const struct sn_community *comm,
		       const n2n_common_t * cmn,
		       const n2n_mac_t dstMac,
		       const uint8_t * pktbuf,
		       size_t pktsize);

static ssize_t sendto_sock(n2n_sn_t *sss,
                           const n2n_sock_t *sock,
                           const uint8_t *pktbuf,
                           size_t pktsize);

static int sendto_mgmt(n2n_sn_t *sss,
                       const struct sockaddr_in *sender_sock,
                       const uint8_t *mgmt_buf,
                       size_t mgmt_size);

static int try_broadcast(n2n_sn_t * sss,
		         const struct sn_community *comm,
			 const n2n_common_t * cmn,
			 const n2n_mac_t srcMac,
			 const uint8_t * pktbuf,
			 size_t pktsize);

static uint16_t reg_lifetime(n2n_sn_t *sss);

static int update_edge(n2n_sn_t *sss,
                       const n2n_REGISTER_SUPER_t* reg,
                       struct sn_community *comm,
                       const n2n_sock_t *sender_sock,
                       time_t now);

static int purge_expired_communities(n2n_sn_t *sss,
                                     time_t* p_last_purge,
                                     time_t now);

static int sort_communities (n2n_sn_t *sss,
                             time_t* p_last_sort,
                             time_t now);

static int process_mgmt(n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size,
                        time_t now);

static int process_udp(n2n_sn_t *sss,
                       const struct sockaddr_in *sender_sock,
                       uint8_t *udp_buf,
                       size_t udp_size,
                       time_t now);

/* Recalculate 24-hour traffic from existing bucket data */
static void recalculate_24h_traffic(struct community_traffic_stats *stats, time_t now) {
    uint64_t total = 0;
    int i;

    traceEvent(TRACE_INFO, "Recalculating 24h traffic due to time anomaly");

    /* Sum all historical buckets */
    for (i = 0; i < 1440; i++) {
        total += stats->bytes_history[i];
    }

    /* Add current minute traffic */
    total += stats->current_minute_bytes;

    /* Update 24-hour total */
    stats->last_24h_bytes = total;

    /* Reset timing to current time (keep history_idx intact) */
    stats->last_minute_update = now;
    stats->base_timestamp = now;

    traceEvent(TRACE_INFO, "24h traffic recalculated: %.2f GB",
               total / (1024.0 * 1024.0 * 1024.0));
}

/* Derive config (.cfg) path from stats (.dat) path */
static void derive_cfg_path(const char *stats_path, char *cfg_path, size_t sz) {
    strncpy(cfg_path, stats_path, sz - 1);
    cfg_path[sz - 1] = '\0';
    char *dot = strrchr(cfg_path, '.');
    char *slash = strrchr(cfg_path, '/');
#ifdef _WIN32
    char *bslash = strrchr(cfg_path, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    if (dot && dot > slash)
        strcpy(dot, ".cfg");
    else
        strncat(cfg_path, ".cfg", sz - strlen(cfg_path) - 1);
}

/* Preload all community statistics from file */
void preload_all_community_stats(n2n_sn_t *sss) {
    FILE *fp;
    struct community_traffic_stats temp_stats;
    int found;
    int i;

    fp = fopen(sss->rate_limit_stats_path, "rb");
    if (!fp) return;

    while (fread(&temp_stats, sizeof(struct community_traffic_stats), 1, fp) == 1) {
        /* Check if this community is already loaded */
        found = 0;
        for (i = 0; i < sss->num_communities; i++) {
            if (memcmp(sss->community_stats[i].community_name, temp_stats.community_name,
                      sizeof(n2n_community_t)) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            /* Add new community stats */
            if (sss->num_communities >= sss->max_communities) {
                sss->max_communities = sss->max_communities ? sss->max_communities * 2 : 16;
                sss->community_stats = realloc(sss->community_stats,
                    sss->max_communities * sizeof(struct community_traffic_stats));
            }

            memcpy(&sss->community_stats[sss->num_communities], &temp_stats,
                   sizeof(struct community_traffic_stats));

            /* Update timestamps */
            sss->community_stats[sss->num_communities].base_timestamp = time(NULL);

            sss->num_communities++;
        }
    }
    fclose(fp);
}

/* Save traffic statistics to binary format in config directory */
static void save_traffic_stats_periodic(n2n_sn_t *sss) {
    if (!sss->community_stats || sss->num_communities == 0) return;

    FILE *fp = fopen(sss->rate_limit_stats_path, "wb");
    if (fp) {
        fwrite(sss->community_stats, sizeof(struct community_traffic_stats),
               sss->num_communities, fp);
        fclose(fp);
        traceEvent(TRACE_NORMAL, "Traffic statistics saved to: %s", sss->rate_limit_stats_path);
    } else {
        traceEvent(TRACE_ERROR, "Failed to save traffic statistics to: %s", sss->rate_limit_stats_path);
    }
}

/* Check if it's time to save statistics periodically */
static void check_periodic_save(n2n_sn_t *sss, time_t now) {
    /* Save every 5 minutes (300 seconds) */
    static time_t last_periodic_save = 0;

    if (now - last_periodic_save >= 300) {
        save_traffic_stats_periodic(sss);
        last_periodic_save = now;
    }
}

/* Check if MAC address is valid */
static int is_valid_mac(const n2n_mac_t mac) {
    /* Reject zero MAC */
    if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
        mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
        return 0;

    /* Reject broadcast MAC */
    if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
        mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF)
        return 0;

    /* Reject locally administered MAC (00:01:00:xx:xx:xx pattern) */
    if (mac[0] == 0x00 && mac[1] == 0x01 && mac[2] == 0x00)
        return 0;

    return 1;
}

/* Find or create community statistics */
static struct community_traffic_stats* get_community_stats(n2n_sn_t *sss,
                                                          const n2n_community_t community) {
    int i;

    /* Search existing stats */
    for (i = 0; i < sss->num_communities; i++) {
        if (memcmp(sss->community_stats[i].community_name, community,
                   sizeof(n2n_community_t)) == 0) {
            return &sss->community_stats[i];
        }
    }

    /* Create new stats entry */
    if (sss->num_communities >= sss->max_communities) {
        sss->max_communities = sss->max_communities ? sss->max_communities * 2 : 16;
        struct community_traffic_stats *new_stats = realloc(sss->community_stats,
                                          sss->max_communities * sizeof(struct community_traffic_stats));
        if (!new_stats) return NULL;
        sss->community_stats = new_stats;
    }

    int loaded_from_file = 0;
    FILE *fp = fopen(sss->rate_limit_stats_path, "rb");
    if (fp) {
        struct community_traffic_stats temp_stats;
        while (fread(&temp_stats, sizeof(struct community_traffic_stats), 1, fp) == 1) {
            if (memcmp(temp_stats.community_name, community, sizeof(n2n_community_t)) == 0) {
                memcpy(&sss->community_stats[sss->num_communities], &temp_stats,
                       sizeof(struct community_traffic_stats));

                /* Time consistency check */
                time_t now = time(NULL);
                if (temp_stats.last_minute_update > now ||
                    temp_stats.last_minute_update < now - 86400) {
                    /* Time anomaly detected, recalculate 24h traffic */
                    recalculate_24h_traffic(&sss->community_stats[sss->num_communities], now);
                }
                /* Update base timestamp to current time */
                sss->community_stats[sss->num_communities].base_timestamp = now;

                loaded_from_file = 1;
                break;
            }
        }
        fclose(fp);
    }

    if (!loaded_from_file) {
        memset(&sss->community_stats[sss->num_communities], 0,
               sizeof(struct community_traffic_stats));
        memcpy(sss->community_stats[sss->num_communities].community_name,
               community, sizeof(n2n_community_t));
        sss->community_stats[sss->num_communities].stats_start_time = time(NULL);
    }

    return &sss->community_stats[sss->num_communities++];
}

/* Record traffic for a community */
static void record_traffic(n2n_sn_t *sss, const n2n_community_t community,
                          uint64_t bytes, time_t now) {
    if (!sss->traffic_stats_enabled) return;  /* Check if traffic stats are enabled */
    struct community_traffic_stats *stats = get_community_stats(sss, community);
    if (!stats) return;  /* Exit if stats structure not found */

    /* Update cumulative traffic counters */
    stats->total_bytes += bytes;           /* Total traffic since start */
    stats->current_minute_bytes += bytes;  /* Traffic in current minute */

    /* Update last stats update time for periodic save */
    sss->last_stats_update = now;

    /* Initialize second-level tracking on first call */
    if (stats->last_second_update == 0) {
        stats->last_second_update = now;   /* Initialize second-level timestamp */
        stats->last_minute_update = now;   /* Initialize minute-level timestamp */
        stats->recent_seconds_idx = 0;     /* Reset recent seconds index */
        memset(stats->recent_seconds, 0, sizeof(stats->recent_seconds));  /* Clear recent seconds array */
    }

    /* Handle second-level updates - for 5-second average rate calculation */
    if (now > stats->last_second_update) {
        int seconds_diff = now - stats->last_second_update;

        /* Handle skipped seconds due to time jumps or delays */
        if (seconds_diff >= 5) {
            /* Skip more than 5 seconds, reset array to avoid stale data */
            memset(stats->recent_seconds, 0, sizeof(stats->recent_seconds));
            stats->recent_seconds_idx = 0;
        } else {
            /* Advance second by second for accurate tracking */
            while (seconds_diff > 0) {
                stats->recent_seconds_idx = (stats->recent_seconds_idx + 1) % 5;
                stats->recent_seconds[stats->recent_seconds_idx] = 0;
                seconds_diff--;
            }
        }
        stats->last_second_update = now;  /* Update second-level timestamp */
    }

    /* Accumulate current second bytes for rate calculation */
    stats->recent_seconds[stats->recent_seconds_idx] += bytes;

    /* Calculate 5-second average instant rate for display purposes only */
    uint64_t recent_total = 0;
    int i;
    for (i = 0; i < 5; i++) {
        recent_total += stats->recent_seconds[i];
    }
    stats->instant_bps = recent_total / 5;  /* 5-second average bytes per second */

    /* Detect time jump before normal update */
    if (stats->last_minute_update > 0 && (now - stats->last_minute_update < 0 || now - stats->last_minute_update > 3600)) {
        traceEvent(TRACE_WARNING, "Time jump detected: last=%lu, now=%lu, diff=%ld",
                   stats->last_minute_update, now, now - stats->last_minute_update);
        recalculate_24h_traffic(stats, now);
    }

    /* Update 24-hour traffic history every minute */
    if (now - stats->last_minute_update >= 60) {
        int minutes_diff = (now - stats->last_minute_update) / 60;

        /* Limit maximum skipped minutes to prevent excessive processing */
        if (minutes_diff > 1440) minutes_diff = 1440;

        /* Handle skipped minutes due to time jumps or delays */
        for (i = 0; i < minutes_diff; i++) {
            stats->history_idx = (stats->history_idx + 1) % 1440;  /* Advance to next bucket */

            /* Remove expired data from 24-hour total (prevent underflow) */
            if (stats->last_24h_bytes >= stats->bytes_history[stats->history_idx]) {
                stats->last_24h_bytes -= stats->bytes_history[stats->history_idx];
            } else {
                stats->last_24h_bytes = 0;  /* Reset if underflow detected */
            }
        }

        /* Record current minute data and update base timestamp */
        stats->bytes_history[stats->history_idx] = stats->current_minute_bytes;
        stats->base_timestamp = now;  /* Update base timestamp for expired data detection */
        stats->last_24h_bytes += stats->current_minute_bytes;  /* Add current minute to 24h total */

        /* Reset minute counter and update time to next minute boundary */
        stats->current_minute_bytes = 0;
        stats->last_minute_update += minutes_diff * 60;
    }
    check_periodic_save(sss, now);  /* Check if periodic save is needed */
}

/* Create default configuration file with examples */
static int create_default_config(const char *config_path) {
    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        traceEvent(TRACE_ERROR, "Failed to create default config file: %s", config_path);
        return -1;
    }

    fprintf(fp, "# N2N Supernode Rate Limit Configuration File\n");
    fprintf(fp, "# Format: <community_name> <rate_limit_KB/s> <max_24h_traffic_GB>\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# community_name    : Name of the community (use * or 0 for all communities)\n");
    fprintf(fp, "# rate_limit_KB/s   : Speed limit applied AFTER 24h traffic exceeded (0 = unlimited)\n");
    fprintf(fp, "# max_24h_traffic_GB: Maximum traffic allowed in 24 hours (0 = unlimited)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# IMPORTANT: Speed limiting only activates when 24h traffic limit is exceeded\n");
    fprintf(fp, "# Rules are processed from top to bottom - later rules have higher priority\n");
    fprintf(fp, "# File changes are automatically detected and applied without restart\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# --------------------------------------------------------------------------- #\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Traffic statistics and rate limiting global switch: (default: off)\n");
    fprintf(fp, "#enabled on\n");
    fprintf(fp, "\n");
    fprintf(fp, "# Practical application examples:\n");
    fprintf(fp, "#community_name    rate_limit_KB/s  max_24h_traffic_GB  remark\n");
    fprintf(fp, "#*                 10               50                  Global limit: 50GB/24h, then throttle to 10KB/s\n");
    fprintf(fp, "#n2n               5                20                  Limit \"n2n\" to 20GB/24h, then throttle to 5KB/s\n");
    fprintf(fp, "#unlimited_group   0                0                   Unlimited traffic for specific community\n");
    fprintf(fp, "#traffic_limited   0                15                  Traffic limit only (no speed limit after exceed)\n");
    fprintf(fp, "#speed_limited     3.0              0                   Speed limit only (activates immediately)\n");

    fclose(fp);
    traceEvent(TRACE_NORMAL, "Created default configuration file: %s", config_path);
    return 0;
}

/* Parse rate limit configuration file */
void parse_rate_limit_config(n2n_sn_t *sss) {
    char cfgpath[512];
    derive_cfg_path(sss->rate_limit_stats_path, cfgpath, sizeof(cfgpath));

    FILE *fp;
    char line[512];
    char community[32];
    double max_24h_gb, rate_limit_kbps;

    /* Check if file exists and is empty */
    struct stat file_stat;
    if (stat(cfgpath, &file_stat) == 0) {
        if (file_stat.st_size == 0) {
            /* File is empty, create default configuration */
            create_default_config(cfgpath);
        }
    } else {
        /* File doesn't exist, create default configuration */
        create_default_config(cfgpath);
    }

    /* Free existing rules */
    while (sss->rate_limit_rules) {
        struct rate_limit_rule *rule = sss->rate_limit_rules;
        sss->rate_limit_rules = rule->next;
        free(rule);
    }

    sss->traffic_stats_enabled = 0; /* Reset to disabled on each reload */
    fp = fopen(cfgpath, "r");
    if (!fp) return;

    /* Build rule list using tail insertion to maintain file order priority */
    struct rate_limit_rule *last_rule = NULL;

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;

        char keyword[32], value[32];
        if (sscanf(line, "%31s %31s", keyword, value) == 2) {
            if (strcmp(keyword, "enabled") == 0) {
                sss->traffic_stats_enabled = (strcmp(value, "on") == 0) ? 1 : 0;
                traceEvent(TRACE_NORMAL, "Traffic stats/rate-limit: %s",
                           sss->traffic_stats_enabled ? "enabled" : "disabled");
                continue;
            }
        }

        if (sscanf(line, "%31s %lf %lf", community, &rate_limit_kbps, &max_24h_gb) == 3) {
            struct rate_limit_rule *rule = malloc(sizeof(struct rate_limit_rule));
            if (!rule) continue;

            if (strcmp(community, "*") == 0 || strcmp(community, "0") == 0) {
                memset(rule->community_name, 0, sizeof(rule->community_name));
            } else {
                strncpy((char*)rule->community_name, community, sizeof(rule->community_name) - 1);
            }

            rule->rate_limit_bps = (uint64_t)(rate_limit_kbps * 1024);
            rule->max_24h_bytes = (uint64_t)(max_24h_gb * 1024 * 1024 * 1024);
            rule->next = NULL;

            /* Tail insertion to maintain file order (later rules have higher priority) */
            if (!sss->rate_limit_rules) {
                sss->rate_limit_rules = rule;
                last_rule = rule;
            } else {
                last_rule->next = rule;
                last_rule = rule;
            }
        }
    }

    fclose(fp);
}

/* Check rate limit for a community using token bucket algorithm */
static int check_rate_limit(n2n_sn_t *sss, const n2n_community_t community,
                           uint64_t packet_size, time_t now) {
    struct rate_limit_rule *rule;
    struct community_traffic_stats *stats;
    static time_t last_config_check = 0;

    /* Reload config if changed (max once per 60 seconds for performance) */
    if (now - last_config_check >= 60) {
        char cfgpath[512];
        derive_cfg_path(sss->rate_limit_stats_path, cfgpath, sizeof(cfgpath));
        struct stat file_stat;
        if (stat(cfgpath, &file_stat) == 0) {
            if (file_stat.st_mtime > sss->config_last_modified) {
                parse_rate_limit_config(sss);
                sss->config_last_modified = file_stat.st_mtime;
            }
        }
        last_config_check = now;
    }

    /* Find matching rule - reverse order for priority (last match wins) */
    struct rate_limit_rule *last_match = NULL;
    rule = sss->rate_limit_rules;
    while (rule) {
        if (rule->community_name[0] == '\0' ||
            memcmp(rule->community_name, community, sizeof(n2n_community_t)) == 0) {
            last_match = rule; /* Keep track of last matching rule */
        }
        rule = rule->next;
    }
    rule = last_match;

    if (!rule) return 1; /* No limit */

    stats = get_community_stats(sss, community);
    if (!stats) return 1;

    /* Calculate total 24h traffic including current minute */
    uint64_t total_24h_traffic = stats->last_24h_bytes + stats->current_minute_bytes;

    /* Hard blocking when rate_limit_bps = 0 and 24h limit exceeded */
    if (rule->rate_limit_bps == 0 && rule->max_24h_bytes > 0) {
        if (total_24h_traffic > rule->max_24h_bytes) {
            /* 24h traffic exceeds limit - block */
            traceEvent(TRACE_DEBUG, "Community %s: 24h limit exceeded (%.2f GB > %.2f GB), blocking",
                       community,
                       total_24h_traffic / (1024.0 * 1024.0 * 1024.0),
                       rule->max_24h_bytes / (1024.0 * 1024.0 * 1024.0));
            return 0; /* Blocked */
        }
        /* If we reach here, 24h traffic is below limit - allow */
    }

    /* Token bucket rate limiting - activate when max_24h_bytes is 0 (limit reached)
       OR when 24h traffic exceeds the configured limit */
    if (rule->rate_limit_bps > 0 &&
        (rule->max_24h_bytes == 0 || total_24h_traffic > rule->max_24h_bytes)) {
        /* Initialize token bucket */
        if (stats->last_token_refill == 0) {
            stats->last_token_refill = now;
            stats->tokens = rule->rate_limit_bps * RATE_LIMIT_ADJUSTMENT_FACTOR;
        }

        /* Refill tokens based on elapsed time */
        if (now > stats->last_token_refill) {
            uint64_t elapsed = (uint64_t)(now - stats->last_token_refill);
            stats->tokens += elapsed * rule->rate_limit_bps * RATE_LIMIT_ADJUSTMENT_FACTOR;
            uint64_t max_tokens = rule->rate_limit_bps * 5 * RATE_LIMIT_ADJUSTMENT_FACTOR;
            if (stats->tokens > max_tokens)
                stats->tokens = max_tokens;
            stats->last_token_refill = now;
        }

        /* Check if enough tokens available */
        if (stats->tokens < packet_size)
            return 0; /* Blocked */

        /* Consume tokens */
        stats->tokens -= packet_size;
    }

    return 1; /* Allowed */
}

/* ************************************** */


static int try_forward(n2n_sn_t * sss,
		       const struct sn_community *comm,
		       const n2n_common_t * cmn,
		       const n2n_mac_t dstMac,
		       const uint8_t * pktbuf,
		       size_t pktsize)
{
  struct peer_info *  scan;
  macstr_t            mac_buf;
  n2n_sock_str_t      sockbuf;
  time_t now = time(NULL); /* Get time once for consistency */

  HASH_FIND_PEER(comm->edges, dstMac, scan);

  if(NULL != scan)
  {
    /* Check rate limit before sending */
    if (!check_rate_limit(sss, cmn->community, pktsize, now)) {
        traceEvent(TRACE_DEBUG, "Rate limit exceeded for community");
        return 0;
    }

    int data_sent_len;
    data_sent_len = sendto_sock(sss, &(scan->sock), pktbuf, pktsize);

    if(data_sent_len == pktsize)
    {
      ++(sss->stats.fwd);
      /* Record traffic */
      record_traffic(sss, cmn->community, pktsize, now);
      traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
		 pktsize,
		 sock_to_cstr(sockbuf, &(scan->sock)),
		 macaddr_str(mac_buf, scan->mac_addr));
    }
    else
    {
      ++(sss->stats.errors);
      traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
		 pktsize,
		 sock_to_cstr(sockbuf, &(scan->sock)),
		 macaddr_str(mac_buf, scan->mac_addr),
		 errno, strerror(errno));
    }
  }
  else
  {
    traceEvent(TRACE_DEBUG, "try_forward unknown MAC");

    /* Not a known MAC so drop. */
    return(-2);
  }

  return(0);
}

/** Send a datagram to the destination embodied in a n2n_sock_t.
 *
 *  @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_sock(n2n_sn_t *sss,
                           const n2n_sock_t *sock,
                           const uint8_t *pktbuf,
                           size_t pktsize)
{
    n2n_sock_str_t sockbuf;

    if (AF_INET == sock->family)
    {
        struct sockaddr_in udpsock;

        udpsock.sin_family = AF_INET;
        udpsock.sin_port = htons(sock->port);
        memcpy(&(udpsock.sin_addr.s_addr), &(sock->addr.v4), IPV4_SIZE);

        traceEvent(TRACE_DEBUG, "sendto_sock %lu to [%s]",
                   pktsize,
                   sock_to_cstr(sockbuf, sock));

        return sendto(sss->sock, pktbuf, pktsize, 0,
                      (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in));
    }
    else
    {
        /* AF_INET6 not implemented */
        errno = EAFNOSUPPORT;
        return -1;
    }
}

/** Try and broadcast a message to all edges in the community.
 *
 *  This will send the exact same datagram to zero or more edges registered to
 *  the supernode.
 */
static int try_broadcast(n2n_sn_t * sss,
                         const struct sn_community *comm,
                         const n2n_common_t * cmn,
                         const n2n_mac_t srcMac,
                         const uint8_t * pktbuf,
                         size_t pktsize)
{
  struct peer_info *scan, *tmp;
  macstr_t            mac_buf;
  n2n_sock_str_t      sockbuf;
  int successful_sends = 0;
  time_t now = time(NULL); /* Get time once for consistency */

  traceEvent(TRACE_DEBUG, "try_broadcast");

  /* Count potential destinations (excluding source) */
  int dest_count = 0;
  HASH_ITER(hh, comm->edges, scan, tmp) {
    if(memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) != 0) {
      dest_count++;
    }
  }

  /* Check rate limit with total expected traffic */
  if (dest_count > 0) {
    if (!check_rate_limit(sss, cmn->community, pktsize * dest_count, now)) {
        traceEvent(TRACE_DEBUG, "Rate limit exceeded for broadcast");
        return 0;
    }
  }

  HASH_ITER(hh, comm->edges, scan, tmp) {
    if(memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) != 0) {
      /* REVISIT: exclude if the destination socket is where the packet came from. */
      int data_sent_len;

      data_sent_len = sendto_sock(sss, &(scan->sock), pktbuf, pktsize);

      if(data_sent_len != pktsize)
      {
        ++(sss->stats.errors);
        traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
  		   pktsize,
		   sock_to_cstr(sockbuf, &(scan->sock)),
		   macaddr_str(mac_buf, scan->mac_addr),
		   strerror(errno));
      }
      else
      {
        ++(sss->stats.broadcast);
        successful_sends++;
        traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
	           pktsize,
		   sock_to_cstr(sockbuf, &(scan->sock)),
		   macaddr_str(mac_buf, scan->mac_addr));
      }
    }
  }

  /* Record traffic ONCE per broadcast packet */
  if (successful_sends > 0) {
      record_traffic(sss, cmn->community, pktsize * successful_sends, now);
  }

  return 0;
}

/** Initialise the supernode structure */
int sn_init(n2n_sn_t *sss) {
#ifdef WIN32
	initWin32();
#endif

	pearson_hash_init();

	memset(sss, 0, sizeof(n2n_sn_t));

	sss->daemon = 1; /* By defult run as a daemon. */
	sss->lport = N2N_SN_LPORT_DEFAULT;
	sss->mport = N2N_SN_MGMT_PORT;
	sss->sock = -1;
	sss->mgmt_sock = -1;
	sss->auto_ip_addr.net_addr = inet_addr(N2N_SN_AUTO_IP_NET_ADDR_DEFAULT);
	sss->auto_ip_addr.net_addr = ntohl(sss->auto_ip_addr.net_addr);
	sss->auto_ip_addr.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;

    /* Initialize traffic statistics */
    sss->community_stats = NULL;
    sss->num_communities = 0;
    sss->max_communities = 0;
    sss->rate_limit_rules = NULL;
    strcpy(sss->rate_limit_stats_path, "rate_limit.dat");
    sss->config_last_modified = 0;
    sss->last_stats_update = 0;
    sss->traffic_stats_enabled = 0;  /* Disabled by default */

    n2n_srand (n2n_seed()); /* https://github.com/ntop/n2n/pull/373/files */

	return 0; /* OK */
}

/** Deinitialise the supernode structure and deallocate any memory owned by
 *  it. */
void sn_term(n2n_sn_t *sss)
{
    struct sn_community *community, *tmp;

    if (sss->sock >= 0)
    {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    if (sss->mgmt_sock >= 0)
    {
        closesocket(sss->mgmt_sock);
    }
    sss->mgmt_sock = -1;

    HASH_ITER(hh, sss->communities, community, tmp)
    {
        clear_peer_list(&community->edges);
        if (NULL != community->header_encryption_ctx)
          free (community->header_encryption_ctx);
        HASH_DEL(sss->communities, community);
        free(community);
    }

    /* Clean up community statistics */
    if (sss->community_stats) {
        save_traffic_stats_periodic(sss);
        free(sss->community_stats);
        sss->community_stats = NULL;
    }

    /* Clean up rate limit rules */
    while (sss->rate_limit_rules) {
        struct rate_limit_rule *rule = sss->rate_limit_rules;
        sss->rate_limit_rules = rule->next;
        free(rule);
    }

#ifdef WIN32
	destroyWin32();
#endif
}

/** Determine the appropriate lifetime for new registrations.
 *
 *  If the supernode has been put into a pre-shutdown phase then this lifetime
 *  should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime(n2n_sn_t *sss)
{
    /* NOTE: UDP firewalls usually have a 30 seconds timeout */
    return 15;
}

/** Update the edge table with the details of the edge which contacted the
 *  supernode. */
static int update_edge(n2n_sn_t *sss,
                       const n2n_REGISTER_SUPER_t* reg,
                       struct sn_community *comm,
                       const n2n_sock_t *sender_sock,
                       time_t now) {
	macstr_t mac_buf;
	n2n_sock_str_t sockbuf;
	struct peer_info *scan;

    /* Validate MAC address first */
    if (!is_valid_mac(reg->edgeMac)) {
        traceEvent(TRACE_WARNING, "Rejecting invalid MAC address");
        return -1; /* Reject invalid MAC */
    }

	traceEvent(TRACE_DEBUG, "update_edge for %s [%s]",
	           macaddr_str(mac_buf, reg->edgeMac),
	           sock_to_cstr(sockbuf, sender_sock));

	HASH_FIND_PEER(comm->edges, reg->edgeMac, scan);

	if (NULL == scan) {
		/* Not known */

		scan = (struct peer_info *) calloc(1,
		                                   sizeof(struct peer_info)); /* deallocated in purge_expired_registrations */

		memcpy(&(scan->mac_addr), reg->edgeMac, sizeof(n2n_mac_t));
		scan->dev_addr.net_addr = reg->dev_addr.net_addr;
		scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
		memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
		scan->last_valid_time_stamp = initial_time_stamp();

		/* Store all LAN addresses */
		scan->num_local_socks = 0;
		uint8_t i;
		for (i = 0; i < reg->num_local_socks && i < N2N_MAX_LOCAL_ADDRS; i++) {
		    if (is_private_ip(&reg->local_socks[i])) {
		        memcpy(&(scan->local_socks[scan->num_local_socks]),
		               &reg->local_socks[i], sizeof(n2n_sock_t));
 		       scan->num_local_socks++;
		    }
		}

		if (scan->num_local_socks > 0) {
 		   traceEvent(TRACE_INFO, "Stored %d LAN address(es) for edge", scan->num_local_socks);
		} else {
		    traceEvent(TRACE_DEBUG, "No LAN addresses stored for edge");
		}

		HASH_ADD_PEER(comm->edges, scan);

		traceEvent(TRACE_INFO, "update_edge created   %s ==> %s",
		           macaddr_str(mac_buf, reg->edgeMac),
		           sock_to_cstr(sockbuf, sender_sock));
	} else {
		/* Known */
		if (!sock_equal(sender_sock, &(scan->sock))) {
			memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));

			traceEvent(TRACE_INFO, "update_edge updated   %s ==> %s",
			           macaddr_str(mac_buf, reg->edgeMac),
			           sock_to_cstr(sockbuf, sender_sock));
		} else {
			traceEvent(TRACE_DEBUG, "update_edge unchanged %s ==> %s",
			           macaddr_str(mac_buf, reg->edgeMac),
			           sock_to_cstr(sockbuf, sender_sock));
		}
	}

	scan->last_seen = now;
	return 0;
}


static signed int peer_tap_ip_sort(struct peer_info *a, struct peer_info *b) {
	uint32_t a_host_id = a->dev_addr.net_addr & (~bitlen2mask(a->dev_addr.net_bitlen));
	uint32_t b_host_id = b->dev_addr.net_addr & (~bitlen2mask(b->dev_addr.net_bitlen));
	return ((signed int)a_host_id - (signed int)b_host_id);
}


/** The IP address assigned to the edge by the auto ip function of sn. */
static int assign_one_ip_addr(n2n_sn_t *sss,
                              struct sn_community *comm,
                              n2n_ip_subnet_t *ipaddr) {
	struct peer_info *peer, *tmpPeer;
	uint32_t net_id, mask, max_host, host_id = 1;
	dec_ip_bit_str_t ip_bit_str = {'\0'};

	mask = bitlen2mask(sss->auto_ip_addr.net_bitlen);
	net_id = sss->auto_ip_addr.net_addr & mask;
	max_host = ~mask;

	HASH_SORT(comm->edges, peer_tap_ip_sort);
	HASH_ITER(hh, comm->edges, peer, tmpPeer) {
		if ((peer->dev_addr.net_addr & bitlen2mask(peer->dev_addr.net_bitlen)) == net_id) {
			if (host_id >= max_host) {
				traceEvent(TRACE_WARNING, "No assignable IP to edge tap adapter.");
				return -1;
			}
			if (peer->dev_addr.net_addr == 0) {
				continue;
			}
			if ((peer->dev_addr.net_addr & max_host) == host_id) {
				++host_id;
			} else {
				break;
			}
		}
	}
	ipaddr->net_addr = net_id | host_id;
	ipaddr->net_bitlen = sss->auto_ip_addr.net_bitlen;

	traceEvent(TRACE_INFO, "Assign IP %s to tap adapter of edge.", ip_subnet_to_str(ip_bit_str, ipaddr));
	return 0;
}


/***
 *
 * For a given packet, find the apporopriate internal last valid time stamp for lookup
 * and verify it (and also update, if applicable).
 */
static int find_edge_time_stamp_and_verify (struct peer_info * edges,
                                           int from_supernode, n2n_mac_t mac,
                                           uint64_t stamp) {

  uint64_t * previous_stamp = NULL;

  if(!from_supernode) {
    struct peer_info *edge;
    HASH_FIND_PEER(edges, mac, edge);
    if(edge) {
      // time_stamp_verify_and_update allows the pointer a previous stamp to be NULL
      // if it is a (so far) unknown edge
      previous_stamp = &(edge->last_valid_time_stamp);
    }
  }

  // failure --> 0;  success --> 1
  return ( time_stamp_verify_and_update (stamp, previous_stamp) );
}

static int purge_expired_communities(n2n_sn_t *sss,
                                     time_t* p_last_purge,
                                     time_t now)
{
  struct sn_community *comm, *tmp;
  size_t num_reg = 0;

  if ((now - (*p_last_purge)) < PURGE_REGISTRATION_FREQUENCY) return 0;

  traceEvent(TRACE_DEBUG, "Purging old communities and edges");

  HASH_ITER(hh, sss->communities, comm, tmp) {
    num_reg += purge_peer_list(&comm->edges, now - REGISTRATION_TIMEOUT);
    if ((comm->edges == NULL) && (!sss->lock_communities)) {
      traceEvent(TRACE_INFO, "Purging idle community %s", comm->community);

      /* NOTE: Traffic statistics are preserved even when community is purged
         to maintain 24-hour traffic counting across reconnections */

      if (NULL != comm->header_encryption_ctx)
        /* this should not happen as no 'locked' and thus only communities w/o encrypted header here */
        free(comm->header_encryption_ctx);
      HASH_DEL(sss->communities, comm);
      free(comm);
    }
  }
  (*p_last_purge) = now;

  traceEvent(TRACE_DEBUG, "Remove %ld edges", num_reg);

  return 0;
}

static int number_enc_packets_sort (struct sn_community *a, struct sn_community *b) {
  // comparison function for sorting communities in descending order of their
  // number_enc_packets-fields
  return (b->number_enc_packets - a->number_enc_packets);
}

static int sort_communities (n2n_sn_t *sss,
                             time_t* p_last_sort,
                             time_t now)
{
  struct sn_community *comm, *tmp;

  if ((now - (*p_last_sort)) < SORT_COMMUNITIES_INTERVAL) return 0;

  // this routine gets periodically called as defined in SORT_COMMUNITIES_INTERVAL
  // it sorts the communities in descending order of their number_enc_packets-fields...
  HASH_SORT(sss->communities, number_enc_packets_sort);

  // ... and afterward resets the number_enc__packets-fields to zero
  // (other models could reset it to half of their value to respect history)
  HASH_ITER(hh, sss->communities, comm, tmp) {
    comm->number_enc_packets = 0;
  }

  (*p_last_sort) = now;

  return 0;
}

static int process_mgmt(n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size,
                        time_t now) {
	char resbuf[N2N_SN_PKTBUF_SIZE];
	size_t ressize = 0;
	uint32_t displayed_edges = 0;
	uint32_t num = 0;
	struct sn_community *community, *tmp;
	struct peer_info *peer, *tmpPeer;
	macstr_t mac_buf;
	n2n_sock_str_t sockbuf;
	dec_ip_bit_str_t ip_bit_str = {'\0'};

    double total_instant_kbps = 0.0;
    double total_last_24h_gb = 0.0;
    double total_gb = 0.0;

	traceEvent(TRACE_DEBUG, "process_mgmt");

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    " id  mac                lan_ip              wan_ip                     lseen\n");
	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "---v2------------------------------------------------------------------v2---\n");

    /* Display communities and their edges with integrated traffic stats */
	HASH_ITER(hh, sss->communities, community, tmp) {

		/* Find traffic stats for this community */
		struct community_traffic_stats *stats = NULL;
		int j;
		for (j = 0; j < sss->num_communities; j++) {
			if (memcmp(sss->community_stats[j].community_name, community->community,
			           sizeof(n2n_community_t)) == 0) {
				stats = &sss->community_stats[j];
				break;
			}
		}

		/* Display online communities (always shown regardless of traffic) */
		if (stats && sss->traffic_stats_enabled && stats->total_bytes > 0) {
    		double display_kbps = stats->instant_bps / 1024.0;
    		double last_24h_gb = stats->last_24h_bytes / (1024.0 * 1024.0 * 1024.0);
    		double total_gb_for_community = stats->total_bytes / (1024.0 * 1024.0 * 1024.0);

            /* Check if inactive for more than 10 seconds */
            if (stats->last_second_update > 0 && (now - stats->last_second_update) > 10) {
                display_kbps = 0.0;
            }

            /* Update totals */
            total_instant_kbps += display_kbps;
            total_last_24h_gb += last_24h_gb;
            total_gb += total_gb_for_community;

            if (display_kbps == 0.0) {
                ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                    "%-37s  %4s %-7.1f  %-7.1f  %-10.1f\n",
                                    community->community, "    ", 0.0, last_24h_gb, total_gb_for_community);
            } else {
                ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                    "%-37s  %4s %-7.1f  %-7.1f  %-10.1f\n",
                                    community->community, "--->", display_kbps, last_24h_gb, total_gb_for_community);
            }
		} else {
    		ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize, "%s\n", community->community);
		}

		sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
		ressize = 0;

        /* Display edges for this community */
		num = 0;
		HASH_ITER(hh, community->edges, peer, tmpPeer) {
			ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
			                    "\%3u  %-17s  %-18s  %-21s      %1lu\n",
			                    ++num, macaddr_str(mac_buf, peer->mac_addr),
			                    ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
			                    sock_to_cstr(sockbuf, &(peer->sock)), now - peer->last_seen);

			sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
			ressize = 0;
		}
		displayed_edges += num;
	}

    /* Display inactive communities with traffic */
    if (sss->traffic_stats_enabled) {
        int i;
        double inactive_total_gb = 0.0; /* Total traffic of communities offline for >24h */

        for (i = 0; i < sss->num_communities; i++) {
            /* Skip communities with no traffic at all */
            if (sss->community_stats[i].total_bytes == 0) {
                continue;
            }

            /* Check if already displayed as active (currently online) */
            int found_active = 0;
            HASH_ITER(hh, sss->communities, community, tmp) {
                if (memcmp(sss->community_stats[i].community_name, community->community,
                          sizeof(n2n_community_t)) == 0) {
                    found_active = 1;
                    break;
                }
            }
            if (found_active) continue;

            double last_24h_gb = sss->community_stats[i].last_24h_bytes / (1024.0 * 1024.0 * 1024.0);
            double total_gb_inactive = sss->community_stats[i].total_bytes / (1024.0 * 1024.0 * 1024.0);

            /* Offline community with last activity >24h ago: fold into summary row */
            time_t last_active = sss->community_stats[i].last_second_update;
            if (last_active == 0 || (now - last_active) > 86400) {
                inactive_total_gb += total_gb_inactive;
                total_gb += total_gb_inactive;
                continue;
            }

            /* Community went offline recently (within 24h): show it */
            total_last_24h_gb += last_24h_gb;
            total_gb += total_gb_inactive;

            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "%-37s  %4s %-7.1f  %-7.1f  %-10.1f\n",
                                sss->community_stats[i].community_name, "    ",
                                0.0, last_24h_gb, total_gb_inactive);
            sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }

        /* Show a single summary row for offline communities inactive for >24h */
        if (inactive_total_gb > 0) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "%-37s  %4s %-7s  %-7s  %-10.1f\n",
                                "offline_community/24h", "    ",
                                "0.0", "0.0", inactive_total_gb);
            sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }
    }

    /* Display total statistics only if there are communities with traffic */
    if (total_gb > 0) {
        struct tm *start_tm = localtime(&sss->community_stats[0].stats_start_time);
        char start_date[9];
        strftime(start_date, sizeof(start_date), "%Y%m%d", start_tm);

	    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                            "---------------------\n");

        if (total_instant_kbps == 0.0) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "Total (KB/s  GB/24h  GB/From:%s) %4s %-7.1f  %-7.1f  %-10.1f\n",
                                start_date, "    ", 0.0, total_last_24h_gb, total_gb);
        } else {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "Total (KB/s  GB/24h  GB/From:%s) %4s %-7.1f  %-7.1f  %-10.1f\n",
                                start_date, "--->", total_instant_kbps, total_last_24h_gb, total_gb);
        }
    	sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
    	ressize = 0;
	}

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "---v2------------------------------------------------------------------v2---\n");

	/* Format current date and time */
	struct tm *tm_info = localtime(&now);
	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "%02d-%02d-%02d %02d:%02d up ",
                        tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
                        tm_info->tm_hour, tm_info->tm_min);

	/* Count the number of seconds running time */
	unsigned long uptime = now - sss->start_time;

	/* Converts the number of seconds to days, hours, minutes, and seconds */
	unsigned long days = uptime / (24 * 60 * 60);
	uptime %= (24 * 60 * 60);
	unsigned long hours = uptime / (60 * 60);
	uptime %= (60 * 60);
	unsigned long minutes = uptime / 60;

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "%lud_%luh_%lum | ", days, hours, minutes);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "edges %u | ", displayed_edges);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "cmnts %u | ", HASH_COUNT(sss->communities));

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "reg_nak %u | ",
	                    (unsigned int) sss->stats.reg_super_nak);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "errs %u\n",
	                    (unsigned int) sss->stats.errors);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "broadcast %u | ",
	                    (unsigned int) sss->stats.broadcast);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "reg_sup %u | ",
	                    (unsigned int) sss->stats.reg_super);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
	                    "fwd %u | ",
	                    (unsigned int) sss->stats.fwd);

	ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last_fwd/_reg %lu/%lus ago\n\n",
                        (long unsigned int) (now - sss->stats.last_fwd),
                        (long unsigned int) (now - sss->stats.last_reg_super));

	sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);

	return 0;
}

static int sendto_mgmt(n2n_sn_t *sss,
                       const struct sockaddr_in *sender_sock,
                       const uint8_t *mgmt_buf,
                       size_t mgmt_size)
{
  ssize_t r = sendto(sss->mgmt_sock, mgmt_buf, mgmt_size, 0 /*flags*/,
                     (struct sockaddr *)sender_sock, sizeof (struct sockaddr_in));

  if (r <= 0) {
    ++(sss->stats.errors);
    traceEvent (TRACE_ERROR, "sendto_mgmt : sendto failed. %s", strerror (errno));
    return -1;
  }
  return 0;
}

/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp(n2n_sn_t * sss,
		       const struct sockaddr_in * sender_sock,
		       uint8_t * udp_buf,
		       size_t udp_size,
		       time_t now)
{
  n2n_common_t        cmn; /* common fields in the packet header */
  size_t              rem;
  size_t              idx;
  size_t              msg_type;
  uint8_t             from_supernode;
  macstr_t            mac_buf;
  macstr_t            mac_buf2;
  n2n_sock_str_t      sockbuf;
  char                buf[32];
  struct sn_community *comm, *tmp;
  uint64_t	      stamp;
  const n2n_mac_t               null_mac = {0, 0, 0, 0, 0, 0}; /* 00:00:00:00:00:00 */

  traceEvent(TRACE_DEBUG, "Processing incoming UDP packet [len: %lu][sender: %s:%u]",
	     udp_size, intoa(ntohl(sender_sock->sin_addr.s_addr), buf, sizeof(buf)),
	     ntohs(sender_sock->sin_port));

  /* check if header is unenrypted. the following check is around 99.99962 percent reliable.
   * it heavily relies on the structure of packet's common part
   * changes to wire.c:encode/decode_common need to go together with this code */
  if (udp_size < 20) {
    traceEvent(TRACE_DEBUG, "process_udp dropped a packet too short to be valid.");
    return -1;
  }
  if ( (udp_buf[19] == (uint8_t)0x00) // null terminated community name
       && (udp_buf[00] == N2N_PKT_VERSION) // correct packet version
       && ((be16toh (*(uint16_t*)&(udp_buf[02])) & N2N_FLAGS_TYPE_MASK ) <= MSG_TYPE_MAX_TYPE  ) // message type
       && ( be16toh (*(uint16_t*)&(udp_buf[02])) < N2N_FLAGS_OPTIONS) // flags
       ) {
    /* most probably unencrypted */
    /* make sure, no downgrading happens here and no unencrypted packets can be
     * injected in a community which definitely deals with encrypted headers */
    HASH_FIND_COMMUNITY(sss->communities, (char *)&udp_buf[04], comm);
    if (comm) {
      if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        traceEvent(TRACE_DEBUG, "process_udp dropped a packet with unencrypted header "
                                "addressed to community '%s' which uses encrypted headers.",
                                 comm->community);
        return -1;
      }
      if (comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
	traceEvent (TRACE_INFO, "process_udp locked community '%s' to using "
                                "unencrypted headers.", comm->community);
        /* set 'no encryption' in case it is not set yet */
        comm->header_encryption = HEADER_ENCRYPTION_NONE;
        comm->header_encryption_ctx = NULL;
      }
    }
  } else {
    /* most probably encrypted */
    /* cycle through the known communities (as keys) to eventually decrypt */
    uint32_t ret = 0;
    HASH_ITER (hh, sss->communities, comm, tmp) {
      /* skip the definitely unencrypted communities */
      if (comm->header_encryption == HEADER_ENCRYPTION_NONE)
        continue;
      uint16_t checksum = 0;
      if ( (ret = packet_header_decrypt (udp_buf, udp_size, comm->community, comm->header_encryption_ctx,
                                         comm->header_iv_ctx,
                                         &stamp, &checksum)) ) {
        // time stamp verification follows in the packet specific section as it requires to determine the
        // sender from the hash list by its MAC, this all depends on packet type and packet structure
        // (MAC is not always in the same place)
       if (checksum != pearson_hash_16 (udp_buf, udp_size)) {
         traceEvent(TRACE_DEBUG, "process_udp dropped packet due to checksum error.");
         return -1;
        }
        if (comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
	  traceEvent (TRACE_INFO, "process_udp locked community '%s' to using "
                                  "encrypted headers.", comm->community);
          /* set 'encrypted' in case it is not set yet */
          comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
        }
        // count the number of encrypted packets for sorting the communities from time to time
	// for the HASH_ITER a few lines above gets faster for the more busy communities
        (comm->number_enc_packets)++;
	// no need to test further communities
        break;
      }
    }
    if (!ret) {
      // no matching key/community
      traceEvent(TRACE_DEBUG, "process_udp dropped a packet with seemingly encrypted header "
			      "for which no matching community which uses encrypted headers was found.");
      return -1;
    }
  }

  /* Use decode_common() to determine the kind of packet then process it:
   *
   * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
   *
   * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
   * destination edge. If the destination is not known then PACKETs are
   * broadcast.
   */

  rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
  idx = 0; /* marches through packet header as parts are decoded. */
  if(decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
    traceEvent(TRACE_ERROR, "Failed to decode common section");
    return -1; /* failed to decode packet */
  }

  msg_type = cmn.pc; /* packet code */
  from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

  if(cmn.ttl < 1) {
    traceEvent(TRACE_WARNING, "Expired TTL");
    return 0; /* Don't process further */
  }

  --(cmn.ttl); /* The value copied into all forwarded packets. */

  switch(msg_type) {
  case MSG_TYPE_PACKET:
  {
    /* PACKET from one edge to another edge via supernode. */

    /* pkt will be modified in place and recoded to an output of potentially
     * different size due to addition of the socket.*/
    n2n_PACKET_t                    pkt;
    n2n_common_t                    cmn2;
    uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
    size_t                          encx=0;
    int                             unicast; /* non-zero if unicast */
    uint8_t *                       rec_buf; /* either udp_buf or encbuf */

    if(!comm) {
      traceEvent(TRACE_DEBUG, "process_udp PACKET with unknown community %s", cmn.community);
      return -1;
    }

    sss->stats.last_fwd=now;
    decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

    // already checked for valid comm
    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
      if(!find_edge_time_stamp_and_verify (comm->edges, from_supernode, pkt.srcMac, stamp)) {
        traceEvent(TRACE_DEBUG, "process_udp dropped PACKET due to time stamp error.");
        return -1;
      }
    }

    unicast = (0 == is_multi_broadcast(pkt.dstMac));

    traceEvent(TRACE_DEBUG, "RX PACKET (%s) %s -> %s %s",
	       (unicast?"unicast":"multicast"),
	       macaddr_str(mac_buf, pkt.srcMac),
	       macaddr_str(mac_buf2, pkt.dstMac),
	       (from_supernode?"from sn":"local"));

    if(!from_supernode) {
      memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

      /* We are going to add socket even if it was not there before */
      cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

      pkt.sock.family = AF_INET;
      pkt.sock.port = ntohs(sender_sock->sin_port);
      memcpy(pkt.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

      rec_buf = encbuf;

      /* Re-encode the header. */
      encode_PACKET(encbuf, &encx, &cmn2, &pkt);
      uint16_t oldEncx = encx;

      /* Copy the original payload unchanged */
      encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));

      if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt (rec_buf, oldEncx, comm->header_encryption_ctx,
                                                 comm->header_iv_ctx,
                                                 time_stamp (), pearson_hash_16 (rec_buf, encx));

    } else {
      /* Already from a supernode. Nothing to modify, just pass to
       * destination. */

      traceEvent(TRACE_DEBUG, "Rx PACKET fwd unmodified");

      rec_buf = udp_buf;
      encx = udp_size;

      if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt (rec_buf, idx, comm->header_encryption_ctx,
                                             comm->header_iv_ctx,
                                             time_stamp (), pearson_hash_16 (rec_buf, udp_size));
    }

    /* Common section to forward the final product. */
    if(unicast)
      try_forward(sss, comm, &cmn, pkt.dstMac, rec_buf, encx);
    else
      try_broadcast(sss, comm, &cmn, pkt.srcMac, rec_buf, encx);
    break;
  }
  case MSG_TYPE_REGISTER:
  {
    /* Forwarding a REGISTER from one edge to the next */

    n2n_REGISTER_t                  reg;
    n2n_common_t                    cmn2;
    uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
    size_t                          encx=0;
    int                             unicast; /* non-zero if unicast */
    uint8_t *                       rec_buf; /* either udp_buf or encbuf */

    if(!comm) {
      traceEvent(TRACE_DEBUG, "process_udp REGISTER from unknown community %s", cmn.community);
      return -1;
    }

    sss->stats.last_fwd=now;
    decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

    // already checked for valid comm
    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
      if(!find_edge_time_stamp_and_verify (comm->edges, from_supernode, reg.srcMac, stamp)) {
        traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER due to time stamp error.");
        return -1;
      }
    }

    unicast = (0 == is_multi_broadcast(reg.dstMac));

    if(unicast) {
      traceEvent(TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
		 macaddr_str(mac_buf, reg.srcMac),
		 macaddr_str(mac_buf2, reg.dstMac),
		 ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE)?"from sn":"local"));

      if(0 == (cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) {
	memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

	/* We are going to add socket even if it was not there before */
	cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

	reg.sock.family = AF_INET;
	reg.sock.port = ntohs(sender_sock->sin_port);
	memcpy(reg.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

	/* Re-encode the header. */
		encode_REGISTER(encbuf, &encx, &cmn2, &reg);

	rec_buf = encbuf;
      } else {
	/* Already from a supernode. Nothing to modify, just pass to
	 * destination. */

	rec_buf = udp_buf;
	encx = udp_size;
      }

      if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt (rec_buf, encx, comm->header_encryption_ctx,
                                             comm->header_iv_ctx,
                                             time_stamp (), pearson_hash_16 (rec_buf, encx));

      try_forward(sss, comm, &cmn, reg.dstMac, rec_buf, encx); /* unicast only */
    } else
      traceEvent(TRACE_ERROR, "Rx REGISTER with multicast destination");
    break;
  }
  case MSG_TYPE_REGISTER_ACK:
    traceEvent(TRACE_DEBUG, "Rx REGISTER_ACK (NOT IMPLEMENTED) Should not be via supernode");
    break;
  case MSG_TYPE_REGISTER_SUPER:
  {
    n2n_REGISTER_SUPER_t            reg;
    n2n_REGISTER_SUPER_ACK_t        ack;
    n2n_common_t                    cmn2;
    uint8_t                         ackbuf[N2N_SN_PKTBUF_SIZE];
    size_t                          encx=0;
    n2n_ip_subnet_t                 ipaddr;

	  memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

    /* Edge requesting registration with us.  */
    sss->stats.last_reg_super=now;
    ++(sss->stats.reg_super);
    decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

    if (comm) {
      if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_edge_time_stamp_and_verify (comm->edges, from_supernode, reg.edgeMac, stamp)) {
          traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER due to time stamp error.");
          return -1;
        }
      }
    }

    /*
      Before we move any further, we need to check if the requested
      community is allowed by the supernode. In case it is not we do
      not report any message back to the edge to hide the supernode
      existance (better from the security standpoint)
    */
    if(!comm && !sss->lock_communities) {
      comm = calloc(1, sizeof(struct sn_community));

      if(comm) {
	strncpy(comm->community, (char*)cmn.community, N2N_COMMUNITY_SIZE-1);
	comm->community[N2N_COMMUNITY_SIZE-1] = '\0';
        /* new communities introduced by REGISTERs could not have had encrypted header */
        comm->header_encryption = HEADER_ENCRYPTION_NONE;
	comm->header_encryption_ctx = NULL;
        comm->number_enc_packets = 0;
	HASH_ADD_STR(sss->communities, community, comm);

	traceEvent(TRACE_INFO, "New community: %s", comm->community);
      }
    }

    if(comm) {
      cmn2.ttl = N2N_DEFAULT_TTL;
      cmn2.pc = n2n_register_super_ack;
      cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
      memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

      memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
      memcpy(ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t));
	    if ((reg.dev_addr.net_addr == 0) || (reg.dev_addr.net_addr == 0xFFFFFFFF) || (reg.dev_addr.net_bitlen == 0) ||
	        ((reg.dev_addr.net_addr & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0 */)) {
		    memset(&ipaddr, 0, sizeof(n2n_ip_subnet_t));
		    assign_one_ip_addr(sss, comm, &ipaddr);
		    ack.dev_addr.net_addr = ipaddr.net_addr;
		    ack.dev_addr.net_bitlen = ipaddr.net_bitlen;
	    }
      ack.lifetime = reg_lifetime(sss);

      ack.sock.family = AF_INET;
      ack.sock.port = ntohs(sender_sock->sin_port);
      memcpy(ack.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

      ack.num_sn=0; /* No backup */

      traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER for %s [%s]",
		 macaddr_str(mac_buf, reg.edgeMac),
		 sock_to_cstr(sockbuf, &(ack.sock)));

      if (!is_valid_mac(reg.edgeMac)) {
          traceEvent(TRACE_DEBUG, "Rejecting REGISTER_SUPER with invalid MAC");
          break; /* Drop the packet */
      }

      if(memcmp(reg.edgeMac, &null_mac, N2N_MAC_SIZE) != 0){
	      update_edge(sss, &reg, comm, &(ack.sock), now);
      }

      encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack);

      if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt (ackbuf, encx, comm->header_encryption_ctx,
                                             comm->header_iv_ctx,
                                             time_stamp (), pearson_hash_16 (ackbuf, encx));

      sendto(sss->sock, ackbuf, encx, 0,
	     (struct sockaddr *)sender_sock, sizeof(struct sockaddr_in));

      traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s [%s]",
		 macaddr_str(mac_buf, reg.edgeMac),
		 sock_to_cstr(sockbuf, &(ack.sock)));
    } else
      traceEvent(TRACE_INFO, "Discarded registration: unallowed community '%s'",
		 (char*)cmn.community);
    break;
  }
  case MSG_TYPE_QUERY_PEER: {
    n2n_QUERY_PEER_t query;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    size_t encx=0;
    n2n_common_t cmn2;
    n2n_PEER_INFO_t pi;

    if(!comm) {
      traceEvent(TRACE_DEBUG, "process_udp QUERY_PEER from unknown community %s", cmn.community);
      return -1;
    }

    decode_QUERY_PEER( &query, &cmn, udp_buf, &rem, &idx );

    // already checked for valid comm
    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
      if(!find_edge_time_stamp_and_verify (comm->edges, from_supernode, query.srcMac, stamp)) {
        traceEvent(TRACE_DEBUG, "process_udp dropped QUERY_PEER due to time stamp error.");
        return -1;
      }
    }

    traceEvent( TRACE_DEBUG, "Rx QUERY_PEER from %s for %s",
                macaddr_str( mac_buf,  query.srcMac ),
                macaddr_str( mac_buf2, query.targetMac ) );

    struct peer_info *scan;
    HASH_FIND_PEER(comm->edges, query.targetMac, scan);

    if (scan) {
      cmn2.ttl = N2N_DEFAULT_TTL;
      cmn2.pc = n2n_peer_info;
      cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
      memcpy( cmn2.community, cmn.community, sizeof(n2n_community_t) );

      pi.aflags = 0;
      memcpy( pi.mac, query.targetMac, sizeof(n2n_mac_t) );
      pi.sock = scan->sock;

      /* Add all LAN addresses */
      pi.num_local_socks = scan->num_local_socks;
      if (pi.num_local_socks > N2N_MAX_LOCAL_ADDRS) {
          pi.num_local_socks = N2N_MAX_LOCAL_ADDRS;
      }
	  uint8_t i;
      for (i = 0; i < pi.num_local_socks; i++) {
          memcpy(&pi.local_socks[i], &scan->local_socks[i], sizeof(n2n_sock_t));
      }

      encode_PEER_INFO( encbuf, &encx, &cmn2, &pi );

      if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt (encbuf, encx, comm->header_encryption_ctx,
                                             comm->header_iv_ctx,
                                             time_stamp (), pearson_hash_16 (encbuf, encx));

      sendto( sss->sock, encbuf, encx, 0,
	      (struct sockaddr *)sender_sock, sizeof(struct sockaddr_in) );

      traceEvent( TRACE_DEBUG, "Tx PEER_INFO to %s",
		                macaddr_str( mac_buf, query.srcMac ) );
    } else {
      traceEvent( TRACE_DEBUG, "Ignoring QUERY_PEER for unknown edge %s",
	                        macaddr_str( mac_buf, query.targetMac ) );
    }

  break;
  }
  default:
    /* Not a known message type */
    traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
  } /* switch(msg_type) */

  return 0;
}

/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
int run_sn_loop(n2n_sn_t *sss, int *keep_running)
{
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    time_t last_purge_edges = 0;
    time_t last_sort_communities = 0;

    sss->start_time = time(NULL);

    while (*keep_running)
    {
        int rc;
        ssize_t bread;
        int max_sock;
        fd_set socket_mask;
        struct timeval wait_time;
        time_t now = 0;

        FD_ZERO(&socket_mask);
        max_sock = MAX(sss->sock, sss->mgmt_sock);

        FD_SET(sss->sock, &socket_mask);
        FD_SET(sss->mgmt_sock, &socket_mask);

        wait_time.tv_sec = 10;
        wait_time.tv_usec = 0;
        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        if (rc > 0)
        {
            if (FD_ISSET(sss->sock, &socket_mask))
            {
                struct sockaddr_in sender_sock;
                socklen_t i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                 (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                if ((bread < 0)
#ifdef WIN32
                    && (WSAGetLastError() != WSAECONNRESET)
#endif
                )
                {
                    /* For UDP bread of zero just means no data (unlike TCP). */
                    /* The fd is no good now. Maybe we lost our interface. */
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
                    traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                    *keep_running = 0;
                    break;
                }

                /* We have a datagram to process */
                if (bread > 0)
                {
                    /* And the datagram has data (not just a header) */
                    process_udp(sss, &sender_sock, pktbuf, bread, now);
                }
            }

            if (FD_ISSET(sss->mgmt_sock, &socket_mask))
            {
                struct sockaddr_in sender_sock;
                size_t i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->mgmt_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                 (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                if (bread <= 0)
                {
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                    *keep_running = 0;
                    break;
                }

                /* We have a datagram to process */
                process_mgmt(sss, &sender_sock, pktbuf, bread, now);
            }
        }
        else
        {
            traceEvent(TRACE_DEBUG, "timeout");
        }

        purge_expired_communities(sss, &last_purge_edges, now);
	sort_communities (sss, &last_sort_communities, now);
	    check_periodic_save(sss, now);
    } /* while */

    sn_term(sss);

    return 0;
}
