/*
 * ConfD CDB subscriber for the DPDK SPI/DPI process.
 *
 * A CDB subscription is control-plane only.  On a completed ConfD commit we
 * read one consistent CDB_RUNNING snapshot, write it to a temporary file,
 * fsync it, atomically rename it over the configured YAML file, and only then
 * notify the data-plane process with SIGUSR1.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <confd_cdb.h>
#include <confd_lib.h>

#define VALUE_BUF_SIZE 1024
#define PATH_BUF_SIZE 4096

static const char *config_path;
static pid_t dpdk_pid;
static const char *confd_ip = "127.0.0.1";
static int confd_port = CONFD_PORT;

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s --config <path> [--pid <pid>] [--confd-ip <ip>] [--confd-port <port>]\n", program);
}

static pid_t find_dpdk_pid(void) {
    FILE *fp = popen("pidof FastAPI", "r");
    pid_t pid = 0;
    if (fp != NULL) {
        (void)fscanf(fp, "%d", &pid);
        (void)pclose(fp);
    }
    return pid;
}

static int signal_dpdk_reload(void) {
    if (dpdk_pid <= 0) dpdk_pid = find_dpdk_pid();
    if (dpdk_pid <= 0) {
        fprintf(stderr, "fastapi_confd: DPDK process not found\n");
        return -1;
    }
    if (kill(dpdk_pid, SIGUSR1) != 0) {
        fprintf(stderr, "fastapi_confd: SIGUSR1 to pid %d failed: %s\n", dpdk_pid, strerror(errno));
        return -1;
    }
    return 0;
}

/* Always quote strings so CDB values cannot alter the YAML structure. */
static int yaml_string(FILE *out, const char *value) {
    if (fputc('"', out) == EOF) return -1;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        switch (*p) {
        case '\\': if (fputs("\\\\", out) == EOF) return -1; break;
        case '"':  if (fputs("\\\"", out) == EOF) return -1; break;
        case '\n': if (fputs("\\n", out) == EOF) return -1; break;
        case '\r': if (fputs("\\r", out) == EOF) return -1; break;
        case '\t': if (fputs("\\t", out) == EOF) return -1; break;
        default:
            if (*p < 0x20 || fputc(*p, out) == EOF) return -1;
        }
    }
    return fputc('"', out) == EOF ? -1 : 0;
}

static int read_string(int sock, char *out, size_t size, const char *path) {
    memset(out, 0, size);
    return cdb_get_str(sock, out, (int)size, path) == CONFD_OK ? 0 : -1;
}

static int emit_optional_string(FILE *out, int sock, const char *key, const char *path, int indent) {
    char value[VALUE_BUF_SIZE];
    if (read_string(sock, value, sizeof(value), path) != 0) return 0;
    fprintf(out, "%*s%s: ", indent, "", key);
    return yaml_string(out, value) || fputc('\n', out) == EOF ? -1 : 0;
}

static int emit_optional_u32(FILE *out, int sock, const char *key, const char *path, int indent) {
    confd_value_t value;
    char rendered[64];
    if (cdb_get(sock, &value, path) != CONFD_OK) return 0;
    confd_pp_value(rendered, sizeof(rendered), &value);
    confd_free_value(&value);
    return fprintf(out, "%*s%s: %s\n", indent, "", key, rendered) < 0 ? -1 : 0;
}

static int emit_optional_bool(FILE *out, int sock, const char *key, const char *path, int indent) {
    int value;
    if (cdb_get_bool(sock, &value, path) != CONFD_OK) return 0;
    return fprintf(out, "%*s%s: %s\n", indent, "", key, value ? "true" : "false") < 0 ? -1 : 0;
}

static int write_tcp_reassembly(FILE *out, int sock) {
    if (fprintf(out, "  tcp_reassembly:\n") < 0 ||
        emit_optional_bool(out, sock, "enabled", "/fastapi:fastapi/spi/tcp_reassembly/enabled", 4) ||
        emit_optional_u32(out, sock, "idle_timeout_sec", "/fastapi:fastapi/spi/tcp_reassembly/idle_timeout_sec", 4) ||
        emit_optional_u32(out, sock, "max_concurrent_streams", "/fastapi:fastapi/spi/tcp_reassembly/max_concurrent_streams", 4) ||
        emit_optional_u32(out, sock, "max_buffered_bytes_per_direction", "/fastapi:fastapi/spi/tcp_reassembly/max_buffered_bytes_per_direction", 4) ||
        emit_optional_u32(out, sock, "max_out_of_order_segments", "/fastapi:fastapi/spi/tcp_reassembly/max_out_of_order_segments", 4) ||
        emit_optional_u32(out, sock, "memory_budget_mb", "/fastapi:fastapi/spi/tcp_reassembly/memory_budget_mb", 4) ||
        emit_optional_bool(out, sock, "drop_conflicting_overlap", "/fastapi:fastapi/spi/tcp_reassembly/drop_conflicting_overlap", 4)) return -1;
    return 0;
}

/* Export the complete ACL-relevant SPI subtree, including both nested lists. */
static int write_spi(FILE *out, int sock) {
    const char *base = "/fastapi:fastapi/spi";
    if (fprintf(out, "\nspi:\n") < 0) return -1;
    if (emit_optional_u32(out, sock, "worker_count", "/fastapi:fastapi/spi/worker_count", 2) ||
        emit_optional_string(out, sock, "packet_distribution", "/fastapi:fastapi/spi/packet_distribution", 2) ||
        emit_optional_u32(out, sock, "dispatch_queue_size", "/fastapi:fastapi/spi/dispatch_queue_size", 2) ||
        emit_optional_bool(out, sock, "drop_unmatched", "/fastapi:fastapi/spi/drop_unmatched", 2) ||
        emit_optional_u32(out, sock, "flow_ttl_sec", "/fastapi:fastapi/spi/flow_ttl_sec", 2) ||
        emit_optional_u32(out, sock, "max_concurrent_flows", "/fastapi:fastapi/spi/max_concurrent_flows", 2) ||
        emit_optional_string(out, sock, "flow_overflow_action", "/fastapi:fastapi/spi/flow_overflow_action", 2) ||
        emit_optional_u32(out, sock, "fragment_timeout_sec", "/fastapi:fastapi/spi/fragment_timeout_sec", 2) ||
        emit_optional_u32(out, sock, "max_compilation_threads", "/fastapi:fastapi/spi/max_compilation_threads", 2) ||
        emit_optional_u32(out, sock, "max_acl_build_threads", "/fastapi:fastapi/spi/max_acl_build_threads", 2) ||
        emit_optional_string(out, sock, "acl_classify_algorithm", "/fastapi:fastapi/spi/acl_classify_algorithm", 2) ||
        emit_optional_u32(out, sock, "acl_build_max_size_mb", "/fastapi:fastapi/spi/acl_build_max_size_mb", 2)) return -1;
    if (write_tcp_reassembly(out, sock)) return -1;

    int groups = cdb_num_instances(sock, "%s/filter-groups", base);
    if (groups < 0) return -1;
    if (fprintf(out, "  filter_groups:\n") < 0) return -1;
    for (int group = 0; group < groups; ++group) {
        char path[PATH_BUF_SIZE], value[VALUE_BUF_SIZE];
        snprintf(path, sizeof(path), "%s/filter-groups[%d]/name", base, group);
        if (read_string(sock, value, sizeof(value), path) != 0) return -1;
        if (fprintf(out, "    - name: ") < 0 || yaml_string(out, value) || fputc('\n', out) == EOF) return -1;
        snprintf(path, sizeof(path), "%s/filter-groups[%d]/precedence", base, group);
        if (emit_optional_u32(out, sock, "precedence", path, 6)) return -1;
        snprintf(path, sizeof(path), "%s/filter-groups[%d]/action", base, group);
        if (emit_optional_string(out, sock, "action", path, 6)) return -1;
        snprintf(path, sizeof(path), "%s/filter-groups[%d]/l7_required", base, group);
        if (emit_optional_bool(out, sock, "l7_required", path, 6)) return -1;
        snprintf(path, sizeof(path), "%s/filter-groups[%d]/dpi_filter_group", base, group);
        if (emit_optional_string(out, sock, "dpi_filter_group", path, 6)) return -1;

        snprintf(path, sizeof(path), "%s/filter-groups[%d]/filters", base, group);
        int filters = cdb_num_instances(sock, path);
        if (filters < 0 || fprintf(out, "      filters:\n") < 0) return -1;
        for (int filter = 0; filter < filters; ++filter) {
            snprintf(path, sizeof(path), "%s/filter-groups[%d]/filters[%d]/protocol", base, group, filter);
            if (read_string(sock, value, sizeof(value), path) != 0) return -1;
            if (fprintf(out, "        - protocol: ") < 0 || yaml_string(out, value) || fputc('\n', out) == EOF) return -1;
            const char *keys[] = {"source_ip_address", "destination_ip_address", "label"};
            for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
                snprintf(path, sizeof(path), "%s/filter-groups[%d]/filters[%d]/%s", base, group, filter, keys[i]);
                if (emit_optional_string(out, sock, keys[i], path, 10)) return -1;
            }
            const char *ports[] = {"source_port", "destination_port"};
            for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); ++i) {
                snprintf(path, sizeof(path), "%s/filter-groups[%d]/filters[%d]/%s", base, group, filter, ports[i]);
                if (emit_optional_u32(out, sock, ports[i], path, 10)) return -1;
            }
        }
    }
    return 0;
}

static int write_dpi(FILE *out, int sock) {
    const char *base = "/fastapi:fastapi/dpi";
    if (fprintf(out, "\ndpi:\n") < 0 ||
        emit_optional_bool(out, sock, "enabled", "/fastapi:fastapi/dpi/enabled", 2)) return -1;
    int filters = cdb_num_instances(sock, "%s/filters", base);
    if (filters < 0 || fprintf(out, "  filters:\n") < 0) return -1;
    for (int filter = 0; filter < filters; ++filter) {
        char path[PATH_BUF_SIZE], value[VALUE_BUF_SIZE];
        snprintf(path, sizeof(path), "%s/filters[%d]/hostname_pattern", base, filter);
        if (read_string(sock, value, sizeof(value), path) != 0 ||
            fprintf(out, "    - hostname_pattern: ") < 0 || yaml_string(out, value) ||
            fputc('\n', out) == EOF) return -1;
        const char *string_keys[] = {"filter_group", "label"};
        for (size_t i = 0; i < sizeof(string_keys) / sizeof(string_keys[0]); ++i) {
            snprintf(path, sizeof(path), "%s/filters[%d]/%s", base, filter, string_keys[i]);
            if (emit_optional_string(out, sock, string_keys[i], path, 6)) return -1;
        }
        snprintf(path, sizeof(path), "%s/filters[%d]/priority", base, filter);
        if (emit_optional_u32(out, sock, "priority", path, 6)) return -1;
    }
    return 0;
}

static int write_virtual_devices(FILE *out, int sock) {
    int devices = cdb_num_instances(sock, "/fastapi:fastapi/eal/virtual_devices");
    if (devices < 0) return -1;
    if (devices == 0) return 0;
    if (fprintf(out, "  virtual_devices:\n") < 0) return -1;
    for (int i = 0; i < devices; ++i) {
        char path[PATH_BUF_SIZE], value[VALUE_BUF_SIZE];
        snprintf(path, sizeof(path), "/fastapi:fastapi/eal/virtual_devices[%d]", i);
        if (read_string(sock, value, sizeof(value), path) != 0 ||
            fprintf(out, "    - ") < 0 || yaml_string(out, value) || fputc('\n', out) == EOF) return -1;
    }
    return 0;
}

static int write_config_snapshot(int sock) {
    char temporary_path[PATH_BUF_SIZE];
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp.XXXXXX", config_path) >= (int)sizeof(temporary_path)) return -1;
    int fd = mkstemp(temporary_path);
    if (fd < 0) return -1;
    FILE *out = fdopen(fd, "w");
    if (out == NULL) { close(fd); unlink(temporary_path); return -1; }

    /* Non-ACL leaves retained from the original integration. */
    int failed = fprintf(out, "eal:\n") < 0 ||
        emit_optional_string(out, sock, "cpu_core_list", "/fastapi:fastapi/eal/cpu_core_list", 2) ||
        emit_optional_string(out, sock, "file_prefix", "/fastapi:fastapi/eal/file_prefix", 2) ||
        emit_optional_u32(out, sock, "memory_channels", "/fastapi:fastapi/eal/memory_channels", 2) ||
        emit_optional_string(out, sock, "memory_size", "/fastapi:fastapi/eal/memory_size", 2) ||
        emit_optional_bool(out, sock, "disable_hugepages", "/fastapi:fastapi/eal/disable_hugepages", 2) ||
        emit_optional_bool(out, sock, "disable_pci", "/fastapi:fastapi/eal/disable_pci", 2) ||
        emit_optional_string(out, sock, "log_level", "/fastapi:fastapi/eal/log_level", 2) ||
        write_virtual_devices(out, sock) ||
        fprintf(out, "\nport:\n") < 0 ||
        emit_optional_string(out, sock, "port_bitmask", "/fastapi:fastapi/port/port_bitmask", 2) ||
        emit_optional_u32(out, sock, "receive_queues", "/fastapi:fastapi/port/receive_queues", 2) ||
        emit_optional_u32(out, sock, "transmit_queues", "/fastapi:fastapi/port/transmit_queues", 2) ||
        emit_optional_u32(out, sock, "receive_descriptors", "/fastapi:fastapi/port/receive_descriptors", 2) ||
        emit_optional_u32(out, sock, "transmit_descriptors", "/fastapi:fastapi/port/transmit_descriptors", 2) ||
        emit_optional_bool(out, sock, "promiscuous", "/fastapi:fastapi/port/promiscuous", 2) ||
        fprintf(out, "\nmempool:\n") < 0 ||
        emit_optional_string(out, sock, "name", "/fastapi:fastapi/mempool/name", 2) ||
        emit_optional_u32(out, sock, "memory_buffer_count", "/fastapi:fastapi/mempool/memory_buffer_count", 2) ||
        emit_optional_u32(out, sock, "memory_buffer_size", "/fastapi:fastapi/mempool/memory_buffer_size", 2) ||
        emit_optional_u32(out, sock, "cache_size", "/fastapi:fastapi/mempool/cache_size", 2) ||
        fprintf(out, "\napp:\n") < 0 ||
        emit_optional_u32(out, sock, "burst_size", "/fastapi:fastapi/app/burst_size", 2) ||
        emit_optional_bool(out, sock, "mac_updating", "/fastapi:fastapi/app/mac_updating", 2) ||
        emit_optional_u32(out, sock, "timer_period_sec", "/fastapi:fastapi/app/timer_period_sec", 2) ||
        write_spi(out, sock) || write_dpi(out, sock);

    if (failed || fflush(out) != 0 || fsync(fd) != 0 || fclose(out) != 0) {
        unlink(temporary_path);
        return -1;
    }
    if (rename(temporary_path, config_path) != 0) {
        unlink(temporary_path);
        return -1;
    }
    return 0;
}

static int open_cdb_socket(enum cdb_sock_type type) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)confd_port);
    if (inet_pton(AF_INET, confd_ip, &address.sin_addr) != 1) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    if (cdb_connect(sock, type, (struct sockaddr *)&address, sizeof(address)) != CONFD_OK) {
        close(sock);
        return -1;
    }
    return sock;
}

static int process_commit(void) {
    int data_sock = open_cdb_socket(CDB_DATA_SOCKET);
    if (data_sock < 0) return -1;
    int result = -1;
    if (cdb_start_session(data_sock, CDB_RUNNING) == CONFD_OK) {
        result = write_config_snapshot(data_sock);
        cdb_end_session(data_sock);
    }
    close(data_sock);
    return result;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config_path = argv[++i];
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) dpdk_pid = (pid_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--confd-ip") == 0 && i + 1 < argc) confd_ip = argv[++i];
        else if (strcmp(argv[i], "--confd-port") == 0 && i + 1 < argc) confd_port = atoi(argv[++i]);
        else { usage(argv[0]); return 1; }
    }
    if (config_path == NULL || confd_port <= 0 || confd_port > 65535) { usage(argv[0]); return 1; }
    if (confd_init("fastapi_confd", stderr, CONFD_TRACE) != CONFD_OK) return 1;

    int subscription_sock = open_cdb_socket(CDB_SUBSCRIPTION_SOCKET);
    if (subscription_sock < 0) { fprintf(stderr, "fastapi_confd: CDB subscription connect failed\n"); return 1; }
    int subscription_point_spi, subscription_point_dpi;
    const int namespace_hash = confd_str2hash("urn:fastapi:dpdk");
    if (cdb_subscribe(subscription_sock, 30, namespace_hash, &subscription_point_spi,
                      "/fastapi:fastapi/spi") != CONFD_OK ||
        cdb_subscribe(subscription_sock, 30, namespace_hash, &subscription_point_dpi,
                      "/fastapi:fastapi/dpi") != CONFD_OK ||
        cdb_subscribe_done(subscription_sock) != CONFD_OK) {
        fprintf(stderr, "fastapi_confd: CDB subscribe failed: %s\n", confd_strerror(confd_errno));
        close(subscription_sock);
        return 1;
    }

    for (;;) {
        int points[8], point_count = 0;
        if (cdb_read_subscription_socket(subscription_sock, points, &point_count) != CONFD_OK) break;
        if (process_commit() == 0 && signal_dpdk_reload() == 0) {
            fprintf(stdout, "fastapi_confd: published CDB snapshot and requested reload\n");
        } else {
            fprintf(stderr, "fastapi_confd: commit received but snapshot/reload failed; active DPDK rules unchanged\n");
        }
        if (cdb_sync_subscription_socket(subscription_sock, CDB_DONE_PRIORITY) != CONFD_OK) break;
    }
    fprintf(stderr, "fastapi_confd: subscription loop ended: %s\n", confd_strerror(confd_errno));
    close(subscription_sock);
    return 1;
}
