/*
 * slirp-pipe: one phone's network, libslirp on stdin and stdout.
 *
 * Every frame either way is an Ethernet frame preceded by its length, two
 * bytes big-endian. The network is QEMU's -netdev user: the phone is
 * 10.0.2.15, the gateway 10.0.2.2, DNS 10.0.2.3. The gateway does not reach
 * the host's loopback unless SLIRP_HOST_LOOPBACK=1 (for tests). Exits when
 * stdin closes. It may not fork, gain privileges or dump core, and has
 * SOCKETS_MAX connections at once.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <slirp/libslirp.h>

#define FRAME_MAX 1514
#define POLL_MAX 1024
#define SOCKETS_MAX 64

struct timer {
    SlirpTimerId id;
    void *cb_opaque;
    int64_t expire_ms;
    bool armed;
    struct timer *next;
};

static Slirp *slirp;
static struct timer *timers;
static struct pollfd fds[POLL_MAX];
static int nfds;

static int64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void write_all(const uint8_t *buf, size_t len)
{
    while (len) {
        ssize_t n = write(STDOUT_FILENO, buf, len);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            exit(0);
        }
        buf += n;
        len -= n;
    }
}

static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    uint8_t head[2] = { len >> 8, len & 0xff };

    if (len > FRAME_MAX) {
        return len;
    }
    write_all(head, sizeof(head));
    write_all(buf, len);
    return len;
}

static void guest_error(const char *msg, void *opaque)
{
    fprintf(stderr, "slirp-pipe: %s\n", msg);
}

static int64_t clock_get_ns(void *opaque)
{
    return now_ns();
}

static void *timer_new_opaque(SlirpTimerId id, void *cb_opaque, void *opaque)
{
    struct timer *t = calloc(1, sizeof(*t));

    t->id = id;
    t->cb_opaque = cb_opaque;
    t->next = timers;
    timers = t;
    return t;
}

static void timer_free(void *timer, void *opaque)
{
    for (struct timer **p = &timers; *p; p = &(*p)->next) {
        if (*p == timer) {
            *p = (*p)->next;
            free(timer);
            return;
        }
    }
}

static void timer_mod(void *timer, int64_t expire_ms, void *opaque)
{
    struct timer *t = timer;

    t->expire_ms = expire_ms;
    t->armed = true;
}

static void register_poll_fd(int fd, void *opaque)
{
}

static void unregister_poll_fd(int fd, void *opaque)
{
}

static void notify(void *opaque)
{
}

static int add_poll(slirp_os_socket fd, int events, void *opaque)
{
    struct pollfd *p;

    if (nfds == POLL_MAX) {
        return -1;
    }
    p = &fds[nfds];
    p->fd = fd;
    p->events = (events & SLIRP_POLL_IN ? POLLIN : 0) |
                (events & SLIRP_POLL_OUT ? POLLOUT : 0) |
                (events & SLIRP_POLL_PRI ? POLLPRI : 0);
    p->revents = 0;
    return nfds++;
}

static int get_revents(int idx, void *opaque)
{
    short r;

    if (idx < 0 || idx >= nfds) {
        return 0;
    }
    r = fds[idx].revents;
    return (r & POLLIN ? SLIRP_POLL_IN : 0) | (r & POLLOUT ? SLIRP_POLL_OUT : 0) |
           (r & POLLPRI ? SLIRP_POLL_PRI : 0) | (r & POLLERR ? SLIRP_POLL_ERR : 0) |
           (r & POLLHUP ? SLIRP_POLL_HUP : 0);
}

static const SlirpCb callbacks = {
    .send_packet = send_packet,
    .guest_error = guest_error,
    .clock_get_ns = clock_get_ns,
    .timer_free = timer_free,
    .timer_mod = timer_mod,
    .register_poll_fd = register_poll_fd,
    .unregister_poll_fd = unregister_poll_fd,
    .notify = notify,
    .timer_new_opaque = timer_new_opaque,
};

/* the frames read so far from stdin: whole ones go to slirp */
static uint8_t in[2 * (FRAME_MAX + 2)];
static size_t in_len;

static void read_stdin(void)
{
    ssize_t n = read(STDIN_FILENO, in + in_len, sizeof(in) - in_len);
    size_t at = 0;

    if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
        return;
    }
    if (n <= 0) {
        exit(0);
    }
    in_len += n;
    while (in_len - at >= 2) {
        size_t len = (in[at] << 8) | in[at + 1];

        if (len > FRAME_MAX) {
            fprintf(stderr, "slirp-pipe: frame of %zu bytes\n", len);
            exit(1);
        }
        if (in_len - at < 2 + len) {
            break;
        }
        slirp_input(slirp, in + at + 2, len);
        at += 2 + len;
    }
    memmove(in, in + at, in_len - at);
    in_len -= at;
}

static void limit(int resource, rlim_t value)
{
    struct rlimit r = { value, value };

    if (setrlimit(resource, &r)) {
        perror("slirp-pipe: setrlimit");
        exit(1);
    }
}

int main(void)
{
    SlirpConfig cfg = {
        .version = 4,
        .in_enabled = true,
        .if_mtu = 1500,
        .if_mru = 1500,
        .disable_host_loopback = !(getenv("SLIRP_HOST_LOOPBACK") &&
                                   !strcmp(getenv("SLIRP_HOST_LOOPBACK"), "1")),
    };

    /* stdin, stdout and stderr are three of the descriptors */
    limit(RLIMIT_NOFILE, SOCKETS_MAX + 3);
    limit(RLIMIT_NPROC, 0);
    limit(RLIMIT_CORE, 0);
    limit(RLIMIT_AS, 256 << 20);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("slirp-pipe: no_new_privs");
        exit(1);
    }

    inet_pton(AF_INET, "10.0.2.0", &cfg.vnetwork);
    inet_pton(AF_INET, "255.255.255.0", &cfg.vnetmask);
    inet_pton(AF_INET, "10.0.2.2", &cfg.vhost);
    inet_pton(AF_INET, "10.0.2.15", &cfg.vdhcp_start);
    inet_pton(AF_INET, "10.0.2.3", &cfg.vnameserver);
    slirp = slirp_new(&cfg, &callbacks, NULL);
    fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);

    for (;;) {
        uint32_t timeout = 1000;
        int64_t now_ms = now_ns() / 1000000;
        int ret;

        for (struct timer *t = timers; t; t = t->next) {
            if (t->armed) {
                int64_t wait = t->expire_ms - now_ms;

                timeout = wait <= 0 ? 0 : (wait < timeout ? wait : timeout);
            }
        }
        nfds = 0;
        add_poll(STDIN_FILENO, SLIRP_POLL_IN, NULL);
        slirp_pollfds_fill_socket(slirp, &timeout, add_poll, NULL);
        ret = poll(fds, nfds, timeout);
        slirp_pollfds_poll(slirp, ret < 0, get_revents, NULL);
        if (ret > 0 && fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            read_stdin();
        }

        /* a timer callback may free timers: start over after each */
        now_ms = now_ns() / 1000000;
        for (bool fired = true; fired;) {
            fired = false;
            for (struct timer *t = timers; t; t = t->next) {
                if (t->armed && t->expire_ms <= now_ms) {
                    t->armed = false;
                    slirp_handle_timer(slirp, t->id, t->cb_opaque);
                    fired = true;
                    break;
                }
            }
        }
    }
}
