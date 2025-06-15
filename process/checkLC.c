// monitor_untrusted_nl.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>

#define TRUSTED_CSV "trusted.csv"

// Lista simplemente enlazada de nombres de ejecutable confiables
typedef struct StrNode {
    char *s;
    struct StrNode *next;
} StrNode;

// Lista de procesos típicos del sistema y aplicaciones comunes que queremos ignorar
const char *ignored_processes[] = {
    "bash", "sh", "sleep", "ps", "cat", "sed", "grep", "awk", "which",
    "cut", "tail", "head", "sort", "uniq", "tr", "tee", "echo", "chmod",
    "ls", "mkdir", "rm", "mv", "cp", "du", "df", "mount", "umount",
    "kill", "top", "less", "more", "env", "clear", "true", "false",
    "systemd", "init", "dbus-daemon", "systemd-journald", "systemd-logind",
    "NetworkManager", "polkitd", "accounts-daemon", "udisksd", "gvfsd",
    "pulseaudio", "snapd", "snap-store", "gnome-shell", "gnome-session",
    "gdm-session-worker", "Xorg", "Xwayland", "display-manager",
    "apt", "apt-get", "apt-key", "apt-config", "apt-daily", "apt-daily-upgrade",
    "dpkg", "dpkg-query", "lsb_release", "ufw", "snapd.refresh.service",
    "gpg", "gpgv", "gpgconf", "gpg-connect-agent",
    "nautilus", "gnome-terminal-server", "gnome-control-center",
    "gnome-software", "totem", "rhythmbox",
    "firefox", "chrome", "chromium-browser",
    "gedit", "code", "vim", "nano",
    "udisksd", "tracker-miner-f",
    "motd-news", "update-motd-upd",
    "python3", "perl", "ruby",
    "mktemp", "readlink", "touch", "find", "dirname", "xdelta3",
    "cpuUsage.sh", "testapp.sh",
    "systemd-hostnam", "libreoffice", "soffice.bin", "oosplash",
    "basename", "uname", "paperconf",
    NULL
};

// Verifica si el ejecutable está en la lista de ignorados
int is_ignored(const char *comm) {
    for (int i = 0; ignored_processes[i]; i++) {
        if (strcmp(comm, ignored_processes[i]) == 0)
            return 1;
    }
    return 0;
}

// Carga del CSV: solo extrae la columna `package`
static StrNode* load_trusted(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen"); return NULL; }
    char line[512];
    // Saltar encabezado
    if (!fgets(line, sizeof line, f)) { fclose(f); return NULL; }
    StrNode *head = NULL;
    while (fgets(line, sizeof line, f)) {
        char *p = strchr(line, ',');
        if (!p) continue;
        char *pkg = p + 1;
        char *q = strchr(pkg, ',');
        if (q) *q = '\0';
        while (*pkg == ' ') pkg++;
        if (*pkg) {
            StrNode *n = malloc(sizeof *n);
            n->s = strdup(pkg);
            n->next = head;
            head = n;
        }
    }
    fclose(f);
    return head;
}

// Comprueba existencia en lista de confianza
static int in_trusted(StrNode *h, const char *s) {
    for (; h; h = h->next) {
        if (strcmp(h->s, s) == 0)
            return 1;
    }
    return 0;
}

// Limpia la lista
static void free_trusted(StrNode *h) {
    while (h) {
        StrNode *t = h->next;
        free(h->s);
        free(h);
        h = t;
    }
}

// Abre socket NETLINK_CONNECTOR y se suscribe a eventos de proceso
static int open_proc_connector(void) {
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (sock < 0) { perror("socket"); return -1; }
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid    = getpid()
    };
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(sock); return -1;
    }
    struct {
        struct nlmsghdr nl;
        struct cn_msg   cn;
        enum proc_cn_mcast_op op;
    } msg = {
        .nl = { .nlmsg_len = sizeof(msg), .nlmsg_type = NLMSG_DONE },
        .cn = { .id = { .idx = CN_IDX_PROC, .val = CN_VAL_PROC }, .len = sizeof(enum proc_cn_mcast_op) },
        .op = PROC_CN_MCAST_LISTEN
    };
    if (send(sock, &msg, sizeof(msg), 0) < 0) {
        perror("send"); close(sock); return -1;
    }
    return sock;
}

// Al recibir un evento PROC_EVENT_EXEC, maneja el PID
static void handle_exec(StrNode *trusted, pid_t pid) {
    char path[64], comm[256];
    snprintf(path, sizeof path, "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(comm, sizeof comm, f)) {
        comm[strcspn(comm, "\n")] = 0;
        if (!in_trusted(trusted, comm) && !is_ignored(comm)) {
            printf("[ALERTA] Proceso no confiable: PID %d, ejecutable '%s'\n", pid, comm);
        }
    }
    fclose(f);
}

int main(void) {
    // 1) Carga la lista de confianza
    StrNode *trusted = load_trusted(TRUSTED_CSV);
    if (!trusted) return EXIT_FAILURE;

    // 2) Abre el conector de procesos
    int nl = open_proc_connector();
    if (nl < 0) {
        free_trusted(trusted);
        return EXIT_FAILURE;
    }

    // 3) Bucle de recepción de eventos
    char buf[1024];
    while (1) {
        int len = recv(nl, buf, sizeof buf, 0);
        if (len <= 0) continue;
        struct nlmsghdr *nlh = (struct nlmsghdr*)buf;
        struct cn_msg   *cn  = NLMSG_DATA(nlh);
        struct proc_event *ev = (struct proc_event*)cn->data;
        if (ev->what == PROC_EVENT_EXEC) {
            handle_exec(trusted, ev->event_data.exec.process_pid);
        }
    }

    // Cleanup (no se alcanza normalmente)
    close(nl);
    free_trusted(trusted);
    return EXIT_SUCCESS;
}
