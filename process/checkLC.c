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
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <dirent.h>

#define TRUSTED_CSV      "trusted.csv"
#define ALERT_DIR        "Txt-ListaConfianza"
#define CLEANUP_INTERVAL 180  // segundos

//
// Estructuras para la lista de confiables y la de no confiables
//
typedef struct StrNode {
    char *s;
    struct StrNode *next;
} StrNode;

typedef struct UnNode {
    pid_t pid;
    char comm[256];
    struct UnNode *next;
} UnNode;

//
// Procesos típicos que no queremos alertar
//
static const char *ignored_processes[] = {
    "bash","sh","sleep","ps","cat","sed","grep","awk","which",
    "cut","tail","head","sort","uniq","tr","tee","echo","chmod",
    "ls","mkdir","rm","mv","cp","du","df","mount","umount",
    "kill","top","less","more","env","clear","true","false",
    "systemd","init","dbus-daemon","systemd-journald","systemd-logind",
    "NetworkManager","polkitd","accounts-daemon","udisksd","gvfsd",
    "pulseaudio","snapd","snap-store","gnome-shell","gnome-session",
    "gdm-session-worker","Xorg","Xwayland","display-manager",
    "apt","apt-get","apt-key","apt-config","apt-daily","apt-daily-upgrade",
    "dpkg","dpkg-query","lsb_release","ufw","snapd.refresh.service",
    "gpg","gpgv","gpgconf","gpg-connect-agent",
    "nautilus","gnome-terminal-server","gnome-control-center",
    "gnome-software","totem","rhythmbox",
    "firefox","chrome","chromium-browser",
    "gedit","code","vim","nano",
    "udisksd","tracker-miner-f",
    "motd-news","update-motd-upd",
    "python3","perl","ruby",
    "mktemp","readlink","touch","find","dirname","xdelta3",
    "cpuUsage.sh","testapp.sh",
    "systemd-hostnam","libreoffice","soffice.bin","oosplash",
    "basename","uname","paperconf",
    NULL
};

static StrNode *trusted   = NULL;
static UnNode  *untrusted = NULL;

//
// Carga la lista de confianza desde TRUSTED_CSV
//
static StrNode* load_trusted(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen trusted"); return NULL; }
    char line[512];
    if (!fgets(line, sizeof line, f)) { fclose(f); return NULL; } // cabezera
    StrNode *head = NULL;
    while (fgets(line, sizeof line, f)) {
        char *p = strchr(line, ',');
        if (!p) continue;
        p++;
        char *q = strchr(p, ',');
        if (q) *q = '\0';
        while (*p == ' ') p++;
        if (*p) {
            StrNode *n = malloc(sizeof *n);
            n->s = strdup(p);
            n->next = head;
            head = n;
        }
    }
    fclose(f);
    return head;
}

static int in_trusted(const char *s) {
    for (StrNode *c = trusted; c; c = c->next)
        if (strcmp(c->s, s) == 0) return 1;
    return 0;
}

static int is_ignored(const char *comm) {
    for (int i = 0; ignored_processes[i]; i++)
        if (strcmp(comm, ignored_processes[i]) == 0) return 1;
    return 0;
}

//
// Añade un proceso no confiable a la lista
//
static void add_untrusted(pid_t pid, const char *comm) {
    UnNode *n = malloc(sizeof *n);
    n->pid = pid;
    strncpy(n->comm, comm, sizeof n->comm - 1);
    n->comm[sizeof n->comm - 1] = '\0';
    n->next = untrusted;
    untrusted = n;
}

//
// Elimina un PID de la lista de no confiables
//
static void remove_untrusted(pid_t pid) {
    UnNode **p = &untrusted;
    while (*p) {
        if ((*p)->pid == pid) {
            UnNode *t = *p;
            *p = (*p)->next;
            free(t);
            return;
        }
        p = &(*p)->next;
    }
}

//
// Vuelca el contenido completo de `untrusted` en un nuevo TXT
//
static void dump_untrusted_to_file(void) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char filename[PATH_MAX];
    strftime(filename, sizeof filename,
             ALERT_DIR "/alert_%Y%m%d_%H%M%S.txt", tm);
    FILE *out = fopen(filename, "w");
    if (!out) { perror("fopen dump"); return; }
    for (UnNode *u = untrusted; u; u = u->next) {
        fprintf(out, "[ALERTA] PID %d, ejecutable '%s'\n",
                u->pid, u->comm);
    }
    fclose(out);
}

//
// Abre NETLINK_CONNECTOR para recibir eventos de proceso
//
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
        .cn = { .id = { .idx = CN_IDX_PROC, .val = CN_VAL_PROC },
                .len = sizeof(enum proc_cn_mcast_op) },
        .op = PROC_CN_MCAST_LISTEN
    };
    if (send(sock, &msg, sizeof(msg), 0) < 0) {
        perror("send"); close(sock); return -1;
    }
    return sock;
}

//
// Maneja PROC_EVENT_EXEC
//
static void handle_exec(pid_t pid) {
    char path[64], comm[256];
    snprintf(path, sizeof path, "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(comm, sizeof comm, f)) {
        comm[strcspn(comm, "\n")] = 0;
        if (!in_trusted(comm) && !is_ignored(comm)) {
            add_untrusted(pid, comm);
            dump_untrusted_to_file();
        }
    }
    fclose(f);
}

//
// Maneja PROC_EVENT_EXIT
//
static void handle_exit(pid_t pid) {
    UnNode *it = untrusted;
    while (it) {
        if (it->pid == pid) {
            remove_untrusted(pid);
            dump_untrusted_to_file();
            return;
        }
        it = it->next;
    }
}

//
// Hilo que cada CLEANUP_INTERVAL s borra el fichero más antiguo
//
static void *cleanup_thread(void *arg) {
    (void)arg;
    while (1) {
        sleep(CLEANUP_INTERVAL);
        DIR *d = opendir(ALERT_DIR);
        if (!d) continue;
        struct dirent *ent;
        char oldest[PATH_MAX] = {0};
        time_t oldest_t = time(NULL);
        int found = 0;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_type != DT_REG) continue;
            if (strncmp(ent->d_name, "alert_", 6)) continue;
            char full[PATH_MAX];
            snprintf(full, sizeof full, ALERT_DIR "/%s", ent->d_name);
            struct stat st;
            if (stat(full, &st) == 0) {
                if (!found || st.st_mtime < oldest_t) {
                    oldest_t = st.st_mtime;
                    strcpy(oldest, full);
                    found = 1;
                }
            }
        }
        closedir(d);
        if (found) unlink(oldest);
    }
    return NULL;
}

int main(void) {
    // 1) Crear carpeta de alertas si no existe
    struct stat st;
    if (stat(ALERT_DIR, &st) < 0) {
        if (errno == ENOENT) {
            if (mkdir(ALERT_DIR, 0755) < 0) {
                perror("mkdir");
                exit(1);
            }
        } else {
            perror("stat");
            exit(1);
        }
    } else if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s existe y no es directorio\n", ALERT_DIR);
        exit(1);
    }

    // 2) Cargar lista de confianza
    trusted = load_trusted(TRUSTED_CSV);
    if (!trusted) exit(1);

    // 3) Abrir NETLINK para recibir eventos
    int nl = open_proc_connector();
    if (nl < 0) exit(1);

    // 4) Lanzar hilo de limpieza
    pthread_t tid;
    if (pthread_create(&tid, NULL, cleanup_thread, NULL) != 0) {
        perror("pthread_create");
    }

    // 5) Bucle principal de eventos
    char buf[1024];
    while (1) {
        int len = recv(nl, buf, sizeof buf, 0);
        if (len <= 0) continue;
        struct nlmsghdr   *nlh = (struct nlmsghdr*)buf;
        struct cn_msg     *cn  = NLMSG_DATA(nlh);
        struct proc_event *ev  = (struct proc_event*)cn->data;
        if (ev->what == PROC_EVENT_EXEC) {
            handle_exec(ev->event_data.exec.process_pid);
        } else if (ev->what == PROC_EVENT_EXIT) {
            handle_exit(ev->event_data.exit.process_pid);
        }
    }

    // nunca llega aquí
    return 0;
}
