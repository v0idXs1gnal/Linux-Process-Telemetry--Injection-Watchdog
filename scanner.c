#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 512

static void scan_maps(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[-] Error opening %s: %s\n", path, strerror(errno));
        return;
    }

    char line[BUFFER_SIZE];
    unsigned long start = 0, end = 0, offset = 0, inode = 0;
    char perms[5] = {0};
    unsigned int dev_major = 0, dev_minor = 0;
    char pathname[BUFFER_SIZE] = "";
    int violations = 0;

    printf("[*] Inspecting virtual memory layout for PID: %d\n", pid);

    while (fgets(line, sizeof(line), fp)) {
        pathname[0] = '\0';

        // Map addresses are hexadecimal; %lx stores them in unsigned long, which 
        // accommodates the full virtual-address width on 64-bit Linux.
        int fields = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %511s", &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, pathname);

        // The pathname is optional and is often absent for anonymous mappings.
        // Require only the address range and permissions to recognize a map line.
        if (fields < 3) {
            continue;
        }

        // Permissions are ordered read, write, execute; [1] is write and [2] is execute.
        if (perms[1] == 'w' && perms[2] == 'x') {
            violations++;
            printf("\n[!] SUSPICIOUS VMA DETECTED\n");
            printf("    Range:       0x%012lx - 0x%012lx\n", start, end);
            printf("    Size:        %lu KB\n", (end - start) / 1024);
            printf("    Perms:       %s\n", perms);
            printf("    Backing:     %s\n", (pathname[0] != '\0') ? pathname : "[anonymous / unbacked]");
        }
    }

    fclose(fp);

    if (violations == 0) {
        printf("[+] Scan finished: No W^X violations found.\n");
    } else {
        printf("\n[-] Scan finished: %d violation(s) flagged.\n", violations);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "[-] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    scan_maps(pid);
    return 0;
}