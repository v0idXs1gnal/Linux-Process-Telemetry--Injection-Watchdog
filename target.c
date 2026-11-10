#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    size_t page_size = 4096;

    // Deliberately violates W^X policy by allocating an unbacked anonymous page 
    // with simultaneous write and execute permissions to simulate shellcode staging.
    void *rogue_mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (rogue_mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("[+] Target running. PID: %d\n", getpid());
    printf("[+] Rogue RWX page mapped at: %p\n", rogue_mem);
    printf("[*] Check /proc/%d/maps or run your scanner against this PID.\n", getpid());
    printf("[*] Press Enter to exit...\n");

    getchar();

    munmap(rogue_mem, page_size);
    return 0;
}