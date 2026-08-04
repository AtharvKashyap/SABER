/* docker/lab/vulnbin/vuln.c
 * Intentionally vulnerable demo binary for the SABER lab. NOT for production.
 * Classic unbounded stack overflow; reads the flag file on request.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void print_flag(void) {
    FILE *f = fopen("/flag.txt", "r");
    char buf[128];
    if (!f) { puts("no flag"); return; }
    while (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
    fclose(f);
}

int main(void) {
    char name[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("vulnbin: enter your name:");
    read(0, name, 512);         /* overflow: reads far more than sizeof(name) */
    printf("hello, %s\n", name);
    if (strcmp(name, "sesame") == 0) print_flag();
    return 0;
}
