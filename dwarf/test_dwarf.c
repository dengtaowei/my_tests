#include <stdio.h>
#include <stdlib.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>

void resolve_function_with_line(pid_t pid, unsigned long ip) {
    Dwfl_Callbacks callbacks = {
        .find_elf = dwfl_linux_proc_find_elf,
        .find_debuginfo = dwfl_standard_find_debuginfo,
        .section_address = dwfl_offline_section_address,
    };

    Dwfl *dwfl = dwfl_begin(&callbacks);
    if (!dwfl) {
        fprintf(stderr, "dwfl_begin failed: %s\n", dwfl_errmsg(-1));
        return;
    }

    if (dwfl_linux_proc_report(dwfl, pid) < 0) {
        fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", dwfl_errmsg(-1));
        goto out;
    }

    Dwfl_Module *mod = dwfl_addrmodule(dwfl, ip);
    if (!mod) {
        fprintf(stderr, "No module contains address 0x%lx\n", ip);
        goto out;
    }

    const char *name = dwfl_module_addrname(mod, ip);
    if (!name) name = "[Unknown]";

    Dwarf_Addr bias;
    Dwarf_Die *cudie = dwfl_module_addrdie(mod, ip, &bias);
    if (cudie) {
        Dwarf_Line *line = dwarf_getsrc_die(cudie, ip - bias);
        if (line) {
            const char *src_file = dwarf_linesrc(line, NULL, NULL);
            int line_num;
            if (dwarf_lineno(line, &line_num) == 0) {
                printf("IP 0x%lx -> Function: %s (File: %s, Line: %d)\n", ip, name, src_file, line_num);
            } else {
                printf("IP 0x%lx -> Function: %s (File: %s, Line: Unknown)\n", ip, name, src_file);
            }
        } else {
            printf("IP 0x%lx -> Function: %s (Line: No debug info)\n", ip, name);
        }
    } else {
        printf("IP 0x%lx -> Function: %s (No DWARF info)\n", ip, name);
    }
out:
    if (dwfl) dwfl_end(dwfl);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <PID> <IP-in-hex>\n", argv[0]);
        return 1;
    }
    resolve_function_with_line(atoi(argv[1]), strtoul(argv[2], NULL, 16));
    return 0;
}