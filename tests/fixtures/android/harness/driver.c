/*
 * Stands in for the app process: dlopen()s the engine library so the agent's do_dlopen hook has
 * to catch it being mapped, exactly as it would in a real game, then calls into it.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *lib = argc > 1 ? argv[1] : "libcocos2dlua.so";
    int delay = argc > 2 ? atoi(argv[2]) : 0;

    if (delay > 0) {
        printf("[driver] waiting %ds before dlopen (attach window)\n", delay);
        fflush(stdout);
        sleep(delay);
    }

    printf("[driver] dlopen(%s)\n", lib);
    fflush(stdout);
    void *h = dlopen(lib, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "[driver] dlopen failed: %s\n", dlerror());
        return 2;
    }

    int (*run)(void *) = (int (*)(void *))dlsym(h, "cocos_run_scripts");
    if (!run) {
        fprintf(stderr, "[driver] dlsym failed: %s\n", dlerror());
        return 3;
    }

    /* The engine uses this to find which vtable slot the key setter occupies. It resolves only
       in the default-visibility builds, which is the point: a hidden one has nothing to look up. */
    void *setter = dlsym(h, "_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i");

    int rc = run(setter);
    printf("[driver] cocos_run_scripts -> %d\n", rc);
    fflush(stdout);

    /* A real game keeps running for minutes after its scripts load. Staying alive gives the
       agent's 30s module-polling fallback the same chance it would have in a real game. */
    int linger = argc > 3 ? atoi(argv[3]) : 0;
    if (linger > 0) {
        printf("[driver] lingering %ds\n", linger);
        fflush(stdout);
        sleep(linger);
    }
    return rc;
}
