/*
 * File    :    interpose.c
 * Date    :    Tue 03 Jul 2018 02:06:43 PM CEST
 *
 * Copyright (c) 2018, Ankur Sharma (ankur.sharma@bigdata.uni-saarland.de)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <execinfo.h>
#include <ucontext.h>

/*
 * generic constants
 * */
#define THRESHOLD   (1 << 13)
#define RW_SLEEPUS  (25000)
#define LOGGER_SLEEPUS (25000)

/*
 * page level ops
 * */
#define PAGESHIFT   12
#define PAGESIZE    (1 << PAGESHIFT)
#define PAGEMASK    (~(PAGESIZE - 1))
#define VADDR_ALIGNED(x) (!(x & (PAGESIZE - 1)))
#define PAGEADDR(x) ((void*)((unsigned long long)x & PAGEMASK))
#define PAGEALIGN(x) ((x + PAGESIZE) & PAGEMASK)

/*
 * MMAP related constants
 * */
#define MAP_SHARED  0x001
#define MAP_PRIVATE 0x002
#define MAP_ANON    0x020
#define PROT_NONE   0x000
#define PROT_READ   0x001
#define PROT_WRITE  0x002
#define PROT_EXEC   0x004

#define MAP_FAILED ((void*) -1)

#define MREMAP_MAYMOVE 1

static pthread_mutex_t alloclist_mutex;

/*
 * prototype typedefs of original functions
 * */
typedef void (*free_t)(void*);
typedef void* (*malloc_t)(size_t);
typedef void* (*realloc_t)(void*, size_t);
typedef int (*mprotect_t)(void*, size_t, int);
typedef void* (*memcpy_t)(void*, void*, size_t);
typedef void* (*mmap_t)(void*, size_t, int, int, int, off_t);
typedef int (*munmap_t)(void*, size_t);
typedef void* (*mremap_t)(void*, size_t, size_t, int);


static int initialized = 0;
static free_t real_free = NULL;
static mmap_t real_mmap = NULL;
static memcpy_t real_memcpy = NULL;
static munmap_t real_munmap = NULL;
static mremap_t real_mremap = NULL;
static malloc_t real_malloc = NULL;
static realloc_t real_realloc = NULL;
static mprotect_t real_mprotect = NULL;


/*
 * initialize the real functions
 * */
static void initialize_real_func()
{
    if (initialized == 0)
    {
        pthread_mutex_init(&alloclist_mutex, NULL);
        real_free = dlsym(RTLD_NEXT, "free");
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        real_memcpy = dlsym(RTLD_NEXT, "memcpy");
        real_munmap = dlsym(RTLD_NEXT, "munmap");
        real_mremap = dlsym(RTLD_NEXT, "mremap");
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_realloc = dlsym(RTLD_NEXT, "realloc");
        real_mprotect = dlsym(RTLD_NEXT, "mprotect");
        __sync_bool_compare_and_swap(&initialized, 0, 1);
    }
}

/*
 * read tsc
 * */
static inline unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

/*
 * constructor and destructor declarations
 * */
void init() __attribute__ ((constructor));
void fini() __attribute__ ((destructor));

/*
 * struct declarations
 * */
struct accesslist_t {
    void *addr;
    int type;
    unsigned long long time;
    struct accesslist_t *next;
};

struct alloclist_t {
    void *addr;
    size_t len;
    int freed;
    int invalid;
    pthread_mutex_t dealloc_mutex;
    struct alloclist_t *next;
};

/*
 * Thread declarations
 * */
static volatile int kill_rw_thread;
static volatile int kill_logger_thread;

static pthread_t rw_thread;
static pthread_t logger_thread;

static void* rw_thread_func(void*);
static void* logger_thread_func(void*);

/*
 * Allocation list
 * */
static struct alloclist_t *alloclist = NULL;
static struct accesslist_t *accesslist = NULL;

static unsigned long long append_counter = 0;

static void append_access(void *addr, int type)
{
    struct accesslist_t *node = real_malloc(sizeof(struct accesslist_t));
    node->addr = addr;
    node->type = type;
    node->time = rdtsc();
    do {
        node->next = accesslist;
    } while (!__sync_bool_compare_and_swap(&accesslist, node->next, node));
    __sync_add_and_fetch(&append_counter, 1);
}

/*
 * segfault handlers
 * */
void segfault_handler(int signum, siginfo_t* info, void *vctx)
{
    if (initialized == 0) initialize_real_func();
    void* pageaddr = PAGEADDR(info->si_addr);
#ifdef LINUX
    ucontext_t *ctx = (ucontext_t*) vctx;
    if (ctx->uc_mcontext.gregs[REG_ERR] & 0x2)
    {
        // write fault
        real_mprotect(pageaddr, PAGESIZE, PROT_WRITE);
        append_access(info->si_addr, 1);
    }
    else
    {
        // read fault
        real_mprotect(pageaddr, PAGESIZE, PROT_READ);
        append_access(info->si_addr, 0);
    }
#else
    real_mprotect(pageaddr, PAGESIZE, PROT_READ | PROT_WRITE);
    append_access(info->si_addr, 1);
#endif // LINUX
}


#define ALLOCNODE_SZ (sizeof(struct alloclist_t))

static void append_alloc(void *addr, size_t len, int inv)
{
    if (initialized == 0) initialize_real_func();
    if (len == 0) return;
    pthread_mutex_lock(&alloclist_mutex);
    struct alloclist_t* node = real_malloc(ALLOCNODE_SZ);
    node->addr = addr;
    node->invalid = inv;
    node->len = len;
    node->freed = 0;
    node->next = alloclist;
    pthread_mutex_init(&node->dealloc_mutex, NULL);
    alloclist = node;
    pthread_mutex_unlock(&alloclist_mutex);
}

static struct alloclist_t* find_alloc(void *addr)
{
    pthread_mutex_lock(&alloclist_mutex);
    struct alloclist_t *ret = NULL, *start = alloclist;
    while (start != NULL)
    {
        if (start->addr == addr) {
            ret = start;
            break;
        }
        start = start->next;
    }
    pthread_mutex_unlock(&alloclist_mutex);
    return ret;
}

/*
 * Constructor and destructor
 * */

static struct sigaction *action;
void init()
{
    // initialize the segfault handler
    if (initialized == 0) initialize_real_func();
    action = real_malloc(sizeof(struct sigaction));
    sigemptyset(&action->sa_mask);
    action->sa_flags = SA_SIGINFO;
    action->sa_sigaction = segfault_handler;
    sigaction(SIGBUS, action, NULL);
    sigaction(SIGSEGV, action, NULL);

    // if (pthread_create(&rw_thread, NULL, &rw_thread_func, NULL) != 0)
    //     fprintf(stderr, "[init] failed to create rw_thread\n");

    // if (pthread_create(&logger_thread, NULL, &logger_thread_func, NULL) != 0)
    //     fprintf(stderr, "[init] failed to create logger_thread\n");
}

void fini()
{
    struct alloclist_t *temp = alloclist;
    if (initialized == 0) initialize_real_func();

    // kill the threads
    kill_rw_thread = 1;
    kill_logger_thread = 1;
    pthread_join(rw_thread, NULL);
    pthread_join(logger_thread, NULL);

    while (alloclist != 0)
    {
        alloclist = alloclist->next;
        real_free(temp);
        temp = alloclist;
    }

    real_free(action);

    struct accesslist_t *temp_access = NULL;

    while (accesslist)
    {
        temp_access = accesslist;
        accesslist = accesslist->next;
        fprintf(stderr, "%llu %p %d\n", temp_access->time, temp_access->addr, temp_access->type);
    }

    // fprintf(stdout, "[fini] unload of interposing library ...successful\n");
    // fprintf(stdout, "[fini] access list appends=%llu\n", append_counter);
}


/*
 * Interposing functions
 * */
void free(void* addr)
{
    if (initialized == 0) initialize_real_func();
    struct alloclist_t *elem = find_alloc(addr);
    if (elem != NULL)
    {
        pthread_mutex_lock(&elem->dealloc_mutex);
        elem->freed = 1;
        if (elem->invalid)
            real_free(elem->addr);
        else
            real_munmap(elem->addr, elem->len);
        pthread_mutex_unlock(&elem->dealloc_mutex);
    }
    else
    {
        real_free(addr);
    }
}

void *malloc(size_t sz)
{
    if (initialized == 0) initialize_real_func();
    if (sz < THRESHOLD) {
        return real_malloc(sz);
    }
    else
    {
        // page align sz and use mmap to allocate the memory
        size_t new_sz = sz;
        if (sz & (PAGESIZE - 1))
            new_sz = PAGEALIGN(new_sz);
        void *ret = real_mmap(NULL, new_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (ret == MAP_FAILED)
        {
            perror("mmap failed");
            ret = real_malloc(sz);
            append_alloc(ret, new_sz, 1);
        }
        else
        {
            append_alloc(ret, new_sz, 0);
        }
        return ret;
    }

}

void *realloc(void* addr, size_t sz)
{
    if (initialized == 0) initialize_real_func();

    size_t org_sz = sz;
    struct alloclist_t *elem = find_alloc(addr);


    if (elem != NULL)
    {
        // existing allocation is modified
        // could also consider the case where sz > pagesize, just using mremap
        if (sz < THRESHOLD || elem->invalid == 1)
        {
            // existing area is shrinked
            // use malloc + memcpy + munmap
            void *ret = real_malloc(sz);
            real_memcpy(ret, addr, sz);
            pthread_mutex_lock(&elem->dealloc_mutex);
            elem->freed = 1;
            real_munmap(elem->addr, elem->len);
            pthread_mutex_unlock(&elem->dealloc_mutex);
            return ret;
        }
        else {
            // use mremap
            if (sz & (PAGESIZE - 1))
                sz = PAGEALIGN(sz);
            pthread_mutex_lock(&elem->dealloc_mutex);
            real_mprotect(addr, elem->len, PROT_READ | PROT_WRITE);
            void *ret = real_mremap(addr, elem->len, sz, MREMAP_MAYMOVE);
            if (ret == MAP_FAILED)
                perror("mremap failed");
            org_sz = elem->len;
            elem->addr = ret;
            elem->len = sz;
            pthread_mutex_unlock(&elem->dealloc_mutex);
            return ret;
        }
    }
    else
    {
        // previous allocation was smaller than threshold
        if (sz < THRESHOLD || addr == MAP_FAILED)
        {
            // use realloc
            void *ret = real_realloc(addr, sz);
            return ret;
        }
        else
        {
            // page align sz and use realloc + mmap + memcpy
            // this is the worst case
            // we do not know the size of previos allocation
            // so we realloc to get the size and page alogn it if
            // necessary using mmap + memcpy

            if (sz & (PAGESIZE - 1))
                sz = PAGEALIGN(sz);

            void *realloc_ret = real_realloc(addr, sz);
                // worst case
            void *ret = real_mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (ret == MAP_FAILED)
            {
                append_alloc(realloc_ret, sz, 1);
                return realloc_ret;
            }

            real_memcpy(ret, realloc_ret, sz);
            append_alloc(ret, sz, 0);
            real_free(realloc_ret);
            return ret;
        }
    }
}

void* mmap(void* addr, size_t sz, int pflags, int mflags, int fd, off_t off)
{
    if (initialized == 0) initialize_real_func();
    void *ret = real_mmap(addr, sz, pflags, mflags, fd, off);

    if (sz < THRESHOLD) return ret;

    if (ret != MAP_FAILED)
        append_alloc(ret, sz, 0);
    return ret;
}

int munmap(void* addr, size_t sz)
{
    if (addr == MAP_FAILED) return -1;
    if (initialized == 0) initialize_real_func();

    int ret = 0;
    struct alloclist_t *elem = find_alloc(addr);

    if (elem != NULL)
    {
        pthread_mutex_lock(&elem->dealloc_mutex);
        elem->freed = 1;
        ret = real_munmap(elem->addr, elem->len);
        pthread_mutex_unlock(&elem->dealloc_mutex);
        return ret;
    }

    return real_munmap(addr, sz);
}

void* mremap(void* addr, size_t old_sz, size_t new_sz, int flags)
{
    if (initialized == 0) initialize_real_func();
    void *ret = real_mremap(addr, old_sz, new_sz, flags);

    if (ret == MAP_FAILED) return ret;

    if (old_sz < THRESHOLD)
    {
        if (new_sz >= THRESHOLD)
        {
            // Add an entry to allocation list for monitoring
            append_alloc(ret, new_sz, 0);
        }
    }
    else
    {
        struct alloclist_t *elem = find_alloc(addr);
        if (new_sz < THRESHOLD)
        {
            if (elem != NULL)
            {
                pthread_mutex_lock(&elem->dealloc_mutex);
                elem->freed = 1;
                // no need to munmap
                pthread_mutex_unlock(&elem->dealloc_mutex);
            }
        }
        else
        {
            if (elem != NULL)
            {
                pthread_mutex_lock(&elem->dealloc_mutex);
                elem->addr = ret;
                elem->len = new_sz;
                pthread_mutex_unlock(&elem->dealloc_mutex);
            }
        }
    }
    return ret;
}

/*
 * Threads
 * */
void *rw_thread_func(void* arg)
{
    if (initialized == 0) initialize_real_func();
    while (kill_rw_thread == 0)
    {
        pthread_mutex_lock(&alloclist_mutex);
        struct alloclist_t *listhead = alloclist, *next, *liststart;

        while (listhead && listhead->freed)
        {
            next = listhead->next;
            real_free(listhead);
            listhead = next;
        }

        liststart = listhead;
        alloclist = listhead;

        while (listhead)
        {
            next = listhead->next;
            if (next && next->freed)
            {
                __sync_bool_compare_and_swap(&listhead->next, next, next->next);
                real_free(next);
            }
            listhead = listhead->next;
        }

        pthread_mutex_unlock(&alloclist_mutex);

        // mark all page aligned allocations to no access
        while (liststart)
        {
            if (liststart->freed == 0)
            {
                pthread_mutex_lock(&liststart->dealloc_mutex);
                if (liststart->freed == 0 && liststart->invalid == 0)
                {
                    real_mprotect(liststart->addr, liststart->len, PROT_NONE);
                }
                pthread_mutex_unlock(&liststart->dealloc_mutex);
            }
            liststart = liststart->next;
        }
        usleep(RW_SLEEPUS);
    }
}

void *logger_thread_func(void* arg)
{
    if (initialized == 0) initialize_real_func();
    while (kill_logger_thread == 0)
    {
        usleep(LOGGER_SLEEPUS);
        struct accesslist_t *pos = __atomic_load_n(&accesslist, __ATOMIC_SEQ_CST);
        struct accesslist_t *next = NULL;

        if (pos != NULL)
        {
            next = pos->next;
            pos->next = NULL;
        }

        while (next != NULL)
        {
            pos = next;
            next = next->next;
            fprintf(stderr, "%llu %p %d\n", pos->time, pos->addr, pos->type);
            real_free(pos);
        }
    }
}
