// mh-timer.h///////////////////////// 锁未完善，另一个线程删除定时器的时候如果定时器已经执行了，te 被释放了会有问题//////////////////////////////////////////////////////////////////
#ifndef _MINHEAP_TIMER_H
#define _MINHEAP_TIMER_H

#if defined(__APPLE__)
#include <AvailabilityMacros.h>
#include <sys/time.h>
#include <mach/task.h>
#include <mach/mach.h>
#else
#include <time.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "minheap.h"

static uint64_t
current_time()
{
    uint64_t t;
#if !defined(__APPLE__) || defined(AVAILABLE_MAC_OS_X_VERSION_10_12_AND_LATER)
    struct timespec ti;
    clock_gettime(CLOCK_MONOTONIC, &ti);
    t = (uint64_t)ti.tv_sec * 1000;
    t += ti.tv_nsec / 1000000;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t = (uint64_t)tv.tv_sec * 1000;
    t += tv.tv_usec / 1000;
#endif
    return t;
}

void init_timer(min_heap_t *min_heap)
{
    min_heap_create(min_heap);
    pthread_mutex_init(&min_heap->mtx, NULL);
}

timer_entry_t *add_timer(min_heap_t *min_heap, uint32_t msec, timer_handler_pt callback, void *privdata)
{
    timer_entry_t *te = (timer_entry_t *)malloc(sizeof(*te));
    if (!te)
    {
        return NULL;
    }
    min_heap_elem_init(te);
    te->handler = callback;
    te->time = current_time() + msec;
    te->interval = msec;
    te->privdata = privdata;
    te->heap = min_heap;

    pthread_mutex_lock(&min_heap->mtx);
    if (0 != min_heap_push(min_heap, te))
    {
        pthread_mutex_unlock(&min_heap->mtx);
        free(te);
        return NULL;
    }
    pthread_mutex_unlock(&min_heap->mtx);
    printf("[add timer] %p, time = %llu now = %llu\n", te, te->time, current_time());
    return te;
}

int del_timer(min_heap_t *min_heap, timer_entry_t *elem)
{
    int ret = 0;
    pthread_mutex_lock(&min_heap->mtx);
    ret = min_heap_delete(min_heap, elem);
    pthread_mutex_unlock(&min_heap->mtx);
    
    return ret;
}

int find_nearest_expire_timer(min_heap_t *min_heap)
{
    pthread_mutex_lock(&min_heap->mtx);
    timer_entry_t *te = min_heap_top(min_heap);
    if (!te)
    {
        pthread_mutex_unlock(&min_heap->mtx);
        return -1;
    }
    int diff = (int)(te->time - current_time());
    pthread_mutex_unlock(&min_heap->mtx);
    return diff > 0 ? diff : 0;
}

void expire_timer(min_heap_t *min_heap)
{
    uint64_t cur = current_time();
    for (;;)
    {
        pthread_mutex_lock(&min_heap->mtx);
        timer_entry_t *te = min_heap_top(min_heap);
        if (!te)
        {
            pthread_mutex_unlock(&min_heap->mtx);
            break;
        }

        if (te->time > cur)
        {
            pthread_mutex_unlock(&min_heap->mtx);
            break;
        }
        min_heap_pop(min_heap);
        if (te->stop)
        {
            pthread_mutex_unlock(&min_heap->mtx);
            continue;
        }
        
        timer_handler_pt handler = te->handler;

        pthread_mutex_unlock(&min_heap->mtx);
        handler(te);
        pthread_mutex_lock(&min_heap->mtx);
        if (te->stop)
        {
            pthread_mutex_unlock(&min_heap->mtx);
            continue;
        }
        te->time = current_time() + te->interval;
        min_heap_push(min_heap, te);
        pthread_mutex_unlock(&min_heap->mtx);
    }
}

#endif // _MINHEAP_TIMER_H