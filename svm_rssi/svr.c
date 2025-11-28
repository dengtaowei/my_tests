#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h> // 用于clock_gettime
#include "svm_rssi.h"

int main()
{
    double x[128] = {0.0};
    double y[128] = {0.0};
    for (int i = 0; i < 128; i++)
    {
        x[i] = -i;
    }

    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < 128; i++)
    {
        y[i] = svm_predict_rssi_2G(x[i]);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double time_spent = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_nsec - start.tv_nsec) / 1e6;

    printf("Time taken: %f milliseconds\n", time_spent);

    for (int i = 0; i < 128; i++)
    {
        printf("Rssi: %f, SNR, %f\n", x[i], y[i]);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < 128; i++)
    {
        y[i] = svm_predict_rssi_5G(x[i]);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    time_spent = (end.tv_sec - start.tv_sec) * 1000.0 +
                 (end.tv_nsec - start.tv_nsec) / 1e6;

    printf("=========================================================\n");
    printf("Time taken: %f milliseconds\n", time_spent);

    for (int i = 0; i < 128; i++)
    {
        printf("Rssi: %f, SNR, %f\n", x[i], y[i]);
    }

    return 0;
}