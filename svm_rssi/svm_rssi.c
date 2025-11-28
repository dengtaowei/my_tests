#include <stdlib.h>
#include <math.h>
#include "svm_rssi.h"

#define MAX_NUM_SUPPORT_VECTORS 128

typedef struct SVM_PARAMS_S
{
    double dIntercept;
    double dGamma;
    double dXMean;
    double dXScale;
    double dYMean;
    double dYScale;
    int iNumVectors;
    double adSupportVector[MAX_NUM_SUPPORT_VECTORS];
    double adDualCoef[MAX_NUM_SUPPORT_VECTORS];
} SVM_PARAMS_T;

#define MIN_RSSI_VAL (-127)
#define MAX_RSSI_VAL (0)
#define MIN_SNR_VAL (0)
#define MAX_SNR_VAL (100)

#define MIN_SVM_VALID_RSSI_2G -94
#define MAX_SVM_VALID_RSSI_2G -46
#define MIN_SVM_VALID_RSSI_5G -89
#define MAX_SVM_VALID_RSSI_5G -49

// 参数设置
#define NUM_SUPPORT_VECTORS_2G 19
#define SVM_INTERCEPT_2G 2.47654183
#define SVM_GAMMA_2G 0.08

// 假设这是从Python中提取的均值和标准差
#define SVM_XMEAN_2G -70.890625
#define SVM_XSCALE_2G 15.4006524
#define SVM_YMEAN_2G 29.328125
#define SVM_YSCALE_2G 14.04885044

static SVM_PARAMS_T g_stSvmParam2G = {
    .dIntercept = SVM_INTERCEPT_2G,
    .dGamma = SVM_GAMMA_2G,
    .dXMean = SVM_XMEAN_2G,
    .dXScale = SVM_XSCALE_2G,
    .dYMean = SVM_YMEAN_2G,
    .dYScale = SVM_YSCALE_2G,
    .iNumVectors = NUM_SUPPORT_VECTORS_2G,
    .adSupportVector = {0.18769497, 1.15356314, -1.46807904, 0.7315031,
                        0.97499928, 0.84513465, 0.12276266, 1.08051429,
                        1.1860293, 0.76396926, 0.05783034, -0.78628974,
                        0.25262728, 1.15356314, 1.26719469, 1.60808934,
                        0.89383389, 0.90195043, 1.59185626},
    .adDualCoef = {1189.00461803, -1247, 222.62799252, -1247,
                   1247, -1247, -1247, -1247,
                   1247, -1247, 1247, -868.18211168,
                   1247, 993.24750526, 1247, -1247,
                   1247, -1247, 957.30199587}};

// 参数设置
#define NUM_SUPPORT_VECTORS_5G 6
#define SVM_INTERCEPT_5G -1.8826612
#define SVM_GAMMA_5G 0.08

// 假设这是从Python中提取的均值和标准差
#define SVM_XMEAN_5G -70.25714286
#define SVM_XSCALE_5G 10.77484894
#define SVM_YMEAN_5G 21.87142857
#define SVM_YSCALE_5G 10.08860238

static SVM_PARAMS_T g_stSvmParam5G = {
    .dIntercept = SVM_INTERCEPT_5G,
    .dGamma = SVM_GAMMA_5G,
    .dXMean = SVM_XMEAN_5G,
    .dXScale = SVM_XSCALE_5G,
    .dYMean = SVM_YMEAN_5G,
    .dYScale = SVM_YSCALE_5G,
    .iNumVectors = NUM_SUPPORT_VECTORS_5G,
    .adSupportVector = {-1.64669196, 0.92101612, 0.20948255, -1.64669196,
                        -0.19268859, 1.70215622},
    .adDualCoef = {-1689, 693.57311533, -1516.20507069, 1604.17601927,
                   1045.62891594, -138.17297985}};

// RBF核函数实现
static double rbf_kernel(double dV1, double dV2, double dGamma)
{
    double dSum = 0.0;
    double dDiff = dV1 - dV2;
    dSum = dDiff * dDiff;
    return exp(-dGamma * dSum);
}

// 标准化输入特征
static double standardize(double dX, double dMean, double dScale)
{
    return (dX - dMean) / dScale;
}

// 反标准化预测结果
static double inverse_standardize(double dY, double dMean, double dScale)
{
    return dY * dScale + dMean;
}

// 使用SVR进行预测
static double predict(double dX, double *pdSupportVectors, double *pdDualCoef,
                      int iNumVectors, double dIntercept, double dGamma)
{
    double dResult = 0.0;

    for (int idx = 0; idx < iNumVectors; idx++)
    {
        double dK = rbf_kernel(pdSupportVectors[idx], dX, dGamma);
        dResult += pdDualCoef[idx] * dK;
    }

    dResult += dIntercept;

    return dResult;
}

// 使用SVR进行预测
static double predict_standardize(SVM_PARAMS_T *pstSvmParam,
                                  double dX)
{
    // 对输入x进行标准化
    double dXStandardized = standardize(dX, pstSvmParam->dXMean, pstSvmParam->dXScale);
    double result = predict(dXStandardized, pstSvmParam->adSupportVector,
                            pstSvmParam->adDualCoef, pstSvmParam->iNumVectors,
                            pstSvmParam->dIntercept, pstSvmParam->dGamma);
    return inverse_standardize(result, pstSvmParam->dYMean, pstSvmParam->dYScale);
}

static double predict_rssi_svm(SVM_PARAMS_T *pstSvmParam,
                               double dX)
{
    return predict_standardize(pstSvmParam, dX);
}

static double predict_rssi_liner(double dX1,
                                 double dY1,
                                 double dX2,
                                 double dY2,
                                 double dX)
{
    if (dX2 - dX1 == 0)
    {
        return -1.0;
    }
    double dK = (dY2 - dY1) / (dX2 - dX1);
    double dB = dY2 - dK * dX2;
    return dK * dX + dB;
}

static double predict_rssi_lower(
    double dXLower, double dYLower, double dX)
{
    return predict_rssi_liner(MIN_RSSI_VAL, MIN_SNR_VAL, dXLower, dYLower, dX);
}

static double predict_rssi_upper(
    double dXUpper, double dYUpper, double dX)
{
    return predict_rssi_liner(MAX_RSSI_VAL, MAX_SNR_VAL, dXUpper, dYUpper, dX);
}

static double predict_rssi(SVM_PARAMS_T *pstSvmParam,
                           double dX,
                           double dXLower, double dXUpper)
{
    double dY = 0.0;

    if (dX < dXLower)
    {
        double dYLower = predict_rssi_svm(pstSvmParam, dXLower);
        dY = predict_rssi_lower(dXLower, dYLower, dX);
    }
    else if (dX >= dXLower && dX <= dXUpper)
    {
        dY = predict_rssi_svm(pstSvmParam, dX);
    }
    else
    {
        double dYUpper = predict_rssi_svm(pstSvmParam, dXUpper);
        dY = predict_rssi_upper(dXUpper, dYUpper, dX);
    }

    return dY;
}

double svm_predict_rssi_2G(double dX)
{
    if (dX < MIN_RSSI_VAL || dX > MAX_RSSI_VAL || g_stSvmParam2G.iNumVectors > MAX_NUM_SUPPORT_VECTORS || g_stSvmParam2G.dXScale == 0)
    {
        return -1.0;
    }
    return predict_rssi(&g_stSvmParam2G, dX,
                        MIN_SVM_VALID_RSSI_2G, MAX_SVM_VALID_RSSI_2G);
}

double svm_predict_rssi_5G(double dX)
{
    if (dX < MIN_RSSI_VAL || dX > MAX_RSSI_VAL || g_stSvmParam2G.iNumVectors > MAX_NUM_SUPPORT_VECTORS || g_stSvmParam5G.dXScale == 0)
    {
        return -1.0;
    }
    return predict_rssi(&g_stSvmParam5G, dX,
                        MIN_SVM_VALID_RSSI_5G, MAX_SVM_VALID_RSSI_5G);
}