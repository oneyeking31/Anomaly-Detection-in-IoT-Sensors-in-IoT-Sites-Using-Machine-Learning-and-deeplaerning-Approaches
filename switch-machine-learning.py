import pandas as pd
import numpy as np
from sklearn import svm
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt

import seaborn as sns
import os

def trunc( floatValue, n ):
    results=0;
    s="%."+str(n)+"f"
    results = float(s % floatValue)
    '''
    "%.2f" % 1.2399  # returns "1.24"
    "%.3f" % 1.2399  # returns "1.240"
    "%.2f" % 1.2  # returns "1.20"
    '''
    return results;
def getMetrics(TP,FP,TN,FN):
    TPR, FPR, Accuracy, Precision, Recall, F1Score, AUC=0,0,0,0,0,0,0
    import math
    from math import sqrt
    try :
        TPR = trunc(  TP / (1.*(TP +FN)) , 4)
        FPR = trunc( FP / (1.*(FP + TN)), 4)
        Recall =trunc(  TP / (1.*(TP + FN)), 4)
        Accuracy =trunc(  (TP + TN) / (1. * (TP + FP + FN + TN)), 4)
        Precision =trunc(  TP * 1. / (1. * (TP + FP)), 4)
        F1Score =trunc(  2. * (Recall * Precision) / (1. * (Recall + Precision)), 4)
        AUC =trunc(  (TPR - FPR + 1) / 2. , 4)
    except :
        print('Error : TP {},FP {},TN {},FN {}'.format(TP,FP,TN,FN))
    #MMC = (TP*TN - FP * FN)/(1.*math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN)))

    return TPR,FPR,Accuracy,Precision,Recall,F1Score,AUC#,MMC

#########################################################################################3
##########################################################################################
'''
rogue-devices.csv: A rogue devices starts communicating with an IEC 104 host using legitimate IEC 104 packets. 
    - The attacker uses a sequence of IEC 104 messages with ASDU type=36 (Measured value, short floating point with time tag) 
    and CoT=3 (spontaneous event). It also correctly responses with supervisory APDUs. The attack start at 15:19:00 and ends at 15:46:03 
    It uses an IP address 192.168.11.246. The attack includes 417 packets.
'''
#########################################################################################3
##########################################################################################
ll = ['TimeStamp', 'RelativeTime', 'srcIP', 'dstIP', 'srcPort', 'dstPort',
       'ipLen', 'len', 'fmt', 'uType', 'asduType', 'numix', 'cot', 'oa',
       'addr', 'ioa']
columns=['srcIP', 'dstIP', 'srcPort', 'dstPort', 'len',]
#########################################
normaldata='normal-traffic.csv'
ndf = pd.read_csv('C:\\Users\\moham\\Downloads\\Dataset\\but-iec104-i\\normal-traffic.csv',sep=';')
ndf.rename(columns = {'Relative Time':'RelativeTime'}, inplace = True)
ndf['srcIP'] = ndf['srcIP'].str[-3:].astype(int)
ndf['dstIP'] = ndf['dstIP'].str[-3:].astype(int)
print(ndf.head())
print(ndf.columns)
dfNormalTest = ndf.query("220004 > RelativeTime > 210000")
print("dfNormalTest shape : ",dfNormalTest.shape)
#print(dfNormal.isnull().sum())
dfNormalTrain = ndf.query("100000 < RelativeTime < 200004")
print("dfNormal shape : ",dfNormalTrain.shape)

#########################################
faultdata='switching-attack'
df = pd.read_csv('C:\\Users\\moham\\Downloads\\Dataset\\but-iec104-i\\switching-attack.csv',sep=';')
df = df[df['cot']==3]
df = df[df['fmt']=='0x00000000']
df = df[df['asduType']==36]
df['srcIP'] = df['srcIP'].str[-3:].astype(int)
df['dstIP'] = df['dstIP'].str[-3:].astype(int)
df.rename(columns = {'Relative Time':'RelativeTime'}, inplace = True)
dfSWTtest = df.query("56778.000000001  < RelativeTime < 57380.844335000 ")
#dfSWTtest = df.query("42508.969874 < RelativeTime < 48017.627779")
print("dfSWTStest shape : ",dfSWTtest.shape)
################################################
scaler = MinMaxScaler(feature_range=(0, 1))
print("Normalization")
X_train = dfNormalTrain[columns].values
X_normal = dfNormalTest[columns].values
X_attack = dfSWTtest[columns].values

X_train = scaler.fit_transform(X_train)
X_normal = scaler.transform(X_normal)
X_attack = scaler.transform(X_attack)
################################################
##############################################
timesteps=1
n_features= len(columns)
print("timesteps : ",timesteps)
print("n_features : ",n_features)
print("X_train shape : ",X_train.shape)

n = len(X_train) % (timesteps * n_features);
if n> 0 : X_train = X_train[:-n, :];
X_train = X_train.reshape(-1,timesteps,n_features)

n = len(X_normal) % (timesteps * n_features);
if n > 0 : X_normal = X_normal[:-n, :]
X_normal = X_normal.reshape(-1,timesteps,n_features)

n = len(X_attack) % (timesteps * n_features);
if n > 0 : X_attack = X_attack[:-n, :]
X_attack = X_attack.reshape(-1,timesteps,n_features)
##############################################

X_train = X_train.reshape(-1,timesteps*n_features)
X_normal = X_normal.reshape(-1,timesteps*n_features)
X_attack = X_attack.reshape(-1,timesteps*n_features)

print("Anomaly Detection")
ifo = IsolationForest(contamination=0.45)
lof = LocalOutlierFactor(novelty=True,contamination=0.09)
ee = EllipticEnvelope(support_fraction=0.999,contamination=0.09)
ocsvm = svm.OneClassSVM(kernel="rbf",nu=0.001,gamma=0.1)
models = ['IsolationForest', 'LocalOutlierFactor', 'OneClassSVM', 'EllipticEnvelope']
for clf, model in zip([ifo, lof, ocsvm, ee], models):
    clf.fit(X_train)
    Y_normal_prediction = clf.predict(X_normal)
    TP = len(Y_normal_prediction[Y_normal_prediction == 1])
    FN = len(Y_normal_prediction[Y_normal_prediction == -1])
    # print("TP = {} FN {}".format(TP,FN))

    Y_test_prediction = clf.predict(X_attack)
    # Y_test_prediction = np.where(Y_test_prediction == -1, 1, -1)
    FP = len(Y_test_prediction[Y_test_prediction == 1])
    TN = len(Y_test_prediction[Y_test_prediction == -1])
    # print("FP = {} TN {}".format(FP,TN))

    TPR, FPR, Accuracy, Precision, Recall, F1Score, AUC = getMetrics(TP, FP, TN, FN)
    print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format( model, TPR, FPR, Accuracy, Precision, Recall, F1Score,
                                                      AUC))
    ####################################################



