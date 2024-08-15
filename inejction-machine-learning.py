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

'''
dos-attack.csv: Denial of service attack against a IEC 104 control station. 
- the attacker sends a hundred of legitimate IEC 104 packets to the destination. 
He uses a spoofed IP address 192.168.11.248 which sends an ASDU with TypeID 36 
(Measured value, short floating point, with time tag) and CoT=3 (Spontaneous event).
 This message is only confirmed by the receiver using an APDU of the S-type. 
 The attack start at 23:50:02 and ends at 01:18:29. 
 From 32905.112964 to 38212.401378
 It contains about 1049 spoofed messages. 
 The attack is repeated at 02:30:05 and lasts until 04:01:54.  
From 42508.969874 to 48017.627383
'''
all = ['TimeStamp', 'RelativeTime', 'srcIP', 'dstIP', 'srcPort', 'dstPort',
       'ipLen', 'len', 'fmt', 'uType', 'asduType', 'numix', 'cot', 'oa',
       'addr', 'ioa']
columns=['srcIP', 'dstIP', 'srcPort', 'dstPort','ipLen', 'len']
###########################################
normaldata='normal-traffic.csv'
ndf = pd.read_csv('C:\\Users\\moham\\Downloads\\Dataset\\but-iec104-i\\normal-traffic.csv',sep=';')
#ndf = ndf[ndf['fmt']=='0x00000000']
ndf['ioa'] = ndf['ioa'].str.count(',')+1

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
faultdata='injection-attack'
df = pd.read_csv('C:\\Users\\moham\\Downloads\\Dataset\\but-iec104-i\\injection-attack.csv',sep=';')
df = df[df['fmt']=='0x00000000']
df = df[df['cot']==3]
df = df[df['asduType']==36]
df['srcIP'] = df['srcIP'].str[-3:].astype(int)
df['dstIP'] = df['dstIP'].str[-3:].astype(int)

df['ioa'] = df['ioa'].str.count(',')+1

df.rename(columns = {'Relative Time':'RelativeTime'}, inplace = True)


dfSWTtest = df.query("23035.965179000 < RelativeTime < 23975.486044000")
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
ifo = IsolationForest(n_estimators=50, contamination=float(0.45))
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
