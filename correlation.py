import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt



names=['srcIP', 'dstIP','asduType','numix','cot', 'len','ipLen','srcPort' , 'ioa']
#names=['srcPort', 'dstPort','ipLen', 'len', 'asduType', 'cot']
datafiles=['normal-traffic.csv','connection-loss.csv',
           'dos-attack.csv','injection-attack.csv',
           'rogue-device.csv','scanning-attack.csv','switching-attack.csv']
pwd='C:\\Users\\moham\\Desktop\\Dataset\\but-iec104-i\\'
datafile = datafiles[5]
df = pd.read_csv(pwd+datafile,sep=';')
data = df[names]
#sns.set(font_scale=1.4)
print("data shape ",data.shape)
corrmat = data.corr('pearson')
fig = plt.figure(num=None, figsize=(12, 12), dpi=80, facecolor='w', edgecolor='k')
sns.heatmap(corrmat, annot=True, cmap="PuBu", linewidths = 0.1)
#plt.savefig("figures/heart.png",format='svg')

'''
# Generate a mask for the upper triangle
mask = np.triu(np.ones_like(corrmat, dtype=bool))

# Set up the matplotlib figure
f, ax = plt.subplots(figsize=(11, 9))

# Generate a custom diverging colormap
cmap = sns.diverging_palette(230, 20, as_cmap=True)

# Draw the heatmap with the mask and correct aspect ratio
ax = sns.heatmap(corrmat, mask=mask, cmap=plt.cm.gist_heat, vmax=.3, center=0,
            square=True, linewidths=.5, cbar_kws={"shrink": .5})
ax.set_xticklabels(
    ax.get_xticklabels(),
    rotation=20,
    horizontalalignment='right'
);
'''
plt.show()