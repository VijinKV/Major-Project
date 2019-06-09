import pandas as pd
from numpy import nan
from scipy.stats import pearsonr
import matplotlib.pyplot as plt
import time

def graphs(x1,y1,x,y,cnt):
    plt.subplot(2, 1, 1)
    plt.plot(x1, 'ko-')
    plt.title('Vulnerability and Codesmells')
    plt.xlabel(x)
    plt.ylabel('Vulnerability')




    plt.subplot(2, 1, 2)
    plt.plot(y1, 'r.-')
    plt.xlabel(y)
    plt.ylabel('Codesmell')
    manager = plt.get_current_fig_manager()
    manager.window.showMaximized()
    plt.savefig('graph'+str(cnt)+'.jpg')
    
    plt.show()
cnt = 0
cd = pd.read_csv("CSmellList.csv", index_col=0)
vl = pd.read_csv("VulnList.csv", index_col=0)
Relation=[]
for x in vl.columns.values:
    for y in cd.columns.values:
        df = pd.DataFrame([vl[x],cd[y]]).transpose()
        df= df.replace(0,nan)
        df=df.dropna(how='all',axis=0)
        df=df.replace(nan,0)
        if (len(df[x])>1 or len(df[y])>1) and x != y:
        	#print("After cleanup",df[x],df[y])
        	correlationof = df[x].corr(df[y])
        	if(correlationof>0.9):
        		print("After cleanup",df[x],df[y])
        		print(x," :X: ",y," :(high) ",correlationof)
        		Relation.append(str(x)+" :X: "+str(y)+" :(high) "+str(correlationof))
        		#print('REsult: \n',df[x])
        		#print(df[y])
        		graphs(df[x],df[y],x,y,cnt)
        		cnt=cnt+1
        
       	
rl = pd.DataFrame({"Correlation":Relation})
rl.to_csv("CorrelationValues.csv")