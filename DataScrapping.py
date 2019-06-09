from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait 
import selenium.webdriver.support.expected_conditions as ec
from   selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
import time
import json
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from numpy import nan
from scipy.stats import pearsonr

def graphs(x1,y1,x,y):
    plt.subplot(2, 1, 1)
    plt.plot(x1, 'ko-')
    plt.title('Vulnerability and Codesmells')
    plt.xlabel(x)
    plt.ylabel('No. of Codesmells')




    plt.subplot(2, 1, 2)
    plt.plot(y1, 'r.-')
    plt.xlabel(y)
    plt.ylabel('No. of Vulnerability')
    manager = plt.get_current_fig_manager()
    manager.frame.Maximize(True)
    plt.show()
    plt.savefig('sampleFileName.png')

browser = webdriver.Chrome()

pageNo = 5
ProjectID = []
ProjectNameID = {}
ValidPro = {}
ProSize = {}


for pn in range(pageNo):
	print("\n\nPage No:",pn)
	browser.get("https://sonarcloud.io/api/components/search_projects?p="+str(pn+1)+"&ps=100&facets=reliability_rating%2Csecurity_rating%2Csqale_rating%2Ccoverage%2Cduplicated_lines_density%2Cncloc%2Calert_status%2Clanguages%2Ctags&f=analysisDate%2CleakPeriodDate&filter=languages%20%3D%20java&s=security_rating&asc=false")
	 
	WebDriverWait(browser,100).until(ec.presence_of_element_located((By.CSS_SELECTOR,'pre'))) 
	value = browser.find_element_by_css_selector('pre')

	x = json.loads(value.text)
	ProjectName={}
	for y in x['components']:
		ProjectName[y['key']] = y['name']
	ProjectNameID.update(ProjectName)
	A='https://sonarcloud.io/api/measures/search?projectKeys='
	C='&metricKeys=%2Ccode_smells%2Cncloc'
	B=''
	#New url for value extraction
	print(pn*100," ",len(ProjectName))#correct this
	for x,i in zip(ProjectName.keys(),range(len(ProjectName))):
		if i+1 != len(ProjectName):
			B+=x+','
		else:
			B+=x
	FinalUrl = A+B+C
	print(FinalUrl)
	browser.get(FinalUrl)
	value = browser.find_element_by_css_selector('pre')
	x = json.loads(value.text)

	
	for y in x['measures']:
		if y['metric']=='code_smells' and int(y['value'])<1000:
			ValidPro[y['component']]=y['value']
		if y['metric']=='ncloc' and y['component'] in ValidPro:
			ProSize[y['component']]=y['value']

print(len(ValidPro))
print(len(ProjectNameID))

pre = 'https://sonarcloud.io/api/issues/search?componentKeys='
posCD= '&resolved=false&types=CODE_SMELL&facets=types%2Crules&additionalFields=_all'
posVL= '&resolved=false&types=VULNERABILITY&facets=types%2Crules&additionalFields=_all'


codesmells = []
vulnerability = []

for x in ValidPro.keys():
	ProjectUrlCd = pre+x+posCD
	ProjectUrlVl = pre+x+posVL
	print("\n\n",ProjectNameID[x],", ID: ",x," Size: ",ProSize[x]," Codesmells: ",ValidPro[x])

	print('codesmells :')
	browser.get(ProjectUrlCd)
	WebDriverWait(browser,100).until(ec.presence_of_element_located((By.CSS_SELECTOR,'pre'))) 
	value = browser.find_element_by_css_selector('pre')
	x = json.loads(value.text)
	sum=0
	info={}
	vinfo={}
	for y in x['rules']:

		for z in x['facets'][1]['values']:
			if y['key'] == z['val']:
			 	count = z['count']
			 	sum+=count
			 	info[y['name']]=z['count']
			 	print(y['name']," : ",z['count'])

	codesmells.append(info)
	print(sum)

	print('Vulnerability :')
	browser.get(ProjectUrlVl)
	WebDriverWait(browser,100).until(ec.presence_of_element_located((By.CSS_SELECTOR,'pre'))) 
	value = browser.find_element_by_css_selector('pre')
	x = json.loads(value.text)
	sum=0
	for y in x['rules']:

		for z in x['facets'][1]['values']:
			if y['key'] == z['val']:
			 	count = z['count']
			 	sum+=count
			 	vinfo[y['name']]=z['count']
			 	print(y['name']," : ",z['count'])

	vulnerability.append(vinfo)
	print(sum)

pname = list(ProjectNameID[x] for x in ValidPro.keys())
psize=[ProSize[x] for x in ValidPro.keys()]
Pdetails = pd.DataFrame({"Project":pname,"Size":psize})
Pdetails.to_csv("Projects.csv")

cd = pd.DataFrame(codesmells)
cd.fillna(0, inplace=True)
print(cd)
cd.to_csv('CSmellList.csv')

vl = pd.DataFrame(vulnerability)
vl.fillna(0, inplace=True)
vl.to_csv('VulnList.csv')
print(vl)
Relation=[]
for x in vl.columns.values:
    for y in cd.columns.values:
        df = pd.DataFrame([vl[x],cd[y]]).transpose()
        if len(df[x])>1 or len(df[y])>1:
        	#corr = df[x].corr(df[y])
        	correlationof, p_value = pearsonr(df[x],df[y])
        	print(x," :X: ",y," : ",correlationof)
        	if(correlationof>0.8):
        		print(x," :X: ",y," :(high) ",correlationof)
        		Relation.append(str(x)+" :X: "+str(y)+" :(high) "+str(correlationof))
        		#print('REsult: \n',df[x])
        		#print(df[y])
        		graphs(df[x],df[y],x,y)
        		

plt.show()
plt.savefig('sampleFileName.png')
        
		        	
rl = pd.DataFrame({"Correlation":Relation})
rl.to_csv("CorrelationValues.csv")






