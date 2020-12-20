
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import re
import pickle

from tqdm import tqdm
import os
from sklearn.metrics import classification_report
from sklearn.metrics import precision_score
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import math
from sklearn.naive_bayes import GaussianNB
from sklearn.naive_bayes import BernoulliNB
from sklearn.linear_model import SGDClassifier
from scipy.stats import randint as sp_randint
from scipy.stats import uniform
from sklearn.preprocessing import LabelEncoder

from flask import Flask, jsonify, request
import joblib


import flask
app = Flask(__name__)


def binary_classification(a):
    new_class=[]
    for i in a:    
        if i==0:
            new_class.append(0)
        else:
            new_class.append(1)
    return new_class


def binary_attack(a):
    new_class=[]
    for i in a:    
        if i==1:
            new_class.append(0)
        else:
            new_class.append(1)
    return new_class

def decontracted(phrase):
    
    phrase = re.sub(r"\'", "", phrase)
    phrase = re.sub(r"^b", "", phrase)
    phrase = re.sub(r"-", "_", phrase)
    
    return phrase


def preprocess_text(text_data):
    preprocessed_text = []
    # tqdm is for printing the status bar
    for sentance in text_data:
        sent = decontracted(str(sentance))
        
        preprocessed_text.append(sent.lower().strip())
    return preprocessed_text

all_columns=['SRC_ADD', 'DES_ADD', 'PKT_ID', 'FROM_NODE', 'TO_NODE', 'PKT_TYPE',
       'PKT_SIZE', 'FLAGS', 'FID', 'SEQ_NUMBER', 'NUMBER_OF_PKT',
       'NUMBER_OF_BYTE', 'NODE_NAME_FROM', 'NODE_NAME_TO', 'PKT_IN', 'PKT_OUT',
       'PKT_R', 'PKT_DELAY_NODE', 'PKT_RATE', 'BYTE_RATE', 'PKT_AVG_SIZE',
       'UTILIZATION', 'PKT_DELAY', 'PKT_SEND_TIME', 'PKT_RESEVED_TIME',
       'FIRST_PKT_SENT', 'LAST_PKT_RESEVED']

@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/DDoS')
def DDoS():
    return flask.render_template('DDoS.html')


@app.route('/predict', methods=['POST'])
def predict ():
    
    loaded_model_3 = joblib.load('Pickle_RL_Model_3.pkl')
    loaded_model_2 = joblib.load('Pickle_RL_Model_2.pkl')
    loaded_model_1 = joblib.load('Pickle_RL_Model_1.pkl')

    scale = joblib.load('Standard_scale.pkl')
    scale_1 = joblib.load('Standard_scale_1.pkl')
    scale_2 = joblib.load('Standard_scale_2.pkl')

    PKT_TYPE_LE = joblib.load('PKT_TYPE_LE.pkl')
    NODE_NAME_FROM_LE = joblib.load('NODE_NAME_FROM_LE.pkl')
    NODE_NAME_TO_LE = joblib.load('NODE_NAME_TO_LE.pkl')

    review_text=list('review_text')
    new={all_columns[i]:review_text[i] for i in range(len(all_columns))}
    df_new=pd.DataFrame((new),index =[1])
    df_new['NODE_NAME_FROM'] = preprocess_text(df_new['NODE_NAME_FROM'].values)
    df_new['NODE_NAME_TO'] = preprocess_text(df_new['NODE_NAME_TO'].values)
    df_new['PKT_TYPE'] = preprocess_text(df_new['PKT_TYPE'].values)
    
    df_new['PKT_TYPE_encode']=PKT_TYPE_LE.transform(df_new['PKT_TYPE'])
    df_new['NODE_NAME_FROM_encode']=NODE_NAME_FROM_LE.transform(df_new['NODE_NAME_FROM'])
    df_new['NODE_NAME_TO_encode']=NODE_NAME_TO_LE.transform(df_new['NODE_NAME_TO'])
    df_new = df_new.drop(['PKT_TYPE','NODE_NAME_FROM','NODE_NAME_TO','FLAGS'], axis=1)
    
    for i in range(df_new.shape[1]):
        t=df_new.columns[i]
        new_val=scale[i].transform(df_new.values[0][i].reshape(1, -1))
        df_new[t]=new_val
        
    result=loaded_model_1.predict(df_new)
    if result == 0:
        return 'Normal traffic'
    
    else:
        df_new1=pd.DataFrame((new),index =[1])
        df_new1['NODE_NAME_FROM'] = preprocess_text(df_new1['NODE_NAME_FROM'].values)
        df_new1['NODE_NAME_TO'] = preprocess_text(df_new1['NODE_NAME_TO'].values)
        df_new1['PKT_TYPE'] = preprocess_text(df_new1['PKT_TYPE'].values)
    
        df_new1['PKT_TYPE_encode']=PKT_TYPE_LE.transform(df_new1['PKT_TYPE'])
        df_new1['NODE_NAME_FROM_encode']=NODE_NAME_FROM_LE.transform(df_new1['NODE_NAME_FROM'])
        df_new1['NODE_NAME_TO_encode']=NODE_NAME_TO_LE.transform(df_new1['NODE_NAME_TO'])
        df_new1 = df_new1.drop(['PKT_TYPE','NODE_NAME_FROM','NODE_NAME_TO','FLAGS'], axis=1)
    
        for i in range(df_new1.shape[1]):
            t=df_new1.columns[i]
            new_val=scale_1[i].transform(df_new1.values[0][i].reshape(1, -1))
            df_new1[t]=new_val
        result1=loaded_model_2.predict(df_new1)
        if result1== 0:
            prediction= 'UDP-Flood Attack'
            
        else:
            df_new2=pd.DataFrame((new),index =[1])
            df_new2['NODE_NAME_FROM'] = preprocess_text(df_new2['NODE_NAME_FROM'].values)
            df_new2['NODE_NAME_TO'] = preprocess_text(df_new2['NODE_NAME_TO'].values)
            df_new2['PKT_TYPE'] = preprocess_text(df_new2['PKT_TYPE'].values)
    
            df_new2['PKT_TYPE_encode']=PKT_TYPE_LE.transform(df_new2['PKT_TYPE'])
            df_new2['NODE_NAME_FROM_encode']=NODE_NAME_FROM_LE.transform(df_new2['NODE_NAME_FROM'])
            df_new2['NODE_NAME_TO_encode']=NODE_NAME_TO_LE.transform(df_new2['NODE_NAME_TO'])
            df_new2 = df_new2.drop(['PKT_TYPE','NODE_NAME_FROM','NODE_NAME_TO','FLAGS'], axis=1)
    
            for i in range(df_new2.shape[1]):
                t=df_new2.columns[i]
                new_val=scale_2[i].transform(df_new2.values[0][i].reshape(1, -1))
                df_new2[t]=new_val
            result2=loaded_model_3.predict(df_new2)
            if result2 == 2:
                prediction= 'Smurf Attack'
            elif result2 ==3:
                prediction= 'SIDDOS Attack'
            elif result2 == 4:
                prediction= 'HTTP-FLOOD Attack'  
            
    return jsonify({'prediction': prediction})       

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)



