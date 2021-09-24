#Copyright 2020 Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED.

#Usage: python TrainAndPickleSKLearnModels.py <Full Path to TrainingData.csv>

import pandas as pd
import numpy as np
import sys
import pickle
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import svm
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression


try:
   inputTrainingData = sys.argv[1]
except:
   print('Full Path to TrainingData.csv was not supplied as command line argument')
   sys.exit()

trainingData = pd.read_csv(inputTrainingData)

#Parse X & Y data from Datasets
x_train = trainingData[['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20',
                        '21','22','23','24','25','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40',
                        '41','42','43','44','45','46','47','48','49','50','51','52','53','54','55','56','57','58','59','60',
                        '61','62','63','64','65','66','67','68','69','70','71','72','73','74','75','76','77','78','79','80',
                        '81','82','83','84','85','86','87','88','89','90','91','92','93','94','95','96','97','98','99','100',
                        '101','102','103','104','105','106','107','108','109','110','111','112','113','114','115','116','117','118','119','120',
                        '121','122','123','124','125','126','127','128']] #Inputs
y_train = trainingData['Description'] #Output

#Run Test
model1 = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(15,), random_state=1, max_iter=4000)  
model2 = AdaBoostClassifier(n_estimators=100, random_state=1)
model3 = RandomForestClassifier(n_estimators=100, max_depth=2, random_state=1)
model4 = KNeighborsClassifier(n_neighbors=3)
model5 = DecisionTreeClassifier(random_state=1)
model6 = svm.SVC(gamma='scale')
model7 = GaussianNB()
model8 = LogisticRegression(random_state=1, solver='lbfgs',multi_class='multinomial', max_iter=200)

model1.fit(x_train, y_train)
model2.fit(x_train, y_train)
model3.fit(x_train, y_train)
model4.fit(x_train, y_train)
model5.fit(x_train, y_train)
model6.fit(x_train, y_train)
model7.fit(x_train, y_train)
model8.fit(x_train, y_train)

pickle.dump(model1, open('ProcessGrabber_NeuralNetwork.sav', 'wb'))
pickle.dump(model2, open('ProcessGrabber_AdaBoost.sav', 'wb'))
pickle.dump(model3, open('ProcessGrabber_RandomForrest.sav', 'wb'))
pickle.dump(model4, open('ProcessGrabber_kNN.sav', 'wb'))
pickle.dump(model5, open('ProcessGrabber_Tree.sav', 'wb'))
pickle.dump(model6, open('ProcessGrabber_SVM.sav', 'wb'))
pickle.dump(model7, open('ProcessGrabber_NaiveBayes.sav', 'wb'))
pickle.dump(model8, open('ProcessGrabber_LogisticRegression.sav', 'wb'))

print('Done')
