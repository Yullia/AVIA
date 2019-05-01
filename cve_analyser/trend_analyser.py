date  = "2005-08-01"
from datetime import datetime


date2 = "2018-01-10T22:29Z"

published = datetime.strptime(date2.split('T')[0], '%Y-%m-%d')

trend_date = datetime.strptime(date, '%Y-%m-%d')
print(trend_date < published)

import pandas as pd
data = pd.read_csv("/home/yuliia/Disser/google_trend_results/CVE-2018-0004.csv")
print(data.head())
print(data.values)