import pandas as pd
df = pd.read_csv('22IT085_Pre-processed_Dataset_1.csv')
df.to_csv('22IT085_Pre-processed_Dataset_1.csv.gz', index=False, compression='gzip')