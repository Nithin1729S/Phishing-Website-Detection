import pandas as pd
df = pd.read_csv('221IT085_URLfeaturedataset.csv')
df.to_csv('221IT085_URLfeaturedataset.csv.gz', index=False, compression='gzip')