import pandas as pd
df = pd.read_csv("221IT085_URLfeaturedataset.csv")
columns_to_drop = ["URL"]
df.drop(columns=columns_to_drop, axis=1, inplace=True)
df.to_csv("221IT085_URLfeaturedataset.csv", index=False)
