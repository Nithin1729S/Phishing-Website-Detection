import pandas as pd

def convert_labels(df, column_name):
    df[column_name] = df[column_name].map({'good': 1, 'bad': 0})
    print(f"Converted '{column_name}' labels: 'good' -> 1, 'bad' -> 0")

df = pd.read_csv("22IT085_Pre-processed_Dataset_1.csv")

# Convert output labels
target_column = "Label"  # Change to your actual column name
convert_labels(df, target_column)

# Save as a CSV file without compression
df.to_csv("22IT085_Pre-processed_Dataset_1.csv", index=False)
