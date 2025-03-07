import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler

def check_duplicate_columns(df):
    duplicate_columns = []
    for idx, col in enumerate(df.columns):
        if df[col].nunique() == 1:  
            duplicate_columns.append((idx, col))  
    if duplicate_columns:
        print("Duplicate columns found:")
        for idx, col in duplicate_columns:
            print(f"Column Index: {idx}, Column Name: {col}")
        with open(f"221IT085-Duplicate-Column.txt", "w") as file:
            for idx, col in duplicate_columns:
                file.write(f"Column Index: {idx}, Column Name: {col}\n")

def check_duplicate_rows(df):
    duplicate_rows = df[df.duplicated()]
    if not duplicate_rows.empty:
        print("Duplicate rows found at indices:", duplicate_rows.index.tolist())
        with open(f"221IT085-Duplicate-Row.txt", "w") as file:
            file.write("\n".join(map(str, duplicate_rows.index.tolist())))

def apply_standardization(df):
    numerical_cols = df.select_dtypes(include=[np.number]).columns
    scaler = StandardScaler()
    df[numerical_cols] = scaler.fit_transform(df[numerical_cols])
    print("Standardization (Z-score normalization) applied.")

def handle_missing_values(df):
    missing_cols = df.columns[df.isnull().any()]
    for col in missing_cols:
        if df[col].dtype == np.number:
            df[col].fillna(df[col].mean(), inplace=True)  
        else:
            df[col].fillna(df[col].mode()[0], inplace=True)  
    print("Missing values handled.")

def generate_heatmap(df):
    # Keep only numeric columns
    df_numeric = df.select_dtypes(include=[float, int])
    correlation_matrix = df_numeric.corr()
    fig, ax = plt.subplots(1, 1, figsize=(30, 20))
    sns.heatmap(
        correlation_matrix, annot=False, cmap="coolwarm",
        cbar=True, linewidths=0.5, square=True, ax=ax
    )
    ax.set_title("Full Correlation Heatmap")
    plt.tight_layout()
    plt.savefig("221IT085_Heatmap.jpeg", format="jpeg")
    print(f"Heatmap saved")
    
    plt.show()



def main():
    file_path = "221IT085_URLfeaturedataset.csv"  
    df = pd.read_csv(file_path)
    check_duplicate_columns(df)
    check_duplicate_rows(df)
    apply_standardization(df) 
    handle_missing_values(df)
    generate_heatmap(df)
    df.to_csv(f"22IT085_Pre-processed_Dataset.csv", index=False) 
    print(f"Modified data saved")

if __name__ == "__main__":
    main()
