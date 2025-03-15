import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix




df = pd.read_csv("22IT085_Pre-processed_Dataset.csv").iloc[:, :]

target_col = df.columns[-1]
features = df.drop(columns=target_col)
target = df[target_col]


corr_matrix = features.corr().abs()
upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
threshold = 0.9
to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
features_final = features.drop(columns=to_drop)
print("Removed highly correlated columns:", to_drop)


df_clean = pd.concat([features_final, target], axis=1)
print("Cleaned dataset shape:", df_clean.shape)
df_clean.to_csv("cleaned_dataset.csv", index=False)
print("Cleaned dataset saved as 'cleaned_dataset.csv'")




X = df_clean.iloc[:, :-1].values  
y = df_clean[target_col].values


X_train_orig, X_test_orig, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)




input_dim = X_train_orig.shape[1]  
encoding_dim = 15  


input_layer = Input(shape=(input_dim,))
encoder = Dense(encoding_dim, activation='relu')(input_layer)
decoder = Dense(input_dim, activation='sigmoid')(encoder)

autoencoder = Model(inputs=input_layer, outputs=decoder)
autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.summary()

early_stopping = EarlyStopping(monitor='val_loss', patience=20, restore_best_weights=True)


autoencoder.fit(X_train_orig, X_train_orig,
                epochs=500,
                batch_size=16,
                shuffle=True,
                validation_split=0.2,
                callbacks=[early_stopping])


encoder_model = Model(inputs=input_layer, outputs=encoder)


X_train_encoded = encoder_model.predict(X_train_orig)
X_test_encoded = encoder_model.predict(X_test_orig)

print("Encoded training data shape:", X_train_encoded.shape)
print("Encoded test data shape:", X_test_encoded.shape)


encoder_output = encoder_model.predict(X_train_orig)
decoder_output = autoencoder.predict(X_train_orig)

plt.figure(figsize=(15, 4))

plt.subplot(1, 3, 1)
sns.histplot(X_train_orig.flatten(), kde=True, bins=30)
plt.title("Input Distribution")
plt.xlabel("Value")
plt.ylabel("Frequency")

plt.subplot(1, 3, 2)
sns.histplot(encoder_output.flatten(), kde=True, bins=30)
plt.title("Encoder Output Distribution")
plt.xlabel("Activation Value")
plt.ylabel("Frequency")

plt.subplot(1, 3, 3)
sns.histplot(decoder_output.flatten(), kde=True, bins=30)
plt.title("Decoder Output Distribution")
plt.xlabel("Activation Value")
plt.ylabel("Frequency")

plt.tight_layout()
plt.show()

X_train_encoded = encoder_model.predict(X_train_orig)
X_test_encoded = encoder_model.predict(X_test_orig)

plt.figure(figsize=(20, 18))
sns.heatmap(X_train_encoded[:100, :15], cmap="viridis", annot=True)
plt.title("Heatmap of Encoded Features (10 Dimensions)")
plt.xlabel("Encoded Feature")
plt.ylabel("Sample Index")
plt.show()


kernels = ['linear', 'poly', 'rbf', 'sigmoid']
for kernel in kernels:
    print(f"\n--- Training SVM with kernel: {kernel} ---")
    svm_model = SVC(kernel=kernel, random_state=42)
    svm_model.fit(X_train_encoded, y_train)
    
    y_pred = svm_model.predict(X_test_encoded)
    
    acc = accuracy_score(y_test, y_pred)
    print("Accuracy:", acc)
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))