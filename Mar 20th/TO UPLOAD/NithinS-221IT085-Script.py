import pandas as pd

df = pd.read_csv("22IT085_Pre-processed_Dataset.csv") 
train_df = df.sample(frac=0.8, random_state=42)  
test_df = df.drop(train_df.index)  

train_df.to_csv("train.csv", index=False)
test_df.to_csv("test.csv", index=False)

print("CSV files saved: train.csv (80%), test.csv (20%)")

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import MinMaxScaler






def reconstruction_accuracy(y_true, y_pred):
    y_true_bin = tf.cast(y_true > 0.5, tf.float32)
    y_pred_bin = tf.cast(y_pred > 0.5, tf.float32)
    equal = tf.equal(y_true_bin, y_pred_bin)
    return tf.reduce_mean(tf.cast(equal, tf.float32))




class TimeHistory(tf.keras.callbacks.Callback):
    def on_train_begin(self, logs=None):
        self.times = []
        self.cumulative_times = []
    def on_epoch_begin(self, epoch, logs=None):
        self.epoch_time_start = time.time()
    def on_epoch_end(self, epoch, logs=None):
        epoch_time = time.time() - self.epoch_time_start
        self.times.append(epoch_time)
        
        if self.cumulative_times:
            cum_time = self.cumulative_times[-1] + epoch_time
        else:
            cum_time = epoch_time
        self.cumulative_times.append(cum_time)





df_train = pd.read_csv("train.csv").iloc[:200000, :]
target_col = df_train.columns[-1]
features = df_train.drop(columns=target_col)
target = df_train[target_col]


corr_matrix = features.corr().abs()
upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
threshold = 0.9
to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
features_final = features.drop(columns=to_drop)
print("Removed highly correlated columns:", to_drop)


df_clean = features_final.copy()
df_clean.to_csv("cleaned_dataset.csv", index=False)
print("Cleaned dataset shape:", df_clean.shape)


X = df_clean.values
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)




input_dim = X_scaled.shape[1]
encoding_dim = 15

input_layer = Input(shape=(input_dim,))
encoder = Dense(encoding_dim, activation='relu')(input_layer)
decoder = Dense(input_dim, activation='sigmoid')(encoder)

autoencoder = Model(inputs=input_layer, outputs=decoder)

autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae', reconstruction_accuracy])
autoencoder.summary()


early_stopping = EarlyStopping(monitor='val_loss', patience=20, restore_best_weights=True)


time_history = TimeHistory()




start_time = time.time()
history = autoencoder.fit(X_scaled, X_scaled,
                          epochs=500,
                          batch_size=16,
                          shuffle=True,
                          validation_split=0.2,
                          callbacks=[early_stopping, time_history],
                          verbose=1)
total_training_time = time.time() - start_time
print(f"Total training time: {total_training_time:.2f} seconds")


df_total_time = pd.DataFrame({"TotalTrainingTimeSeconds": [total_training_time]})
df_total_time.to_excel("studentname-regnumber-trainingtime.xlsx", index=False)




epochs = range(1, len(history.history['loss']) + 1)
df_metrics = pd.DataFrame({
    "Epoch": epochs,
    "TrainingLoss": history.history['loss'],
    "ValidationLoss": history.history['val_loss'],
    "TrainingMAE": history.history['mae'],
    "ValidationMAE": history.history['val_mae'],
    "TrainingAccuracy": history.history['reconstruction_accuracy'],
    "ValidationAccuracy": history.history['val_reconstruction_accuracy']
})
print(df_metrics)


with pd.ExcelWriter("studentname-regnumber-trainingmetrics.xlsx") as writer:
    df_metrics.to_excel(writer, sheet_name="All_Metrics", index=False)
    df_accuracy = pd.DataFrame({
         "Epoch": epochs,
         "TrainingAccuracy": history.history['reconstruction_accuracy'],
         "ValidationAccuracy": history.history['val_reconstruction_accuracy']
    })
    df_accuracy.to_excel(writer, sheet_name="Accuracy", index=False)




df_time = pd.DataFrame({
    "Epoch": epochs,
    "EpochTimeSeconds": time_history.times,
    "CumulativeTimeSeconds": time_history.cumulative_times
})
df_time.to_excel("studentname-regnumber-epochtime.xlsx", index=False)






plt.figure(figsize=(10, 6))
plt.plot(epochs, history.history['reconstruction_accuracy'], label="Training Accuracy")
plt.plot(epochs, history.history['val_reconstruction_accuracy'], label="Validation Accuracy")
plt.xlabel("Epoch")
plt.ylabel("Reconstruction Accuracy")
plt.title("Training and Validation Accuracy vs Epochs")
plt.legend()
plt.savefig("studentname-regnumber-accuracygraph.jpeg")
plt.show()


plt.figure(figsize=(10, 6))
plt.plot(epochs, history.history['loss'], label="Training Loss")
plt.plot(epochs, history.history['val_loss'], label="Validation Loss")
plt.xlabel("Epoch")
plt.ylabel("Loss (MSE)")
plt.title("Training and Validation Loss vs Epochs")
plt.legend()
plt.savefig("studentname-regnumberlossgraph.jpeg")
plt.show()


plt.figure(figsize=(10, 6))
plt.plot(epochs, history.history['mae'], label="Training MAE")
plt.plot(epochs, history.history['val_mae'], label="Validation MAE")
plt.xlabel("Epoch")
plt.ylabel("Mean Absolute Error")
plt.title("Training and Validation MAE vs Epochs")
plt.legend()
plt.savefig("studentname-regnumber-maegraph.jpeg")
plt.show()





encoder_model = Model(inputs=input_layer, outputs=encoder)

encoder_output = encoder_model.predict(X_scaled)

decoder_output = autoencoder.predict(X_scaled)


plt.figure(figsize=(10, 6))
plt.hist(encoder_output.flatten(), bins=30, color='skyblue', edgecolor='black')
plt.title("Distribution of Encoder Layer Output")
plt.xlabel("Activation Value")
plt.ylabel("Frequency")
plt.savefig("studentname-regnumber-encoderoutput.jpeg")
plt.show()


plt.figure(figsize=(10, 6))
plt.hist(decoder_output.flatten(), bins=30, color='salmon', edgecolor='black')
plt.title("Distribution of Decoder Layer Output")
plt.xlabel("Activation Value")
plt.ylabel("Frequency")
plt.savefig("studentname-regnumber-decoderoutput.jpeg")
plt.show()




encoder_model.save("encoder_model.h5")
print("Encoder model saved as 'encoder_model.h5'")


import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             matthews_corrcoef, confusion_matrix, roc_curve, auc)
import warnings
warnings.filterwarnings("ignore")




encoder_model = load_model("encoder_model.h5")
print("Loaded encoder model.")





df_test = pd.read_csv("test.csv").iloc[:100000, :]
target_col = df_test.columns[-1]
y_test = df_test[target_col].values



df_clean = pd.read_csv("cleaned_dataset.csv")
training_feature_columns = df_clean.columns  



df_test_features = df_test.drop(columns=[target_col])
X_test = df_test_features[training_feature_columns]


scaler = MinMaxScaler()
X_test_scaled = scaler.fit_transform(X_test)




X_test_encoded = encoder_model.predict(X_test_scaled)
print("Encoded test data shape:", X_test_encoded.shape)




sample_indices = np.random.choice(X_test_encoded.shape[0], size=100, replace=False)
sample_encoded = X_test_encoded[sample_indices, :]


df_encoded = pd.DataFrame(sample_encoded, columns=[f"Feature_{i+1}" for i in range(sample_encoded.shape[1])])
plt.figure(figsize=(12, 8))

for index, row in df_encoded.iterrows():
    plt.plot(range(1, sample_encoded.shape[1] + 1), row.values, marker='o', alpha=0.6)
plt.xlabel("Feature Index")
plt.ylabel("Encoded Value")
plt.title("Encoded Features for 100 Sampled Test Inputs")
plt.xticks(range(1, sample_encoded.shape[1] + 1))
plt.savefig("studentname-regnumber-encodedfeatures.jpeg")
plt.show()




kernels = ['linear', 'poly', 'rbf', 'sigmoid']
svm_results = {}  


predictions_df = pd.DataFrame()


test_times = []

for kernel in kernels:
    print(f"\nTraining SVM with kernel: {kernel}")
    svm_model = SVC(kernel=kernel, probability=True)
    
    start_train = time.time()
    svm_model.fit(X_test_encoded, y_test)
    svm_train_time = time.time() - start_train
    print(f"SVM training time with {kernel} kernel: {svm_train_time:.4f} seconds")
    
    
    predictions = []
    individual_times = []
    for i in range(X_test_encoded.shape[0]):
        x_input = X_test_encoded[i].reshape(1, -1)
        start_pred = time.time()
        pred = svm_model.predict(x_input)[0]
        end_pred = time.time()
        predictions.append(pred)
        individual_times.append(end_pred - start_pred)
    avg_test_time = np.mean(individual_times)
    test_times.extend(individual_times)
    
    
    misclassified = sum(1 for actual, pred in zip(y_test, predictions) if actual != pred)
    print(f"For kernel '{kernel}': Misclassified {misclassified} out of {len(y_test)} samples")
    
    
    predictions_df[f"{kernel}_Actual"] = y_test
    predictions_df[f"{kernel}_Predicted"] = predictions
    
    
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)
    mcc = matthews_corrcoef(y_test, predictions)
    cm = confusion_matrix(y_test, predictions)
    
    svm_results[kernel] = {
        "TrainingTime": svm_train_time,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1Score": f1,
        "MCC": mcc,
        "ConfusionMatrix": cm,
        "AvgPredictionTime": avg_test_time
    }
    
    
    print(f"Metrics for kernel '{kernel}':")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-Score: {f1:.4f}")
    print(f"  MCC: {mcc:.4f}")
    print("  Confusion Matrix:")
    print(cm)
    print(f"  Average Prediction Time per sample: {avg_test_time*1000:.4f} ms")
    
    
    if len(np.unique(y_test)) == 2:
        
        probas = svm_model.predict_proba(X_test_encoded)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, probas)
        roc_auc = auc(fpr, tpr)
        plt.figure(figsize=(8,6))
        plt.plot(fpr, tpr, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0,1], [0,1], 'k--')
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title(f"ROC Curve for SVM with {kernel} kernel")
        plt.legend(loc="lower right")
        plt.savefig(f"studentname-regnumber-rocgraph_{kernel}.jpeg")
        plt.show()


predictions_df.to_excel("studentname-regnumber-prediction.xlsx", index=False)
print("Predictions saved to 'studentname-regnumber-prediction.xlsx'.")


svm_metrics_list = []
for kernel, metrics in svm_results.items():
    svm_metrics_list.append({
        "Kernel": kernel,
        "TrainingTime": metrics["TrainingTime"],
        "Accuracy": metrics["Accuracy"],
        "Precision": metrics["Precision"],
        "Recall": metrics["Recall"],
        "F1Score": metrics["F1Score"],
        "MCC": metrics["MCC"],
        "AvgPredictionTime": metrics["AvgPredictionTime"]
    })
df_svm_metrics = pd.DataFrame(svm_metrics_list)
df_svm_metrics.to_excel("studentname-regnumber-svmmetrics.xlsx", index=False)
print("SVM metrics saved to 'studentname-regnumber-svmmetrics.xlsx'.")


df_test_times = pd.DataFrame({"PredictionTimeSeconds": test_times})
df_test_times.loc["Average"] = df_test_times.mean()
df_test_times.to_excel("studentname-regnumber-testingtime.xlsx", index=False)
print("Testing times saved to 'studentname-regnumber-testingtime.xlsx'.")
