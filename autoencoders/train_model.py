# Train Model on Dataset and export it to .pb (Portobuf file)
import tensorflow as tf
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.models import Model
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

data = pd.read_csv('../data.csv')

scaler = StandardScaler()
scaled_data = scaler.fit_transform(data)

X_train, X_test = train_test_split(scaled_data, test_size=0.2, random_state=67)

# Input Layer
input_layer = Input(shape=(7,))

# Encoder Layers
encoder = tf.keras.Sequential([
    tf.keras.layers.Dense(4, activation='relu'),
    tf.keras.layers.Dense(2, activation='relu')])(input_layer)
# Decoder Layers
decoder = tf.keras.Sequential([
    tf.keras.layers.Dense(4, activation='relu'),
    tf.keras.layers.Dense(7, activation='relu')])(encoder)

auto_encoder = tf.keras.Model(inputs=input_layer, outputs=decoder)

auto_encoder.compile(optimizer='adam', loss='mae')
history = auto_encoder.fit(X_train, X_train,
                           epochs=20,
                           batch_size=64,
                           validation_data=(X_test, X_test),
                           shuffle=True)
# for predict anomalies/outliers in the training dataset
prediction = auto_encoder.predict(X_test)
# for get the mean absolute error between actual and reconstruction/prediction
prediction_loss = tf.keras.losses.mae(prediction, X_test)
# for check the prediction loss threshold for 2% of outliers
loss_threshold = np.percentile(prediction_loss, 98)
print(f'The prediction loss threshold for 2% of outliers is {loss_threshold:.2f}')
# for visualize the threshold
sns.histplot(prediction_loss, bins=30, alpha=0.8)
plt.axvline(x=loss_threshold, color='orange')
plt.show()
