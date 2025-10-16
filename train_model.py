import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib

print("Starting training...")

# Load the CSV with features and label
data = pd.read_csv('training_data.csv')

# Features are all columns except 'label'
X = data.drop('label', axis=1)
y = data['label']

# Split into train and test sets (80/20)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and fit the scaler on training data
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)

# Create and train the model on scaled data
model = DecisionTreeClassifier(random_state=42)
model.fit(X_train_scaled, y_train)

# Scale the test data using the same scaler
X_test_scaled = scaler.transform(X_test)

# Predict on test set
y_pred = model.predict(X_test_scaled)

# Show classification report
print(classification_report(y_test, y_pred))

# Save the trained scaler and model to disk
joblib.dump(scaler, 'ddos_scaler.pkl')
joblib.dump(model, 'ddos_model.pkl')

print("Model and scaler saved as 'ddos_model.pkl' and 'ddos_scaler.pkl'")