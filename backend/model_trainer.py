import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from feature_extraction import URLFeatureExtractor
import os

# 1. Generate a synthetic dataset for the prototype
# In a real-world scenario, you would use a large dataset of actual phishing and legitimate URLs.
def generate_synthetic_data(num_samples=1000):
    np.random.seed(42)
    data = []
    labels = []
    
    # Generate Legitimate feature distributions
    for _ in range(num_samples // 2):
        feat = {
            'url_length': int(np.random.normal(30, 10)),
            'domain_length': int(np.random.normal(12, 4)),
            'has_ip': 0,
            'count_at': 0,
            'path_length': int(np.random.normal(10, 5)),
            'count_params': 0 if np.random.rand() > 0.5 else 1,
            'entropy': float(np.random.uniform(2.5, 4.0)),
            'domain_hyphens': 0 if np.random.rand() > 0.8 else 1,
            'has_https': 1 if np.random.rand() > 0.1 else 0, # 90% have https
            'num_subdomains': 0 if np.random.rand() > 0.3 else 1 # 70% have 0 subdomains
        }
        data.append(feat)
        labels.append(0) # 0 = Legitimate
        
    # Generate Phishing feature distributions
    for _ in range(num_samples // 2):
        feat = {
            'url_length': int(np.random.normal(80, 20)),
            'domain_length': int(np.random.normal(25, 8)),
            'has_ip': 1 if np.random.rand() > 0.7 else 0, # 30% have IP
            'count_at': 1 if np.random.rand() > 0.8 else 0, # 20% have @
            'path_length': int(np.random.normal(30, 15)),
            'count_params': int(np.random.normal(3, 2)),
            'entropy': float(np.random.uniform(3.8, 5.5)),
            'domain_hyphens': int(np.random.normal(2, 1)),
            'has_https': 1 if np.random.rand() > 0.6 else 0, # 40% have https
            'num_subdomains': int(np.random.normal(3, 1))
        }
        # ensure no negatives
        feat = {k: max(0, v) for k, v in feat.items()}
        data.append(feat)
        labels.append(1) # 1 = Phishing
        
    df = pd.DataFrame(data)
    df['label'] = labels
    return df

def train_model():
    print("Generating synthetic dataset...")
    df = generate_synthetic_data(2000)
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training RandomForest Classifier...")
    # Balanced weights to ensure good sensitivity to both classes
    clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)
    
    score = clf.score(X_test, y_test)
    print(f"Model trained. Test Accuracy: {score*100:.2f}%")
    
    # Save the model
    os.makedirs(os.path.dirname(os.path.abspath(__file__)), exist_ok=True)
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(clf, f)
    print(f"Model saved to {model_path}")
    
    # Save a reference to feature columns so API knows exact order
    feature_cols_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'features.pkl')
    with open(feature_cols_path, 'wb') as f:
        pickle.dump(list(X.columns), f)
        
if __name__ == "__main__":
    train_model()