import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import f1_score, recall_score, accuracy_score
from sklearn.model_selection import train_test_split
from utils.train_model import train_model
import shap

# Load and clean data
df = pd.read_csv('processed_web_traffic.csv')
# Remove columns with lists/dicts, convert object columns to float if possible
for col in df.columns:
    if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
        df.drop(columns=[col], inplace=True)
for col in df.select_dtypes(include='object').columns:
    try:
        df[col] = df[col].astype(float)
    except:
        pass

# Train model and get stats
model, f1, shap_values, feature_importance = train_model(df)
features = list(feature_importance.keys())
X = df[features]
y = df['classification'].map({'benign':0, 'malicious':1})
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
y_pred = model.predict(X_test)

# F1 Score
f1_val = f1_score(y_test, y_pred)
plt.figure(figsize=(4,2))
plt.bar(['F1 Score'], [f1_val], color='#fda085')
plt.ylim(0,1)
plt.title('F1 Score')
plt.show()

# Recall
recall_val = recall_score(y_test, y_pred)
plt.figure(figsize=(4,2))
plt.bar(['Recall'], [recall_val], color='#f6d365')
plt.ylim(0,1)
plt.title('Recall')
plt.show()

# Accuracy
acc_val = accuracy_score(y_test, y_pred)
plt.figure(figsize=(4,2))
plt.bar(['Accuracy'], [acc_val], color='#a47d97')
plt.ylim(0,1)
plt.title('Accuracy')
plt.show()

# Correlation heatmap
plt.figure(figsize=(8,6))
corr = df.corr(numeric_only=True)
sns.heatmap(corr, cmap='coolwarm', annot=False)
plt.title('Feature Correlation Heatmap')
plt.tight_layout()
plt.show()

# Overfitting plot (Train vs Test Accuracy)
train_acc = accuracy_score(y_train, model.predict(X_train))
test_acc = accuracy_score(y_test, y_pred)
plt.figure(figsize=(4,2))
plt.bar(['Train','Test'], [train_acc, test_acc], color=['#f6d365','#fda085'])
plt.ylim(0,1)
plt.title('Overfitting (Train vs Test Accuracy)')
plt.show()

# Feature importance
plt.figure(figsize=(8,4))
fi_sorted = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
plt.bar([f[0] for f in fi_sorted], [f[1] for f in fi_sorted], color='#fda085')
plt.xticks(rotation=90)
plt.title('Feature Importance')
plt.tight_layout()
plt.show()



# SHAP summary plot (no plt.figure, add data check)
if hasattr(model, 'named_steps') and 'preprocessor' in model.named_steps:
    preprocessor = model.named_steps['preprocessor']
    if hasattr(preprocessor, 'get_feature_names_out'):
        feature_names = preprocessor.get_feature_names_out()
    else:
        feature_names = [f'feature_{i}' for i in range(shap_values.data.shape[1])]
else:
    feature_names = [f'feature_{i}' for i in range(shap_values.data.shape[1])]

if hasattr(shap_values, 'values') and hasattr(shap_values, 'data') and shap_values.values.size > 0 and shap_values.data.size > 0:
    shap.summary_plot(shap_values.values, shap_values.data, feature_names=feature_names, show=True)
else:
    print("SHAP values or data are empty. Cannot plot summary.")
