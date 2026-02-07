import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

from xgboost import XGBClassifier
df = pd.read_csv("/content/drive/MyDrive/Train_dos_dataSet/train.csv")
FEATURES = [
    'flow_duration', 'Rate', 'Srate', 'Drate',
    'Protocol Type', 'Header_Length',
    'syn_flag_number', 'fin_flag_number', 'rst_flag_number',
    'Tot size', 'Std', 'Variance'
]

X = df[FEATURES]
y = df['label']
le = LabelEncoder()
y_encoded = le.fit_transform(y)
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)
xgb_model = XGBClassifier(
    objective='multi:softmax',   # multi-class classification
    num_class=len(np.unique(y_encoded)),
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric='mlogloss'
)
xgb_model.fit(X_train, y_train)
y_pred = xgb_model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred, target_names=le.classes_))
sample = X_test.iloc[0].values.reshape(1, -1)
pred = xgb_model.predict(sample)

print("Predicted Attack Type:", le.inverse_transform(pred)[0])
import joblib
joblib.dump(xgb_model, "dos_xgboost_model3.pkl")
joblib.dump(le, "label_encoder3.pkl")
