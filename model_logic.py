import joblib
import numpy as np

model = joblib.load("dos_xgboost_model2.pkl")
le = joblib.load("label_encoder2.pkl")

FEATURE_ORDER = [
    'flow_duration', 'Rate', 'Srate', 'Drate',
    'Protocol Type', 'Header_Length',
    'syn_flag_number', 'fin_flag_number', 'rst_flag_number',
    'Tot size', 'Std', 'Variance'
]

def classify_warning(feature_dict):

    X = np.array([[feature_dict[f] for f in FEATURE_ORDER]])

    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0].max()

    label = le.inverse_transform([pred])[0]
    return label, prob
