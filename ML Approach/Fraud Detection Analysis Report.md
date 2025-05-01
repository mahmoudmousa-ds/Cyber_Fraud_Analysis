# Fraud Detection Analysis Report

## Introduction

This report details the process and findings of building a machine learning model to detect potentially fraudulent user connections based on the provided dataset (`enriched_data.xlsx`) and specific compromised identifiers. The primary objective was to identify all connections within the dataset that exhibit characteristics similar to those associated with the known compromised Device ID (`91b12379-8098-457f-a2ad-a94d767797c2`) and Identity hash (`0007f265568f1abc1da791e852877df2047b3af9`).

## Data Overview

The analysis was performed on the `enriched_data.xlsx` file, which contains 1802 connection records. Each record includes 21 attributes, such as `device_id`, `identity`, `bank`, `device_fingerprint`, IP address (`ip`), operating system (`os`), browser information, and location details (`country`, `city`, etc.).

## Methodology

1.  **Compromised Identifier Analysis:** We first identified all connections directly linked to the provided compromised `device_id` or `identity`. This resulted in 79 direct matches (`compromised_connections.csv`). We then extracted associated identifiers like IP addresses and device fingerprints from these compromised connections (`related_identifiers.txt`).

2.  **Feature Engineering:** A target variable, `fraud_label`, was created. Connections directly linked to the compromised identifiers were initially labeled as fraudulent (1), and others as non-fraudulent (0). Additional features were engineered to capture potential links to the compromised activity, specifically:
    *   `shares_compromised_ip`: Indicates if a connection shares an IP address with any of the directly compromised connections.
    *   `shares_compromised_fingerprint`: Indicates if a connection shares a device fingerprint with any of the directly compromised connections.

3.  **Data Preparation:** Categorical features (like `bank`, `os`, `browser`, `country`) were encoded using Label Encoding. Boolean features (`ua_is_mobile`, `ua_is_pc`) were converted to integers. The final feature set included these encoded categorical features, boolean features, and the engineered features (`shares_compromised_ip`, `shares_compromised_fingerprint`), totaling 12 features used for modeling (`prepared_data.csv`). The data was split into training (70%, 1261 records) and testing (30%, 541 records) sets, ensuring stratification based on the `fraud_label` (`train_data.csv`, `test_data.csv`).

4.  **Model Training:** A RandomForestClassifier model was chosen due to its robustness and ability to handle potential non-linear relationships in the data. The model was trained on the prepared training dataset, using balanced class weights to address the inherent imbalance between fraudulent and non-fraudulent samples (`fraud_detection_model.joblib`).

5.  **Model Evaluation:** The trained model was evaluated on the unseen test dataset. Performance metrics were calculated to assess its effectiveness in identifying fraudulent connections.

6.  **Prediction on Full Dataset:** The validated model was then used to predict the likelihood of fraud for all 1802 connections in the original dataset.

## Model Performance

The model demonstrated strong performance on the test set:

*   **Accuracy:** 99.45% - The overall correctness of the model's predictions.
*   **Precision (Fraud Class):** 0.8889 - Out of all connections predicted as fraudulent, 88.89% were actually fraudulent.
*   **Recall (Fraud Class):** 1.0000 - The model successfully identified 100% of the actual fraudulent connections in the test set.
*   **F1-Score (Fraud Class):** 0.9412 - The harmonic mean of precision and recall, indicating excellent balance.
*   **Confusion Matrix:**
    ```
    [[514   3]  <- Predicted Non-Fraud | Actual Non-Fraud (TN), Actual Fraud (FN)
     [  0  24]]  <- Predicted Fraud     | Actual Non-Fraud (FP), Actual Fraud (TP)
    ```
    This shows 514 true negatives, 0 false negatives, 3 false positives, and 24 true positives.



## Findings

Applying the trained model to the entire dataset (1802 connections), we identified **89 connections** as potentially fraudulent (predicted `fraud_label` = 1). These connections exhibit characteristics learned from the initially compromised identifiers and associated patterns (shared IPs, fingerprints, etc.).

The list of these 89 potentially fraudulent connections, including their original details and the model's predicted fraud probability, has been saved to `fraudulent_connection.csv`. Connections are sorted by probability, with the highest probability indicating the strongest suspicion according to the model.

A file containing all original connections along with their predicted fraud label and probability is also available (`all_enriched_data_fraud_labeled.csv.csv`).

## Conclusion and Recommendations

The machine learning model successfully identified connections linked to the compromised identifiers and expanded the search to find other potentially related fraudulent activities based on shared characteristics. The high recall score indicates the model is effective at finding known fraud patterns.

It is recommended to review the connections listed in `fraudulent_connection.csv`, prioritizing those with higher predicted fraud probabilities, to determine appropriate actions.

