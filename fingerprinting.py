import sys

import numpy as np
import pandas as pd
import sklearn.metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold


def classify(train_features, train_labels, test_features, test_labels):
    """Function to perform classification, using a
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier(n_estimators=300)
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    predictions_prob = clf.predict_proba(test_features)

    return predictions, predictions_prob, clf.feature_importances_, clf.score(test_features, test_labels)


def perform_crossval(features, labels, folds=10):
    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    num_features = len(features[0])
    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    # Scores
    accuracy = []
    f1 = []
    top_2_accuracy = []
    top_3_accuracy = []
    top_5_accuracy = []

    feature_importance_list = []
    for i in range(num_features):
        feature_importance_list.append([])

    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions, predictions_prob, importance, score = classify(X_train, y_train, X_test, y_test)
        # Evaluate performance
        accuracy.append(sklearn.metrics.accuracy_score(y_test, predictions))
        f1.append(sklearn.metrics.f1_score(y_test, predictions, average='weighted'))
        top_2_accuracy.append(sklearn.metrics.top_k_accuracy_score(y_test, predictions_prob))
        top_3_accuracy.append(sklearn.metrics.top_k_accuracy_score(y_test, predictions_prob, k=3))
        top_5_accuracy.append(sklearn.metrics.top_k_accuracy_score(y_test, predictions_prob, k=5))
        for i in range(num_features):
            feature_importance_list[i].append(importance[i])

    return accuracy, f1, top_2_accuracy, top_3_accuracy, top_5_accuracy, feature_importance_list


def load_data():
    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    features = []
    labels = []

    df = pd.read_csv('part_3/features.csv')
    for row in df.iterrows():
        features_list = row[1][1:].tolist()
        features.append([float(feature) for feature in features_list])
        labels.append(int(row[1][0]))

    return features, labels


def main():
    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    accuracy, f1, top_2_accuracy, top_3_accuracy, top_5_accuracy, feature_importance_list = perform_crossval(features,
                                                                                                             labels,
                                                                                                             folds=10)

    accuracy_mean = np.mean(accuracy)
    accuracy_std = np.std(accuracy)
    f1_mean = np.mean(f1)
    f1_std = np.std(f1)
    top_2_accuracy_mean = np.mean(top_2_accuracy)
    top_2_accuracy_std = np.std(top_2_accuracy)
    top_3_accuracy_mean = np.mean(top_3_accuracy)
    top_3_accuracy_std = np.std(top_3_accuracy)
    top_5_accuracy_mean = np.mean(top_5_accuracy)
    top_5_accuracy_std = np.std(top_5_accuracy)
    feature_importance_means = []
    for i in range(len(features[0])):
        feature_importance_means.append(round(np.mean(feature_importance_list[i]), 2))

    accuracy_result = "Accuracy: %0.2f (+/- %0.2f)\n" % (accuracy_mean, accuracy_std)
    f1_result = "F1: %0.2f (+/- %0.2f)\n" % (f1_mean, f1_std)
    top_2_accuracy_result = "Top 2: %0.2f (+/- %0.2f)\n" % (top_2_accuracy_mean, top_2_accuracy_std)
    top_3_accuracy_result = "Top 3: %0.2f (+/- %0.2f)\n" % (top_3_accuracy_mean, top_3_accuracy_std)
    top_5_accuracy_result = "Top 5: %0.2f (+/- %0.2f)\n" % (top_5_accuracy_mean, top_5_accuracy_std)
    importance_means_result = "Mean importance per feature: " + str(feature_importance_means)

    with open('part_3/fingerprinting_result.txt', 'wt', newline='') as output_file:
        output_file.writelines(
            [accuracy_result, f1_result, top_2_accuracy_result, top_3_accuracy_result, top_5_accuracy_result,
             importance_means_result])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
