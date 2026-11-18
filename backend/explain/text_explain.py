# text_explain.py — Top TF-IDF token explainability
# Returns top N words that contributed most to the phishing prediction

import numpy as np

def get_top_phishing_words(text, tfidf, model, top_n=5):
    """
    Returns top N words from the email that most strongly
    indicate phishing based on LR coefficients.
    """
    # Transform text
    tfidf_vector = tfidf.transform([text])
    
    # Get feature names and coefficients
    feature_names = np.array(tfidf.get_feature_names_out())
    coefficients  = model.coef_[0]
    
    # Get non-zero features in this email
    nonzero_indices = tfidf_vector.nonzero()[1]
    
    if len(nonzero_indices) == 0:
        return []
    
    # Score = tfidf weight * lr coefficient
    scores = []
    for idx in nonzero_indices:
        score = tfidf_vector[0, idx] * coefficients[idx]
        scores.append((feature_names[idx], float(score)))
    
    # Sort by score descending and return top N
    scores.sort(key=lambda x: x[1], reverse=True)
    
    return [word for word, score in scores[:top_n]]