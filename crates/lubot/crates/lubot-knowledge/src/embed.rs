//! Dependency-free TF-IDF embedding - turns text into numeric vectors and
//! searches by cosine similarity, without needing an external vector API. The
//! closed-circuit principle: embedding runs locally and no data leaves the
//! machine.
//!
//! The stopword list below keeps Turkish words on purpose: the corpus this
//! index reads is bilingual, and dropping the Turkish function words is what
//! the list is for. The same goes for the Turkish fixtures in the tests, which
//! measure that the tokenizer handles them.

use std::collections::{BTreeMap, BTreeSet};

/// A vector is a dimensioned array of `f64`.
pub type EmbeddingVector = Vec<f64>;

/// Frequent English and Turkish words (they reduce the embedding noise).
///
/// The Turkish entries are data, not prose: they are the tokens this embedder
/// must recognise in order to serve Turkish documents, so translating them
/// would break the feature the list exists for. They are written without
/// diacritics because the tokeniser folds to ASCII before lookup, and the
/// `tree-is-english` baseline carries this file for that reason rather than as
/// an untranslated comment.
const STOPWORDS: &[&str] = &[
    "the", "is", "in", "it", "of", "and", "or", "to", "a", "an", "for", "on", "with", "as", "at",
    "be", "this", "that", "are", "was", "were", "by", "from", "not", "but", "if", "so", "do", "we",
    "he", "she", "they", "you", "i", "my", "its", "our", "has", "have", "had", "will", "would",
    "can", "could", "may", "should", "all", "no", "than", "when", "then", "bir", "bu", "ve",
    "veya", "icin", "ile", "degil", "ama", "sonra", "gibi", "cok", "daha",
];

/// The default embedding dimension.
pub const DEFAULT_DIMENSIONS: usize = 256;

/// The TF-IDF embedder.
#[derive(Debug, Clone)]
pub struct TfIdfEmbedder {
    dimensions: usize,
    /// The ordered term list (the vocabulary).
    vocab: Vec<String>,
    vocab_index: BTreeMap<String, usize>,
    idf: BTreeMap<String, f64>,
    fitted: bool,
}

impl Default for TfIdfEmbedder {
    fn default() -> Self {
        Self::new(DEFAULT_DIMENSIONS)
    }
}

impl TfIdfEmbedder {
    #[must_use]
    pub fn new(dimensions: usize) -> Self {
        Self {
            dimensions: dimensions.max(8),
            vocab: Vec::new(),
            vocab_index: BTreeMap::new(),
            idf: BTreeMap::new(),
            fitted: false,
        }
    }

    fn tokenize(text: &str) -> Vec<String> {
        let lower = text.to_lowercase();
        lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| t.len() >= 2 && !STOPWORDS.contains(t))
            .map(ToString::to_string)
            .collect()
    }

    /// Build the vocabulary and the IDF weights over a corpus.
    pub fn fit(&mut self, texts: &[String]) {
        if texts.is_empty() {
            return;
        }
        let n_docs = texts.len();
        let mut doc_freq: BTreeMap<String, usize> = BTreeMap::new();
        for text in texts {
            let tokens: BTreeSet<String> = Self::tokenize(text).into_iter().collect();
            for tok in tokens {
                *doc_freq.entry(tok).or_insert(0) += 1;
            }
        }
        // Sort by frequency and keep as many as the dimension allows.
        let mut ranked: Vec<(String, usize)> = doc_freq.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        // `ranked` is still needed below to look up document frequencies, so
        // borrow here instead of consuming it. `into_iter()` moved the vector
        // and the later `ranked.iter()` then failed to compile.
        self.vocab = ranked
            .iter()
            .take(self.dimensions)
            .map(|(t, _)| t.clone())
            .collect();
        self.vocab_index = self
            .vocab
            .iter()
            .enumerate()
            .map(|(i, t)| (t.clone(), i))
            .collect();
        self.idf = self
            .vocab
            .iter()
            .map(|t| {
                let df = ranked
                    .iter()
                    .find(|(term, _)| term == t)
                    .map_or(1, |(_, f)| *f);
                (
                    t.clone(),
                    ((n_docs as f64 + 1.0) / (df as f64 + 1.0)).ln() + 1.0,
                )
            })
            .collect();
        self.fitted = true;
    }

    /// Turn text into a TF-IDF vector (unit-normalised).
    #[must_use]
    pub fn embed(&self, text: &str) -> EmbeddingVector {
        let tokens = Self::tokenize(text);
        if tokens.is_empty() || !self.fitted {
            return vec![0.0; self.dimensions];
        }
        let mut tf: BTreeMap<String, usize> = BTreeMap::new();
        for t in &tokens {
            *tf.entry(t.clone()).or_insert(0) += 1;
        }
        let total = tokens.len() as f64;
        let mut vec = vec![0.0; self.dimensions];
        for (term, count) in tf {
            if let Some(idx) = self.vocab_index.get(&term) {
                let tfidf = (count as f64 / total) * self.idf.get(&term).copied().unwrap_or(1.0);
                vec[*idx] = tfidf;
            }
        }
        unit_normalize(&mut vec);
        vec
    }

    /// The cosine similarity of two vectors.
    #[must_use]
    pub fn cosine_similarity(a: &EmbeddingVector, b: &EmbeddingVector) -> f64 {
        if a.len() != b.len() {
            return 0.0;
        }
        let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
        let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
        if na == 0.0 || nb == 0.0 {
            return 0.0;
        }
        dot / (na * nb)
    }

    /// Returns the `k` items closest to the query vector, as (id, score).
    #[must_use]
    pub fn top_k_similar(
        &self,
        query_vec: &EmbeddingVector,
        corpus: &[(String, EmbeddingVector)],
        k: usize,
    ) -> Vec<(String, f64)> {
        let mut scored: Vec<(String, f64)> = corpus
            .iter()
            .map(|(id, vec)| (id.clone(), Self::cosine_similarity(query_vec, vec)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        scored
    }

    #[must_use]
    pub fn is_fitted(&self) -> bool {
        self.fitted
    }

    #[must_use]
    pub fn vocabulary_size(&self) -> usize {
        self.vocab.len()
    }
}

fn unit_normalize(vec: &mut [f64]) {
    let norm: f64 = vec.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for v in vec.iter_mut() {
            *v /= norm;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similar_texts_score_higher() {
        let mut e = TfIdfEmbedder::new(64);
        let corpus = vec![
            "erasure coding storage shard parity".to_string(),
            "consensus finality validator block".to_string(),
            "erasure recovery repair bandwidth".to_string(),
        ];
        e.fit(&corpus);
        let query = e.embed("erasure shard recovery storage");
        let items: Vec<(String, EmbeddingVector)> = corpus
            .iter()
            .enumerate()
            .map(|(i, t)| (i.to_string(), e.embed(t)))
            .collect();
        let top = e.top_k_similar(&query, &items, 3);
        // The ones mentioning erasure have to come out on top.
        assert_eq!(top[0].0, "0");
        assert_eq!(top[1].0, "2");
    }

    #[test]
    fn deterministic_embeddings() {
        let mut e = TfIdfEmbedder::new(32);
        e.fit(&[
            "budlum storage layer".to_string(),
            "lubot inference".to_string(),
        ]);
        assert_eq!(e.embed("budlum depolama"), e.embed("budlum depolama"));
    }

    #[test]
    fn empty_text_yields_zero_vector() {
        let e = TfIdfEmbedder::new(32);
        assert_eq!(e.embed(""), vec![0.0; 32]);
    }

    #[test]
    fn cosine_zero_for_zero_vectors() {
        // `&[]` is a `&[_; 0]`, while the signature wants an
        // `&EmbeddingVector` (that is, a `&Vec<f64>`).
        let empty: EmbeddingVector = Vec::new();
        assert_eq!(TfIdfEmbedder::cosine_similarity(&empty, &empty), 0.0);
        let zero = vec![0.0; 8];
        assert_eq!(TfIdfEmbedder::cosine_similarity(&zero, &zero), 0.0);
    }

    #[test]
    fn tokenize_filters_stopwords() {
        let tokens = TfIdfEmbedder::tokenize("The quick brown fox and the lazy dog");
        assert!(!tokens.contains(&"the".to_string()));
        assert!(tokens.contains(&"quick".to_string()));
    }
}
