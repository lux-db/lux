use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

#[derive(Clone)]
struct HnswNode {
    // Unit-normalized vector used by HNSW. The store keeps the original vector
    // for VGET; the index only needs cosine ordering.
    vector: Vec<f32>,
    connections: Vec<Vec<String>>,
}

pub struct HnswIndex {
    nodes: HashMap<String, HnswNode>,
    entry_point: Option<String>,
    max_layer: usize,
    ef_construction: usize,
    m: usize,
    m_max0: usize,
    dims: u32,
    /// Per-index random state used for HNSW layer selection.
    rng_state: u64,
}

#[derive(PartialEq)]
struct Candidate<'a> {
    similarity: ordered_float::OrderedFloat<f32>,
    key: &'a str,
}

impl Eq for Candidate<'_> {}

impl PartialOrd for Candidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.similarity.cmp(&other.similarity)
    }
}

impl HnswIndex {
    pub fn new(dims: u32) -> Self {
        Self {
            nodes: HashMap::new(),
            entry_point: None,
            max_layer: 0,
            ef_construction: 64,
            m: 12,
            m_max0: 24,
            dims,
            rng_state: 0,
        }
    }

    fn xorshift_random(&mut self) -> f64 {
        if self.rng_state == 0 {
            self.rng_state = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            if self.rng_state == 0 {
                self.rng_state = 1;
            }
        }
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        (self.rng_state as f64) / (u64::MAX as f64)
    }

    fn random_level(&mut self) -> usize {
        let mut level = 0;
        let ml = 1.0 / (self.m as f64).ln();
        while self.xorshift_random() < (-1.0 / ml).exp() && level < 16 {
            level += 1;
        }
        level
    }

    fn max_connections(&self, layer: usize) -> usize {
        if layer == 0 {
            self.m_max0
        } else {
            self.m
        }
    }

    fn search_layer<'a>(
        &'a self,
        query: &[f32],
        entry_key: &'a str,
        ef: usize,
        layer: usize,
    ) -> Vec<(&'a str, f32)> {
        let entry_node = match self.nodes.get(entry_key) {
            Some(n) => n,
            None => return Vec::new(),
        };
        let entry_sim = cosine_unit_similarity(query, &entry_node.vector);

        let mut visited = HashSet::new();
        visited.insert(entry_key);

        let mut candidates: BinaryHeap<Candidate> = BinaryHeap::new();
        let mut results: BinaryHeap<Reverse<Candidate>> = BinaryHeap::new();

        candidates.push(Candidate {
            similarity: ordered_float::OrderedFloat(entry_sim),
            key: entry_key,
        });
        results.push(Reverse(Candidate {
            similarity: ordered_float::OrderedFloat(entry_sim),
            key: entry_key,
        }));

        while let Some(current) = candidates.pop() {
            let worst_result = results
                .peek()
                .map(|r| r.0.similarity)
                .unwrap_or(ordered_float::OrderedFloat(f32::NEG_INFINITY));
            if current.similarity < worst_result && results.len() >= ef {
                break;
            }

            if let Some(node) = self.nodes.get(current.key) {
                let neighbors = if layer < node.connections.len() {
                    &node.connections[layer]
                } else {
                    continue;
                };
                for neighbor_key in neighbors {
                    let neighbor_key = neighbor_key.as_str();
                    if visited.contains(neighbor_key) {
                        continue;
                    }
                    visited.insert(neighbor_key);

                    if let Some(neighbor_node) = self.nodes.get(neighbor_key) {
                        let sim = cosine_unit_similarity(query, &neighbor_node.vector);

                        let worst_result = results
                            .peek()
                            .map(|r| r.0.similarity)
                            .unwrap_or(ordered_float::OrderedFloat(f32::NEG_INFINITY));
                        if results.len() < ef || ordered_float::OrderedFloat(sim) > worst_result {
                            candidates.push(Candidate {
                                similarity: ordered_float::OrderedFloat(sim),
                                key: neighbor_key,
                            });
                            results.push(Reverse(Candidate {
                                similarity: ordered_float::OrderedFloat(sim),
                                key: neighbor_key,
                            }));
                            if results.len() > ef {
                                results.pop();
                            }
                        }
                    }
                }
            }
        }

        results
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse(c)| (c.key, c.similarity.0))
            .collect()
    }

    fn select_neighbors(
        &self,
        _query: &[f32],
        candidates: &[(String, f32)],
        m: usize,
    ) -> Vec<String> {
        let mut sorted: Vec<(String, f32)> = candidates.to_vec();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(m);
        sorted.into_iter().map(|(k, _)| k).collect()
    }

    pub fn insert(&mut self, key: String, vector: Vec<f32>) {
        if self.dims == 0 {
            self.dims = vector.len() as u32;
        } else if self.dims != vector.len() as u32 {
            self.nodes.clear();
            self.entry_point = None;
            self.max_layer = 0;
            self.dims = vector.len() as u32;
        }

        let existed = self.nodes.contains_key(&key);
        if existed {
            self.remove(&key);
        }

        let vector = normalize_vector(vector);
        let level = self.random_level();
        let mut connections = Vec::with_capacity(level + 1);
        for _ in 0..=level {
            connections.push(Vec::new());
        }

        let node = HnswNode {
            vector: vector.clone(),
            connections,
        };
        self.nodes.insert(key.clone(), node);

        if self.entry_point.is_none() {
            self.entry_point = Some(key);
            self.max_layer = level;
            return;
        }

        let entry_point = self.entry_point.clone().unwrap();
        let mut current_entry = entry_point.clone();

        for l in (level + 1..=self.max_layer).rev() {
            let results = self.search_layer(&vector, &current_entry, 1, l);
            if let Some((best, _)) = results.first() {
                current_entry = (*best).to_string();
            }
        }

        let insert_from = std::cmp::min(level, self.max_layer);
        for l in (0..=insert_from).rev() {
            let ef = self.ef_construction;
            let candidates = self.search_layer(&vector, &current_entry, ef, l);
            let next_entry = candidates.first().map(|(best, _)| (*best).to_string());
            let owned_candidates: Vec<(String, f32)> = candidates
                .iter()
                .map(|(key, sim)| ((*key).to_string(), *sim))
                .collect();
            if let Some(best) = next_entry {
                current_entry = best;
            }

            let m = self.max_connections(l);
            let neighbors = self.select_neighbors(&vector, &owned_candidates, m);

            if let Some(node) = self.nodes.get_mut(&key) {
                if l < node.connections.len() {
                    node.connections[l] = neighbors.clone();
                }
            }

            for neighbor_key in &neighbors {
                if let Some(neighbor) = self.nodes.get_mut(neighbor_key) {
                    while neighbor.connections.len() <= l {
                        neighbor.connections.push(Vec::new());
                    }
                    if !neighbor.connections[l].contains(&key) {
                        neighbor.connections[l].push(key.clone());
                    }
                }
            }

            let max_conn = self.max_connections(l);
            let mut to_prune: Vec<(String, Vec<f32>, Vec<String>)> = Vec::new();
            for neighbor_key in &neighbors {
                if let Some(neighbor) = self.nodes.get(neighbor_key) {
                    if l < neighbor.connections.len() && neighbor.connections[l].len() > max_conn {
                        let neighbor_vec = neighbor.vector.clone();
                        let conns = neighbor.connections[l].clone();
                        to_prune.push((neighbor_key.clone(), neighbor_vec, conns));
                    }
                }
            }
            for (nk, nv, conns) in to_prune {
                let conn_with_sim: Vec<(String, f32)> = conns
                    .iter()
                    .filter_map(|k| {
                        self.nodes
                            .get(k)
                            .map(|n| (k.clone(), cosine_unit_similarity(&nv, &n.vector)))
                    })
                    .collect();
                let pruned = self.select_neighbors(&nv, &conn_with_sim, max_conn);
                if let Some(neighbor) = self.nodes.get_mut(&nk) {
                    if l < neighbor.connections.len() {
                        neighbor.connections[l] = pruned;
                    }
                }
            }
        }

        if level > self.max_layer {
            self.entry_point = Some(key);
            self.max_layer = level;
        }
    }

    pub fn remove(&mut self, key: &str) {
        let node = match self.nodes.remove(key) {
            Some(n) => n,
            None => return,
        };

        for (layer, connections) in node.connections.iter().enumerate() {
            for neighbor_key in connections {
                if let Some(neighbor) = self.nodes.get_mut(neighbor_key) {
                    if layer < neighbor.connections.len() {
                        neighbor.connections[layer].retain(|k| k != key);
                    }
                }
            }

            for i in 0..connections.len() {
                for j in (i + 1)..connections.len() {
                    let key_i = &connections[i];
                    let key_j = &connections[j];

                    let should_connect = {
                        if let (Some(ni), Some(nj)) = (self.nodes.get(key_i), self.nodes.get(key_j))
                        {
                            layer < ni.connections.len()
                                && layer < nj.connections.len()
                                && !ni.connections[layer].contains(key_j)
                                && ni.connections[layer].len() < self.max_connections(layer)
                                && nj.connections[layer].len() < self.max_connections(layer)
                        } else {
                            false
                        }
                    };

                    if should_connect {
                        let ki = key_i.clone();
                        let kj = key_j.clone();
                        if let Some(ni) = self.nodes.get_mut(&ki) {
                            if layer < ni.connections.len() {
                                ni.connections[layer].push(kj.clone());
                            }
                        }
                        if let Some(nj) = self.nodes.get_mut(&kj) {
                            if layer < nj.connections.len() {
                                nj.connections[layer].push(ki);
                            }
                        }
                    }
                }
            }
        }

        if self.entry_point.as_deref() == Some(key) {
            if self.nodes.is_empty() {
                self.entry_point = None;
                self.max_layer = 0;
            } else {
                let mut best_key = None;
                let mut best_layer = 0usize;
                for (k, n) in &self.nodes {
                    let node_layer = n.connections.len().saturating_sub(1);
                    if node_layer >= best_layer {
                        best_layer = node_layer;
                        best_key = Some(k.clone());
                    }
                }
                self.entry_point = best_key;
                self.max_layer = best_layer;
            }
        }
    }

    pub fn search(&self, query: &[f32], k: usize) -> Vec<(String, f32)> {
        let entry_point = match &self.entry_point {
            Some(ep) => ep.clone(),
            None => return Vec::new(),
        };
        if self.dims != 0 && self.dims != query.len() as u32 {
            return Vec::new();
        }
        let query = normalize_vector(query.to_vec());

        let mut current_entry = entry_point;

        for l in (1..=self.max_layer).rev() {
            let results = self.search_layer(&query, &current_entry, 1, l);
            if let Some((best, _)) = results.first() {
                current_entry = (*best).to_string();
            }
        }

        let ef = std::cmp::max(k, 10);
        let mut results = self.search_layer(&query, &current_entry, ef, 0);
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(k);
        results
            .into_iter()
            .map(|(key, sim)| (key.to_string(), sim))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[allow(dead_code)]
    pub fn contains(&self, key: &str) -> bool {
        self.nodes.contains_key(key)
    }
}

fn normalize_vector(mut vector: Vec<f32>) -> Vec<f32> {
    let norm_sq = vector.iter().map(|v| v * v).sum::<f32>();
    if norm_sq == 0.0 {
        return vector;
    }
    let inv_norm = norm_sq.sqrt().recip();
    for value in &mut vector {
        *value *= inv_norm;
    }
    vector
}

fn cosine_unit_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_search() {
        let mut index = HnswIndex::new(3);
        index.insert("a".to_string(), vec![1.0, 0.0, 0.0]);
        index.insert("b".to_string(), vec![0.0, 1.0, 0.0]);
        index.insert("c".to_string(), vec![0.9, 0.1, 0.0]);

        let results = index.search(&[1.0, 0.0, 0.0], 2);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "a");
        assert_eq!(results[1].0, "c");
    }

    #[test]
    fn remove_node() {
        let mut index = HnswIndex::new(2);
        index.insert("a".to_string(), vec![1.0, 0.0]);
        index.insert("b".to_string(), vec![0.0, 1.0]);
        index.insert("c".to_string(), vec![0.7, 0.7]);
        assert_eq!(index.len(), 3);

        index.remove("b");
        assert_eq!(index.len(), 2);
        assert!(!index.contains("b"));

        let results = index.search(&[1.0, 0.0], 2);
        assert_eq!(results.len(), 2);
        assert!(!results.iter().any(|(k, _)| k == "b"));
    }

    #[test]
    fn empty_search() {
        let index = HnswIndex::new(3);
        let results = index.search(&[1.0, 0.0, 0.0], 5);
        assert!(results.is_empty());
    }

    #[test]
    fn single_element() {
        let mut index = HnswIndex::new(2);
        index.insert("only".to_string(), vec![1.0, 0.0]);
        let results = index.search(&[0.5, 0.5], 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "only");
    }

    #[test]
    fn overwrite_vector() {
        let mut index = HnswIndex::new(2);
        index.insert("v".to_string(), vec![1.0, 0.0]);
        index.insert("v".to_string(), vec![0.0, 1.0]);
        assert_eq!(index.len(), 1);

        let results = index.search(&[0.0, 1.0], 1);
        assert_eq!(results[0].0, "v");
        assert!(results[0].1 > 0.99);
    }
}
