use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub estimate: f64,
    pub upper: f64,
}

#[must_use]
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

#[must_use]
pub fn bootstrap_median_95(values: &[f64], iterations: usize, seed: u64) -> ConfidenceInterval {
    if values.is_empty() {
        return ConfidenceInterval {
            lower: f64::NAN,
            estimate: f64::NAN,
            upper: f64::NAN,
        };
    }
    if values.len() == 1 || iterations < 2 {
        let value = values[0];
        return ConfidenceInterval {
            lower: value,
            estimate: value,
            upper: value,
        };
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut resampled = Vec::with_capacity(iterations);
    let mut sample = Vec::with_capacity(values.len());
    for _ in 0..iterations {
        sample.clear();
        for _ in 0..values.len() {
            sample.push(values[rng.gen_range(0..values.len())]);
        }
        resampled.push(median(&sample));
    }
    resampled.sort_by(f64::total_cmp);
    let last = resampled.len() - 1;
    let lower = resampled[((last as f64 * 0.025).floor() as usize).min(last)];
    let upper = resampled[((last as f64 * 0.975).ceil() as usize).min(last)];
    ConfidenceInterval {
        lower,
        estimate: median(values),
        upper,
    }
}

#[must_use]
pub fn coefficient_of_variation(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| {
            let difference = value - mean;
            difference * difference
        })
        .sum::<f64>()
        / (values.len() - 1) as f64;
    variance.sqrt() / mean.abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_handles_odd_even_and_empty_inputs() {
        assert!(median(&[]).is_nan());
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
    }

    #[test]
    fn bootstrap_is_deterministic_and_contains_estimate() {
        let interval = bootstrap_median_95(&[0.97, 0.98, 0.99, 1.0, 1.01], 2_000, 7);
        assert!(interval.lower <= interval.estimate);
        assert!(interval.estimate <= interval.upper);
        assert_eq!(
            interval,
            bootstrap_median_95(&[0.97, 0.98, 0.99, 1.0, 1.01], 2_000, 7)
        );
    }

    #[test]
    fn coefficient_of_variation_reports_relative_spread() {
        assert_eq!(coefficient_of_variation(&[10.0]), 0.0);
        assert!(coefficient_of_variation(&[99.0, 100.0, 101.0]) < 0.02);
    }
}
