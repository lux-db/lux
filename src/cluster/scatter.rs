#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GlobalScanSpec {
    Keys {
        pattern: Vec<u8>,
    },
    VectorCardinality,
    VectorSearch {
        query: Vec<f32>,
        k: usize,
        filter_key: Option<String>,
        filter_value: Option<String>,
        include_meta: bool,
    },
    TimeSeriesRange {
        from: i64,
        to: i64,
        filters: Vec<(String, String)>,
        aggregation: Option<(String, i64)>,
    },
}

pub(crate) fn global_scan_spec(argv: &[&[u8]]) -> Result<Option<GlobalScanSpec>, String> {
    let Some(command) = argv.first() else {
        return Ok(None);
    };
    if command.eq_ignore_ascii_case(b"KEYS") {
        if argv.len() != 2 {
            return Err("ERR wrong number of arguments for 'keys' command".to_string());
        }
        return Ok(Some(GlobalScanSpec::Keys {
            pattern: argv[1].to_vec(),
        }));
    }
    if command.eq_ignore_ascii_case(b"VCARD") {
        if argv.len() != 1 {
            return Err("ERR wrong number of arguments for 'vcard' command".to_string());
        }
        return Ok(Some(GlobalScanSpec::VectorCardinality));
    }
    if command.eq_ignore_ascii_case(b"VSEARCH") {
        return parse_vector_search(argv).map(Some);
    }
    if command.eq_ignore_ascii_case(b"TSMRANGE") {
        return parse_time_series_range(argv).map(Some);
    }
    Ok(None)
}

fn text<'a>(value: &'a [u8], label: &str) -> Result<&'a str, String> {
    std::str::from_utf8(value).map_err(|_| format!("ERR {label} is not valid UTF-8"))
}

fn parse_vector_search(argv: &[&[u8]]) -> Result<GlobalScanSpec, String> {
    if argv.len() < 4 {
        return Err("ERR wrong number of arguments for 'vsearch' command".to_string());
    }
    let dimensions = text(argv[1], "dimension count")?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "ERR invalid dimension count".to_string())?;
    if argv.len() < 2 + dimensions {
        return Err("ERR not enough float values for specified dimensions".to_string());
    }
    let query = argv[2..2 + dimensions]
        .iter()
        .map(|value| {
            text(value, "vector value")?
                .parse::<f32>()
                .map_err(|_| "ERR value is not a valid float".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut index = 2 + dimensions;
    if argv
        .get(index)
        .is_none_or(|value| !value.eq_ignore_ascii_case(b"K"))
    {
        return Err("ERR missing K parameter".to_string());
    }
    index += 1;
    let k = argv
        .get(index)
        .ok_or_else(|| "ERR missing K value".to_string())
        .and_then(|value| text(value, "K value"))?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "ERR invalid K value".to_string())?;
    index += 1;
    let mut filter_key = None;
    let mut filter_value = None;
    let mut include_meta = false;
    while index < argv.len() {
        if argv[index].eq_ignore_ascii_case(b"FILTER") {
            if index + 2 >= argv.len() {
                return Err("ERR FILTER requires key and value arguments".to_string());
            }
            filter_key = Some(text(argv[index + 1], "filter key")?.to_string());
            filter_value = Some(text(argv[index + 2], "filter value")?.to_string());
            index += 3;
        } else if argv[index].eq_ignore_ascii_case(b"META") {
            include_meta = true;
            index += 1;
        } else {
            return Err("ERR syntax error".to_string());
        }
    }
    Ok(GlobalScanSpec::VectorSearch {
        query,
        k,
        filter_key,
        filter_value,
        include_meta,
    })
}

fn parse_time_series_range(argv: &[&[u8]]) -> Result<GlobalScanSpec, String> {
    if argv.len() < 5 {
        return Err("ERR wrong number of arguments for 'tsmrange' command".to_string());
    }
    let from = if argv[1] == b"-" {
        i64::MIN
    } else {
        text(argv[1], "from timestamp")?
            .parse::<i64>()
            .map_err(|_| "ERR invalid from timestamp".to_string())?
    };
    let to = if argv[2] == b"+" {
        i64::MAX
    } else {
        text(argv[2], "to timestamp")?
            .parse::<i64>()
            .map_err(|_| "ERR invalid to timestamp".to_string())?
    };
    let mut filters = Vec::new();
    let mut aggregation = None;
    let mut index = 3;
    while index < argv.len() {
        if argv[index].eq_ignore_ascii_case(b"FILTER") {
            index += 1;
            while index < argv.len()
                && !argv[index].eq_ignore_ascii_case(b"AGGREGATION")
                && !argv[index].eq_ignore_ascii_case(b"WITHLABELS")
            {
                let filter = text(argv[index], "time-series filter")?;
                let (key, value) = filter
                    .split_once('=')
                    .ok_or_else(|| "ERR time-series filter must be label=value".to_string())?;
                filters.push((key.to_string(), value.to_string()));
                index += 1;
            }
        } else if argv[index].eq_ignore_ascii_case(b"AGGREGATION") {
            if index + 2 >= argv.len() {
                return Err("ERR AGGREGATION requires function and bucket".to_string());
            }
            let function = text(argv[index + 1], "aggregation function")?.to_ascii_lowercase();
            let bucket = text(argv[index + 2], "aggregation bucket")?
                .parse::<i64>()
                .map_err(|_| "ERR invalid aggregation bucket".to_string())?;
            aggregation = Some((function, bucket));
            index += 3;
        } else if argv[index].eq_ignore_ascii_case(b"WITHLABELS") {
            index += 1;
        } else {
            return Err("ERR syntax error".to_string());
        }
    }
    if filters.is_empty() {
        return Err("ERR TSMRANGE requires at least one FILTER".to_string());
    }
    Ok(GlobalScanSpec::TimeSeriesRange {
        from,
        to,
        filters,
        aggregation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_supported_global_reads() {
        assert!(matches!(
            global_scan_spec(&[b"KEYS", b"user:*"]).unwrap(),
            Some(GlobalScanSpec::Keys { .. })
        ));
        assert!(matches!(
            global_scan_spec(&[b"VCARD"]).unwrap(),
            Some(GlobalScanSpec::VectorCardinality)
        ));
        assert!(global_scan_spec(&[b"DBSIZE"]).unwrap().is_none());
        assert!(
            global_scan_spec(&[b"VSEARCH", b"2", b"1", b"0", b"K", b"3"])
                .unwrap()
                .is_some()
        );
        assert!(
            global_scan_spec(&[b"TSMRANGE", b"-", b"+", b"FILTER", b"site=west"])
                .unwrap()
                .is_some()
        );
    }
}
