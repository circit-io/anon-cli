use crate::crypto::CohortKey;
use crate::policy::Policy;
use crate::sql_adapter::transform_csv;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchResult {
    pub rows_generated: usize,
    pub rows_processed: usize,
    pub elapsed_secs: f64,
    pub rows_per_sec: f64,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub throughput_mbps: f64,
}

pub fn generate_csv(path: &Path, rows: usize) -> std::io::Result<usize> {
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "customer_id,account_number,amount,currency,date,description,balance")?;
    let mut id = 0u64;
    for _ in 0..rows {
        id += 1;
        let cust = format!("cust-{id}");
        let acct = format!("ACC{id:010}");
        let amount = format!("{id}.{:02}", id % 100);
        let balance = format!("{}.00", id * 10);
        let date = format!("2026-{:02}-{:02}", (id % 12) + 1, (id % 28) + 1);
        let desc = if id.is_multiple_of(7) {
            "transaction note".to_string()
        } else {
            String::new()
        };
        writeln!(file, "{cust},{acct},{amount},USD,{date},{desc},{balance}")?;
    }
    file.flush()?;
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.len() as usize)
}

pub fn run_csv_bench(
    rows: usize,
    policy: &Policy,
    key: &CohortKey,
    tmpdir: &Path,
) -> anyhow::Result<BenchResult> {
    let input = tmpdir.join("bench_input.csv");
    let output = tmpdir.join("bench_output.csv");

    let input_bytes = generate_csv(&input, rows)?;

    let start = Instant::now();
    let report = transform_csv(&input, &output, policy, key)?;
    let elapsed = start.elapsed();

    let output_bytes = std::fs::metadata(&output)?.len() as usize;
    let elapsed_secs = elapsed.as_secs_f64();
    let rows_per_sec = if elapsed_secs > 0.0 {
        report.rows_processed as f64 / elapsed_secs
    } else {
        0.0
    };
    let throughput_mbps = if elapsed_secs > 0.0 {
        (input_bytes as f64 / 1_048_576.0) / elapsed_secs
    } else {
        0.0
    };

    Ok(BenchResult {
        rows_generated: rows,
        rows_processed: report.rows_processed,
        elapsed_secs,
        rows_per_sec,
        input_bytes,
        output_bytes,
        throughput_mbps,
    })
}

pub fn run_batched_bench(
    total_rows: usize,
    batch_size: usize,
    policy: &Policy,
    key: &CohortKey,
    tmpdir: &Path,
) -> anyhow::Result<Vec<BenchResult>> {
    let batches = total_rows.div_ceil(batch_size);
    let mut results = Vec::with_capacity(batches);

    for i in 0..batches {
        let rows_in_batch = batch_size.min(total_rows - i * batch_size);
        let batch_dir = tmpdir.join(format!("batch_{i}"));
        std::fs::create_dir_all(&batch_dir)?;
        let result = run_csv_bench(rows_in_batch, policy, key, &batch_dir)?;
        results.push(result);
    }

    Ok(results)
}
