use core::time;
use std::{
    collections::HashMap,
    env,
    error::Error,
    fs::File,
    ops::Range,
    sync::{Arc, Mutex},
    thread::{self, available_parallelism},
};

use zip::ZipArchive;

type ResultsQueue = Vec<(u64, u32)>;

// we know that flag is printable so we can reject anything that have byte value not in [0x20;0x80]
fn to_bytes(n: u64, bytes_num: u32) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut n = n;

    for _ in 0..bytes_num {
        let byte = (n & 0xFF) as u8;
        if byte < 0x20 || byte > 0x80 {
            return None;
        }
        bytes.push(byte);
        n >>= 8;
    }

    Some(bytes)
}

fn worker(bytes_num: u32, range: Range<u64>, results: Arc<Mutex<ResultsQueue>>, crcs: Vec<u32>) {
    for n in range {
        if let Some(bytes) = to_bytes(n, bytes_num) {
            let crc = crc32fast::hash(&*bytes);

            for &_crc in crcs.iter() {
                if _crc == crc {
                    println!("{crc:#x} = {n:#x}");
                    let mut out_q = results.lock().unwrap();
                    out_q.push((n, crc));
                }
            }
        }
    }
}

fn prepare_chunks(max_number: u64) -> Vec<Range<u64>> {
    let default_parallelism_approx = available_parallelism().unwrap().get() as u64;
    // let default_parallelism_approx = cmp::max(1, default_parallelism_approx - 1);
    let chunk = max_number / default_parallelism_approx;
    let mut results: Vec<Range<u64>> = Vec::new();

    for idx in 0..default_parallelism_approx {
        let start = idx * chunk;
        let end = if idx == default_parallelism_approx - 1 {
            max_number
        } else {
            (idx + 1) * chunk
        };

        results.push(start..end)
    }

    results
}

fn brute_crc32(bytes_to_brute: u32, crcs: &Vec<u32>) -> Vec<(u32, String)> {
    let max_number = u64::pow(256, bytes_to_brute);
    let chunks = prepare_chunks(max_number);
    let queue: ResultsQueue = Vec::new();
    let arc_queue = Arc::new(Mutex::new(queue.clone()));

    for range in chunks {
        let q_clone = Arc::clone(&arc_queue);
        let c = crcs.clone();
        thread::spawn(move || {
            worker(bytes_to_brute, range.clone(), q_clone, c);
        });
    }

    loop {
        let qlen = {
            let q = arc_queue.lock().unwrap();
            q.len()
        };

        if qlen == crcs.len() {
            break;
        }

        time::Duration::from_millis(100);
    }

    let q = arc_queue.lock().unwrap();
    q.iter()
        .map(|&(n, crc)| {
            (
                crc,
                String::from_utf8(to_bytes(n, bytes_to_brute).unwrap()).unwrap(),
            )
        })
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let zippath = env::args().nth(1).expect("no parameter provided");
    println!("zippath: {zippath}");

    let file = File::open(zippath)?;
    let mut archive = ZipArchive::new(file)?;

    let crcs: Vec<(u32, u32)> = (0..archive.len())
        .map(|idx| {
            let zipfile = archive
                .by_index_raw(idx)
                .expect(format!("unable to read file {idx}").as_str());
            let orig_len = zipfile.size() as u32;
            let crc = zipfile.crc32();
            (orig_len, crc)
        })
        .collect();

    let mut brute_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut crc_to_idx: HashMap<u32, u64> = HashMap::new();
    let mut idx = 0;
    for (orig_len, crc) in crcs {
        println!("orig_len: {orig_len}, crc: {crc:#x}");

        brute_map.entry(orig_len).or_default().push(crc);
        crc_to_idx.insert(crc, idx);
        idx += 1;
    }

    let mut flag_parts: Vec<(u64, String)> = Vec::new();
    for (orig_len, values) in brute_map {
        println!("Bruteforcing crc for n={orig_len}");
        let results = brute_crc32(orig_len, &values);

        for (crc, chunk) in results {
            let &idx = crc_to_idx.get(&crc).unwrap();
            flag_parts.push((idx, chunk));
        }
    }

    flag_parts.sort_by_key(|(idx, _)| *idx);
    let flag_chunks: Vec<String> = flag_parts.iter().map(|(_, chunk)| chunk.clone()).collect();
    let flag = flag_chunks.join("");
    println!("{flag}");

    Ok(())
}
