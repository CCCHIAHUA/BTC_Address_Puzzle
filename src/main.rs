// main.rs

use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use bs58;
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::{Arc, Mutex}; // <--- MODIFIED: 引入 Mutex
use std::time::{Instant, Duration};
use hex;
use num_cpus;
use ctrlc;
use clap::Parser;
use std::collections::HashSet;
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};
use bloomfilter::Bloom;
use num_bigint::{BigUint, ToBigUint};
use num::traits::Zero;
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;

const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
];

#[derive(Parser, Clone)]
#[command(author, version, about = "一个用于从文件中搜索目标P2PKH地址的比特币私钥查找器")]
struct Args {
    #[arg(long, default_value = "target_addresses.tsv", help = "包含目标P2PKH地址的TSV文件")]
    target_file: String,

    #[arg(long, default_value = "found.tsv", help = "用于保存找到的匹配项的输出文件")]
    output_file: String,

    #[arg(long, help = "（可选）用于存储所有生成的私钥、公钥和地址以供验证的文件")]
    test_file: Option<String>,

    #[arg(long, help = "要使用的线程数（默认：CPU核心数）")]
    threads: Option<usize>,

    #[arg(long, help = "（可选）十六进制私钥范围 (例如, 111111:ffffff)")]
    range: Option<String>,
}

fn format_with_commas(number: u64) -> String {
    let s = number.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().rev().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }
    result.chars().rev().collect()
}

fn format_float_with_commas(number: f64) -> String {
    let s = format!("{:.2}", number);
    let parts: Vec<String> = s.split('.').map(String::from).collect();
    if parts.len() != 2 {
        return s;
    }
    let integer_part = parts[0].parse::<u64>().unwrap_or(0);
    format!("{}.{}", format_with_commas(integer_part), parts[1])
}

fn parse_range(range: &str, curve_order: &BigUint) -> Result<(BigUint, BigUint), String> {
    let parts: Vec<&str> = range.split(':').collect();
    if parts.len() != 2 {
        return Err("范围必须是 'start:end' 格式".to_string());
    }
    let start = BigUint::parse_bytes(parts[0].trim().as_bytes(), 16)
        .ok_or("范围中的起始值无效".to_string())?;
    let end = BigUint::parse_bytes(parts[1].trim().as_bytes(), 16)
        .ok_or("范围中的结束值无效".to_string())?;
    if start.is_zero() {
        return Err("起始值必须至少为1".to_string());
    }
    if &start > &end {
        return Err("起始值不能大于结束值".to_string());
    }
    if &end >= curve_order {
        return Err("结束值必须小于曲线的阶".to_string());
    }
    Ok((start, end))
}

fn is_valid_p2pkh_address(address: &str) -> Option<Vec<u8>> {
    let decoded = bs58::decode(address).into_vec().ok()?;
    if decoded.len() != 25 || decoded[0] != 0x00 {
        return None;
    }
    let payload = &decoded[0..21];
    let checksum = &decoded[21..25];
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let sha256_1 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(&sha256_1);
    let sha256_2 = hasher.finalize();
    let calculated_checksum = &sha256_2[..4];
    if checksum == calculated_checksum {
        Some(decoded[1..21].to_vec())
    } else {
        None
    }
}

fn load_targets(file_path: &str) -> Result<(HashSet<Vec<u8>>, HashSet<String>, Bloom<Vec<u8>>), String> {
    let start_time = Instant::now();
    let file = File::open(file_path).map_err(|e| format!("无法打开目标文件: {}", e))?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines()
        .map(|l| l.map_err(|e| format!("无法读取行: {}", e)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e)?;
    if lines.is_empty() {
        return Err("输入文件为空".to_string());
    }

    let valid_count = Arc::new(AtomicU64::new(0));
    let pb = ProgressBar::new(lines.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})")
            .unwrap()
    );
    lines.par_iter().for_each(|address| {
        if is_valid_p2pkh_address(address.trim()).is_some() {
            valid_count.fetch_add(1, Ordering::Relaxed);
        }
        pb.inc(1);
    });
    let valid_count = valid_count.load(Ordering::SeqCst);
    if valid_count == 0 {
        return Err("在输入文件中没有找到有效的P2PKH地址".to_string());
    }
    pb.finish_with_message("地址验证完成");

    let mut bloom = Bloom::new_for_fp_rate(valid_count.max(1) as usize, 0.001)
        .map_err(|e| format!("无法创建Bloom filter: {:?}", e))?;
    let results: Vec<(Vec<u8>, String)> = lines.par_iter()
        .filter_map(|address| {
            let address = address.trim();
            is_valid_p2pkh_address(address).map(|ripemd160| (ripemd160, address.to_string()))
        })
        .collect();
    let mut ripemd160_set = HashSet::with_capacity(results.len());
    let mut address_set = HashSet::with_capacity(results.len());
    for (ripemd160, address) in results {
        bloom.set(&ripemd160);
        ripemd160_set.insert(ripemd160);
        address_set.insert(address);
    }
    
    println!("有效地址数: {}, 总行数: {}, 加载耗时: {:.2}s", 
        valid_count, 
        lines.len(), 
        start_time.elapsed().as_secs_f64());
    Ok((ripemd160_set, address_set, bloom))
}

fn generate_address_from_pubkey(public_key: &PublicKey) -> (Vec<u8>, String) {
    let pubkey_bytes = public_key.serialize();
    let mut sha256 = Sha256::new();
    sha256.update(&pubkey_bytes);
    let sha256_result = sha256.finalize();
    
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(&sha256_result);
    let ripemd160_result = ripemd160.finalize();
    let mut extended_ripemd160 = Vec::with_capacity(25);
    extended_ripemd160.push(0x00);
    extended_ripemd160.extend_from_slice(&ripemd160_result);
    
    let mut sha256 = Sha256::new();
    sha256.update(&extended_ripemd160);
    let sha256_1 = sha256.finalize();
    let mut sha256 = Sha256::new();
    sha256.update(&sha256_1);
    let checksum = &sha256.finalize()[..4];
    
    extended_ripemd160.extend_from_slice(checksum);
    let address = bs58::encode(&extended_ripemd160).into_string();
    (ripemd160_result.to_vec(), address)
}

fn save_result(private_key_bytes: &[u8], public_key_bytes: &[u8], address: &str, output_file: &str) -> bool {
    let mut file = match OpenOptions::new().append(true).create(true).open(output_file) {
        Ok(f) => f,
        Err(e) => {
            println!("无法打开结果文件 {}: {}", output_file, e);
            return false;
        }
    };
    let content = format!(
        "{}\t{}\t{}\n",
        hex::encode(private_key_bytes),
        hex::encode(public_key_bytes),
        address
    );
    file.write_all(content.as_bytes()).is_ok()
}

fn biguint_to_32_bytes(b: &BigUint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let biguint_bytes = b.to_bytes_be();
    if biguint_bytes.len() > 32 {
        panic!("BigUint太大，无法放入32字节数组");
    }
    let offset = 32 - biguint_bytes.len();
    bytes[offset..].copy_from_slice(&biguint_bytes);
    bytes
}

/// 在指定范围内随机搜索的函数
// <--- MODIFIED: 更新函数签名 --->
fn search_range(
    args: Args, 
    ripemd160_set: Arc<HashSet<Vec<u8>>>, 
    address_set: Arc<HashSet<String>>, 
    bloom: Arc<Bloom<Vec<u8>>>, 
    total_checked: Arc<AtomicU64>, 
    stop: Arc<AtomicBool>,
    test_file_tx: Option<Sender<String>>,
    last_reseed_time: Arc<Mutex<Instant>>,
    reseed_count: Arc<AtomicU64>,
) {
    let num_threads = args.threads.unwrap_or_else(num_cpus::get);
    let curve_order = BigUint::from_bytes_be(&CURVE_ORDER);
    let (start_key, end_key) = parse_range(&args.range.clone().unwrap(), &curve_order).expect("无效的范围");
    
    let total_keys_in_range = &end_key - &start_key;
    let keys_per_thread = &total_keys_in_range / num_threads.to_biguint().unwrap();
    
    println!("正在以 {} 个线程启动范围内的【随机】搜索...", num_threads);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap()
        .install(|| {
            (0..num_threads).into_par_iter().for_each(|i| {
                let secp = Secp256k1::new();
                let mut rng = rand::rng();
                let thread_tx = test_file_tx.clone();
                const RESEED_INTERVAL: Duration = Duration::from_secs(15 * 60); // 15分钟

                let thread_start_key = &start_key + i.to_biguint().unwrap() * &keys_per_thread;
                let thread_end_key = if i == num_threads - 1 {
                    end_key.clone()
                } else {
                    &thread_start_key + &keys_per_thread
                };

                while !stop.load(Ordering::Relaxed) {
                    // <--- MODIFIED: 检查并重新获取熵的逻辑 --->
                    let needs_reseed = {
                        let last_reseed = last_reseed_time.lock().unwrap();
                        last_reseed.elapsed() >= RESEED_INTERVAL
                    };

                    if needs_reseed {
                        let mut last_reseed = last_reseed_time.lock().unwrap();
                        if last_reseed.elapsed() >= RESEED_INTERVAL {
                            rng = rand::rng(); // 重新获取熵
                            *last_reseed = Instant::now(); // 更新全局时间戳
                            let count = reseed_count.fetch_add(1, Ordering::Relaxed);
                            println!("\n熵已重新获取！总次数: {}", count + 1);
                        }
                    }
                    // <--- MODIFIED: 逻辑结束 --->

                    let range = &thread_end_key - &thread_start_key;
            
                    let required_bytes = (range.bits() as usize + 7) / 8;
                    let mut bytes = vec![0u8; required_bytes];
                    let current_privkey_biguint;
                    loop {
                        rng.fill_bytes(&mut bytes);
                        let mut num = BigUint::from_bytes_be(&bytes);
                        if num < range {
                            num += &thread_start_key;
                            current_privkey_biguint = num;
                            break;
                        }
                    }

                    let privkey_bytes = biguint_to_32_bytes(&current_privkey_biguint);
                    let secret_key = match SecretKey::from_byte_array(privkey_bytes) {
                        Ok(key) => key,
                        Err(_) => continue,
                    };
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

                    let (ripemd160, address) = generate_address_from_pubkey(&public_key);
                    if let Some(tx) = &thread_tx {
                        let pubkey_bytes = public_key.serialize();
                        let content = format!(
                            "{}\t{}\t{}\n",
                            hex::encode(&privkey_bytes),
                            hex::encode(&pubkey_bytes),
                            address
                        );
                        let _ = tx.send(content);
                    }

                    if bloom.check(&ripemd160) {
                        if ripemd160_set.contains(&ripemd160) && address_set.contains(&address) {
                            stop.store(true, Ordering::SeqCst);
                            let pubkey_bytes = public_key.serialize();
                            if save_result(&privkey_bytes, &pubkey_bytes, &address, &args.output_file) {
                                println!("\n找到匹配地址: {}", address);
                                println!("私钥: {}", hex::encode(&privkey_bytes));
                                println!("公钥: {}", hex::encode(&pubkey_bytes));
                            }
                        }
                    }
                    total_checked.fetch_add(1, Ordering::Relaxed);
                }
            });
        });
}


/// 全范围随机搜索函数
// <--- MODIFIED: 更新函数签名 --->
fn search_random(
    args: Args, 
    ripemd160_set: Arc<HashSet<Vec<u8>>>, 
    address_set: Arc<HashSet<String>>, 
    bloom: Arc<Bloom<Vec<u8>>>, 
    total_checked: Arc<AtomicU64>, 
    stop: Arc<AtomicBool>,
    test_file_tx: Option<Sender<String>>,
    last_reseed_time: Arc<Mutex<Instant>>,
    reseed_count: Arc<AtomicU64>,
) {
    let num_threads = args.threads.unwrap_or_else(num_cpus::get);
    println!("正在以 {} 个线程启动全范围随机搜索...", num_threads);
    
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap()
        .install(|| {
            (0..num_threads).into_par_iter().for_each(|_| {
                let secp = Secp256k1::new();
                let mut rng = rand::rng();
                let mut privkey_bytes = [0u8; 32];
                let thread_tx = test_file_tx.clone();
                const RESEED_INTERVAL: Duration = Duration::from_secs(15 * 60); // 15分钟
                
                while !stop.load(Ordering::SeqCst) {
                    // <--- MODIFIED: 检查并重新获取熵的逻辑 --->
                    let needs_reseed = {
                        let last_reseed = last_reseed_time.lock().unwrap();
                        last_reseed.elapsed() >= RESEED_INTERVAL
                    };

                    if needs_reseed {
                        let mut last_reseed = last_reseed_time.lock().unwrap();
                        if last_reseed.elapsed() >= RESEED_INTERVAL {
                            rng = rand::rng(); // 重新获取熵
                            *last_reseed = Instant::now(); // 更新全局时间戳
                            let count = reseed_count.fetch_add(1, Ordering::Relaxed);
                            println!("\n熵已重新获取！总次数: {}", count + 1);
                        }
                    }
                    // <--- MODIFIED: 逻辑结束 --->
                    
                    if stop.load(Ordering::Relaxed) { break; }
                    
                    rng.fill_bytes(&mut privkey_bytes);
                    
                    let secret_key = match SecretKey::from_byte_array(privkey_bytes) {
                        Ok(key) => key,
                        Err(_) => continue,
                    };
                    
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    let (ripemd160, address) = generate_address_from_pubkey(&public_key);
                    if let Some(tx) = &thread_tx {
                        let pubkey_bytes = public_key.serialize();
                        let content = format!(
                            "{}\t{}\t{}\n",
                            hex::encode(&privkey_bytes),
                            hex::encode(&pubkey_bytes),
                            address
                        );
                        let _ = tx.send(content);
                    }

                    if bloom.check(&ripemd160) {
                        if ripemd160_set.contains(&ripemd160) && address_set.contains(&address) {
                            stop.store(true, Ordering::SeqCst);
                            let pubkey_bytes = public_key.serialize();
                            if save_result(&privkey_bytes, &pubkey_bytes, &address, &args.output_file) {
                                println!("\n找到匹配地址: {}", address);
                                println!("私钥: {}", hex::encode(&privkey_bytes));
                                println!("公钥: {}", hex::encode(&pubkey_bytes));
                                return;
                            }
                        }
                    }
                    
                    total_checked.fetch_add(1, Ordering::Relaxed);
                }
            });
        });
}


fn main() {
    let args = Args::parse();
    let start_time = Instant::now();
    let (ripemd160_set, address_set, bloom) = match load_targets(&args.target_file) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("加载目标地址时出错: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("从 {} 加载了 {} 个目标地址, 耗时: {:.2}s", 
        args.target_file, 
        address_set.len(), 
        start_time.elapsed().as_secs_f64());
    println!("地址加载完成，即将开始生成和比对比特币地址...");
    
    let total_checked = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // <--- MODIFIED: 初始化计时器和计数器 --->
    let last_reseed_time = Arc::new(Mutex::new(Instant::now()));
    let reseed_count = Arc::new(AtomicU64::new(0));
    
    let progress_stop = stop.clone();
    let progress_checked = total_checked.clone();
    let progress_thread = std::thread::spawn(move || {
        let mut last_checked = 0;
        let mut last_time = Instant::now();
        while !progress_stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
            let current_checked = progress_checked.load(Ordering::SeqCst);
            let elapsed_sec = last_time.elapsed().as_secs_f64();
            if elapsed_sec > 0.0 {
                let speed = (current_checked.saturating_sub(last_checked)) as f64 / elapsed_sec;
                print!("\r已检查密钥总数: {} | 速度: {} keys/s ", 
                    format_with_commas(current_checked), 
                    format_float_with_commas(speed));
                io::stdout().flush().unwrap();
            }
            last_checked = current_checked;
            last_time = Instant::now();
        }
    });
    let stop_clone = stop.clone();
    let total_checked_clone = total_checked.clone();
    let start_time_clone = start_time;
    ctrlc::set_handler(move || {
        stop_clone.store(true, Ordering::SeqCst);
        println!("\n接收到 Ctrl+C 信号，正在关闭...");
        std::thread::sleep(Duration::from_millis(200)); 
        
        let elapsed = start_time_clone.elapsed().as_secs_f64();
        let checked = total_checked_clone.load(Ordering::SeqCst);
        let speed = if elapsed > 0.0 { checked as f64 / elapsed } else { 0.0 };
        
        println!("\n已检查密钥总数: {}", format_with_commas(checked));
        println!("平均速度: {:.2} keys/s", speed);
        println!("总耗时: {:.2} 秒", elapsed);
        
        std::process::exit(0);
    }).expect("设置 Ctrl-C 处理器时出错");

    let ripemd160_set_arc = Arc::new(ripemd160_set);
    let address_set_arc = Arc::new(address_set);
    let bloom_arc = Arc::new(bloom);
    
    let mut test_file_tx: Option<Sender<String>> = None;
    let mut writer_handle: Option<JoinHandle<()>> = None;

    if let Some(test_path) = args.test_file.clone() {
        println!("\n警告：已启用 --test-file。所有生成的密钥将被写入 {}，这会严重影响性能。", test_path);
        let (tx, rx) = mpsc::channel::<String>();
        test_file_tx = Some(tx);
        
        writer_handle = Some(std::thread::spawn(move || {
            let mut file = File::create(&test_path).expect("无法创建 test_file");
            for received in rx {
                if file.write_all(received.as_bytes()).is_err() {
                    eprintln!("写入到 {} 失败", test_path);
                    break;
                }
            }
        }));
    }

    if args.range.is_some() {
        println!("正在指定范围内进行【随机】搜索...");
        // <--- MODIFIED: 传递新参数 --->
        search_range(args, ripemd160_set_arc, address_set_arc, bloom_arc, total_checked.clone(), stop.clone(), test_file_tx, last_reseed_time.clone(), reseed_count.clone());
    } else {
        println!("正在全范围（随机）搜索私钥...");
        // <--- MODIFIED: 传递新参数 --->
        search_random(args, ripemd160_set_arc, address_set_arc, bloom_arc, total_checked.clone(), stop.clone(), test_file_tx, last_reseed_time.clone(), reseed_count.clone());
    }
    
    stop.store(true, Ordering::SeqCst);
    progress_thread.join().unwrap();
    
    if let Some(handle) = writer_handle {
        println!("\n正在等待将所有数据写入 test_file...");
        handle.join().unwrap();
        println!("test_file 写入完成。");
    }
    
    let elapsed = start_time.elapsed().as_secs_f64();
    let checked = total_checked.load(Ordering::SeqCst);
    let speed = if elapsed > 0.0 { checked as f64 / elapsed } else { 0.0 };
    
    println!("\n\n搜索完成。");

    // <--- MODIFIED: 打印重新获取熵的次数 --->
    let final_reseed_count = reseed_count.load(Ordering::SeqCst);
    println!("熵已重新获取 {} 次。", final_reseed_count);

    println!("已检查密钥总数: {}", format_with_commas(checked));
    println!("平均速度: {} keys/s", format_float_with_commas(speed));
    println!("总耗时: {:.2} 秒", elapsed);
}