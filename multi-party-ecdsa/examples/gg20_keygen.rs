use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, LocalKey};
use round_based::async_runtime::AsyncProtocol;
use curv::elliptic::curves::secp256_k1::{Secp256k1};
use curv::elliptic::curves::{Point};
use sha3::{Digest, Keccak256};

mod gg20_sm_client;
use gg20_sm_client::{join_computation, SmClient};
use bs58;
use ripemd::{Ripemd160};
use sha2::Digest as Sha256Digest;




#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long)]
    output: PathBuf,

    #[structopt(short, long)]
    index: u16,
    #[structopt(short, long)]
    threshold: u16,
    #[structopt(short, long)]
    number_of_parties: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)
        .await
        .context("cannot create output file")?;
    let address = args.address.clone();
    let room = args.room.as_str();
    let client = SmClient::new(address, &room).context("construct SmClient")?;
    let (_i, incoming, outgoing) = join_computation(&client, args.address, room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;
    
    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    let local_key = serde_json::from_slice::<LocalKey<Secp256k1>>(&output)
        .context("deserialize output")?;
    let public_key = local_key.public_key();
    let address = public_key_to_eth_address(&public_key);
    println!("address: {}", address);

    tokio::io::copy(&mut output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;

    Ok(())
}

pub fn public_key_to_eth_address(public_key: &Point<Secp256k1>) -> String {
    let key_bytes = public_key.to_bytes(false);
    // 0x34c6bd7fca4742c735ac7bba940bf5447b7c51dd
    // 0x34c6bd7FcA4742c735AC7Bba940Bf5447b7c51dD
    let mut hasher = Keccak256::new();
    hasher.update(&key_bytes[1..]); // 移除首字节
    let result = hasher.finalize();
    
    // 从 Vec<u8> 转换为十六进制字符串
    let eth_address = &result[12..32];
    format!("0x{}", hex::encode(eth_address))
}

// 将 Secp256k1 公钥转换为 Bitcoin 地址
pub fn public_key_to_btc_address(public_key: &Point<Secp256k1>) -> String {
    // 1. 获取公钥字节
    let key_bytes = public_key.to_bytes(false); // 未压缩格式
    
    // 2. SHA-256 哈希
    let sha256_hash = sha2::Sha256::digest(&key_bytes);
    
    // 3. RIPEMD-160 哈希
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    
    // 4. 添加版本前缀 (0x00 表示主网)
    let mut with_version = vec![0x00];
    with_version.extend_from_slice(&ripemd160_hash);
    
    // 5. 计算校验和 (两次 SHA-256，取前 4 字节)
    let checksum = sha2::Sha256::digest(
        &sha2::Sha256::digest(&with_version)
    )[..4].to_vec();
    
    // 6. 添加校验和
    with_version.extend_from_slice(&checksum);
    
    // 7. Base58Check 编码
    bs58::encode(with_version).into_string()
}