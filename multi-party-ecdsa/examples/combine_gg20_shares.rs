use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::Secp256k1;
use curv::elliptic::curves::{Point, Scalar};
// use curv::elliptic::curves::traits::ECPoint;
// use curv::elliptic::curves::traits::ECScalar;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::BufReader;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <share1.json> <share2.json> [share3.json...]", args[0]);
        return;
    }
    
    // 至少需要两个分片（2-3门限方案）
    let shares: Vec<&String> = args.iter().skip(1).collect();
    if shares.len() < 2 {
        println!("Error: Need at least 2 shares for a 2-3 threshold scheme");
        return;
    }
    
    // 读取并解析所有分片文件
    let mut x_i_values = Vec::new();
    let mut indices = Vec::new();
    let mut vss_scheme: Option<VerifiableSS<Secp256k1>> = None;
    let mut public_key: Option<Point<Secp256k1>> = None;
    
    for share_file in shares.clone() {
        let file = File::open(share_file).expect("Failed to open share file");
        let reader = BufReader::new(file);
        let share: Value = serde_json::from_reader(reader).expect("Failed to parse JSON");
        
        // 提取私钥分片
        let x_i_scalar = &share["keys_linear"]["x_i"]["scalar"].as_array().expect("Invalid JSON format");
        let x_i_bytes: Vec<u8> = x_i_scalar.iter()
            .map(|val| val.as_u64().expect("Invalid scalar value") as u8)
            .collect();
            
        let x_i = Scalar::<Secp256k1>::from_bytes(&x_i_bytes).expect("Failed to convert to Scalar");
        x_i_values.push(x_i);
        
        // 提取索引
        let index = share["i"].as_u64().expect("Invalid or missing index") as u16;
        indices.push(index);
        
        // 提取公钥
        if public_key.is_none() {
            let pk_bytes = &share["keys_linear"]["y"]["point"].as_array().expect("Invalid JSON format");
            let pk_vec: Vec<u8> = pk_bytes.iter()
                .map(|val| val.as_u64().expect("Invalid point value") as u8)
                .collect();
            public_key = Some(Point::<Secp256k1>::from_bytes(&pk_vec).expect("Failed to convert to Point"));
        }
        
        // 提取VSS方案（只需从第一个文件中获取一次）
        if vss_scheme.is_none() {
            if let Some(vss) = share.get("vss_scheme") {
                let params = &vss["parameters"];
                let threshold = params["threshold"].as_u64().expect("Invalid threshold") as usize;
                let share_count = params["share_count"].as_u64().expect("Invalid share count") as usize;
                
                // 解析公开的承诺值
                let commitments = vss["commitments"].as_array().expect("Invalid commitments");
                let mut commitment_points = Vec::new();
                
                for commitment in commitments {
                    let point_bytes = commitment["point"].as_array().expect("Invalid point format");
                    let point_vec: Vec<u8> = point_bytes.iter()
                        .map(|val| val.as_u64().expect("Invalid point value") as u8)
                        .collect();
                    let point = Point::<Secp256k1>::from_bytes(&point_vec).expect("Failed to convert to Point");
                    commitment_points.push(point);
                }
                
                println!("Found VSS scheme with threshold {} of {}", threshold, share_count);
                println!("Commitments count: {}", commitment_points.len());
                
                // 构建VerifiableSS对象
                // 注意：由于完整重构VSS需要更多信息，这里我们使用Lagrange插值法直接计算
                // 而不依赖于VSS对象的重构功能
                // 如果需要使用VSS进行验证，应该提取更多字段
                
                println!("Using Lagrange interpolation for key reconstruction");
                
                // 存储门限值，以便验证是否有足够的分片
                if threshold + 1 > shares.len() {
                    println!("Warning: Need at least {} shares for secure reconstruction, but only {} provided",
                             threshold + 1, shares.len());
                } else {
                    println!("Have sufficient shares ({}) for secure reconstruction (need {})",
                             shares.len(), threshold + 1);
                }
            }
        }
    }
    
    // 使用Lagrange插值重构私钥
    let private_key = reconstruct_secret(&x_i_values, &indices);
    
    // 将私钥转换为十六进制格式
    let private_key_hex = private_key.to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
        
    // 显示结果
    println!("Reconstructed private key: 0x{}", private_key_hex);
    
    // 验证：重新计算公钥并与原始公钥比较
    if let Some(pk) = public_key {
        let calculated_pk = Point::<Secp256k1>::generator() * private_key;
        let matches = calculated_pk == pk;
        
        println!("Public key verification: {}", if matches { "PASSED" } else { "FAILED" });
        
        // 显示公钥
        let pk_hex = pk.to_bytes(false)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        println!("Public key: 0x{}", pk_hex);
        // println!("Ethereum address: {}", public_key_to_eth_address(&pk));
    }
}

// 使用Lagrange插值重构私钥
fn reconstruct_secret(shares: &[Scalar<Secp256k1>], indices: &[u16]) -> Scalar<Secp256k1> {
    if shares.len() != indices.len() {
        panic!("Number of shares must equal number of indices");
    }
    
    let mut result = Scalar::<Secp256k1>::zero();
    
    for (i, share) in shares.iter().enumerate() {
        let mut coef = Scalar::<Secp256k1>::from(1);
        
        for (j, idx_j) in indices.iter().enumerate() {
            if i != j {
                // 计算Lagrange系数：Π(j≠i) (x - x_j) / (x_i - x_j)
                // 其中x=0，我们计算 Π(j≠i) (0 - x_j) / (x_i - x_j) = Π(j≠i) (-x_j) / (x_i - x_j)
                let idx_i = indices[i] as i32;
                let idx_j = *idx_j as i32;
                
                let num = Scalar::<Secp256k1>::from(-idx_j); // -x_j
                let denom = Scalar::<Secp256k1>::from(idx_i - idx_j); // x_i - x_j
                let denom_inv = denom.invert().expect("Failed to invert denominator"); // (x_i - x_j)^-1
                
                coef = coef * num * denom_inv;
            }
        }
        
        // 累加当前分片的贡献
        result = result + share * coef;
    }
    
    result
}