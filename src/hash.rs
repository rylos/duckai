use crate::Result;
use crate::error::Error::HashError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn get_hex(s: &str) -> isize {
    let t = if let Some(i) = s.chars().position(|c| c == '(') {
        &s[i + 3..s.len() - 1]
    } else {
        s
    };
    isize::from_str_radix(t, 16).unwrap()
}

fn compute_sha256_base64(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    BASE64_STANDARD.encode(hash)
}

pub fn gen_request_hash(hash: &str) -> Result<String> {
    // let hash = "";
    let decoded_bytes = BASE64_STANDARD
        .decode(hash.as_bytes())
        .expect("invalid base64");
    let decoded_str = String::from_utf8(decoded_bytes).expect("invalid utf-8");
    // dbg!(&decoded_str);

    let capture = |pat: &str| {
        Regex::new(pat)
            .unwrap()
            .captures(&decoded_str)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str())
    };

    let string_array: Vec<&str> = capture(r"=\[([^\]]*)\]")
        .ok_or_else(|| HashError("string array not found"))?
        .split(',')
        .map(|s| s.trim_matches('\''))
        .collect();

    let offset = capture(r"0x([[:alnum:]]+);let").ok_or_else(|| HashError("offset not found"))?;
    let offset = isize::from_str_radix(offset, 16).map_err(|_| HashError("offset error"))?;

    let mut shift_offset = None;

    let find_offset = |pat, target: &'static str| {
        let index = get_hex(pat);
        let origin_index = string_array.iter().position(|&s| s == target).unwrap() as isize;
        origin_index - (index - offset)
    };

    if shift_offset.is_none() {
        let doc_pat = capture(r"document\[[^(]*\(0x([[:alnum:]]+)\)\]");
        // dbg!(doc_pat);
        if let Some(pat) = doc_pat {
            shift_offset = Some(find_offset(pat, "createElement"));
        }
    }

    if shift_offset.is_none() {
        let user_agent_pat = capture(r"'client_hashes':\[navigator\[[^(]*\(0x([[:alnum:]]+)\)\]");
        // dbg!(user_agent_pat);
        if let Some(pat) = user_agent_pat {
            shift_offset = Some(find_offset(pat, "userAgent"));
        }
    }

    if shift_offset.is_none() {
        let div_pat = capture(r"0x([[:alnum:]]+)\)\);return\s");
        // dbg!(div_pat);
        if let Some(pat) = div_pat {
            shift_offset = Some(find_offset(pat, "div"));
        }
    }

    let shift_offset = shift_offset.ok_or_else(|| HashError("shift offset not found"))?;
    // dbg!(shift_offset);

    let mut server_hashes = vec![None, None];

    let server_hash_pats = Regex::new(r"'server_hashes':\[([^,]+),([^]]+)\]")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| {
            let a = cap.get(1).map(|s| s.as_str());
            let b = cap.get(2).map(|s| s.as_str());
            a.zip(b).map(|(a, b)| vec![a, b])
        })
        .ok_or_else(|| HashError("server hash pats not found"))?;
    // dbg!(&server_hash_pats);

    let resolve_value = |pat: &str| {
        if pat.starts_with('\'') {
            pat.trim_matches('\'').to_owned()
        } else {
            let index = get_hex(pat);
            let array_len = string_array.len() as isize;
            let origin_index = (index - offset + shift_offset).rem_euclid(array_len);
            string_array[origin_index as usize].to_owned()
        }
    };

    for (i, pat) in server_hash_pats.iter().enumerate() {
        server_hashes[i] = Some(resolve_value(pat));
    }
    // dbg!(&server_hashes);

    let innerhtml_pat =
        capture(r"=([^,;]+),String").ok_or_else(|| HashError("inner html pattern not found"))?;
    let innerhtml = resolve_value(innerhtml_pat);
    // dbg!(innerhtml);

    let inner_html_data: HashMap<&str, i32> = HashMap::from([
        ("<div><div></div><div></div", 99),
        ("<p><div></p><p></div", 128),
        ("<br><div></br><br></div", 92),
        ("<li><div></li><li></div", 87),
    ]);

    let inner_html_len = inner_html_data
        .get(innerhtml.as_str())
        .ok_or_else(|| HashError("unknown inner html pattern"))?;

    let extracted_number = capture(r"String\(0x([[:alnum:]]+)\+")
        .ok_or_else(|| HashError("extracted number not found"))?;
    let extracted_number = i32::from_str_radix(extracted_number, 16)
        .map_err(|_| HashError("extracted number parsing error"))?;
    // dbg!(extracted_number);

    let user_agent_hash = compute_sha256_base64(crate::client::USER_AGENT);
    // dbg!(extracted_number + inner_html_len);
    let number_hash = compute_sha256_base64(&(extracted_number + inner_html_len).to_string());

    let challenge_id_pat =
        capture(r"'challenge_id':([^},]+)").ok_or_else(|| HashError("challenge id not found"))?;
    let challenge_id = resolve_value(challenge_id_pat);
    // dbg!(challenge_id);

    let timestamp_pat =
        capture(r"'timestamp':([^},]+)").ok_or_else(|| HashError("timestamp not found"))?;
    let timestamp = resolve_value(timestamp_pat);
    // dbg!(timestamp);

    let result_json = serde_json::json!({
        "server_hashes": server_hashes,
        "client_hashes": [user_agent_hash, number_hash],
        "signals": {},
        "meta": {
            "v": "3",
            "challenge_id": challenge_id,
            "timestamp": timestamp,
            "origin":"https://duckduckgo.com",
            "stack":"@https://duckduckgo.com/dist/wpm.chat.4a9875a416a3b5ff84e8.js:1:59965"
        }
    });
    // dbg!(result_json.to_string());

    Ok(BASE64_STANDARD.encode(result_json.to_string()))
}
