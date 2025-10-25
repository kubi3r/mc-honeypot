use tokio::io::{Error, AsyncRead, AsyncReadExt};

pub async fn read_varint<T: AsyncRead + Unpin>(byte_iter: &mut T) -> Result<(i32, i32), Error> {
    let mut value: i32 = 0;
    let mut bytes_read = 0;

    loop {
        let current_byte = byte_iter.read_u8().await?;
        
        value |= ((current_byte & 0x7F) as i32) << (bytes_read * 7);

        bytes_read += 1;

        if (current_byte & 0x80) == 0 {
            break
        }

        if bytes_read * 7 >= 32 {
            return Err(Error::other("varint too big"))
        }
    }

    Ok((value, bytes_read))
}

pub fn write_varint(num: i32) -> Vec<u8> {
    let mut bytes = Vec::new();

    let mut num = num as u32;
    loop {
        if num & 0xffffff80 == 0 {
            bytes.push(num as u8);
            break
        }

        bytes.push(num as u8 | 0x80);
        num >>= 7;
    }
    bytes
}


pub async fn read_string<T: AsyncRead + Unpin>(byte_iter: &mut T) -> Result<(String, i32), Error> {   
    let mut output = String::new();
    let mut total_bytes_consumed = 0;

    let (string_len, bytes_consumed) = read_varint(byte_iter).await?;
    total_bytes_consumed += bytes_consumed;

    for _ in 0..string_len {
        let current_byte = byte_iter.read_u8().await?;
        total_bytes_consumed += 1;

        output.push(current_byte as char);
    }

    Ok((output, total_bytes_consumed))
}

pub fn prefix_str_len(string: &str) -> Vec<u8> {
    [&write_varint(string.len().try_into().unwrap()), string.as_bytes()].concat()
}

pub async fn send_webhook(message: String, webhook_url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    client.post(webhook_url)
        .json(&serde_json::json!({"content": message}))
        .send().await?;
    Ok(())
}