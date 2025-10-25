use mc_honeypot::{read_varint, write_varint, read_string, prefix_str_len, send_webhook};
use base64::Engine;
use serde_json::{json, Value};
use uuid::Uuid;
use clap::Parser;
use base64::{engine::general_purpose};
use tokio::{fs, net::{TcpListener, TcpStream}, io::{AsyncReadExt, AsyncWriteExt, AsyncRead, Error}};
use std::io::Cursor;

#[derive(Parser, Debug)]
struct Args {
    /// Webhook to send logs to
    #[arg(short, long)]
    webhook: Option<String>,

    /// Path to server icon
    #[arg(short, long)]
    server_icon: Option<String>
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut server_icon = None;
    if let Some(ref icon_path) = args.server_icon {
        let image_bytes = fs::read(icon_path).await.unwrap_or_else(|_| panic!("couldn't find image at {icon_path}"));
        let base64_encoded = general_purpose::STANDARD.encode(image_bytes);

        server_icon = Some(format!("data:image/png;base64,{base64_encoded}"));
    }

    let listener = TcpListener::bind("127.0.0.1:25565").await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();

        let webhook = args.webhook.clone();
        let icon = server_icon.clone();

        tokio::spawn(async move {
            if let Ok(message) = handle_connection(stream, icon).await {
                println!("{message}");

                if let Some(webhook) = webhook
                    && let Err(e) = send_webhook(message, &webhook).await {
                        println!("failed to send messsage to webhook: {e}")
                }
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, server_icon: Option<String>) -> Result<String, Error> {
    let (packet_id, data) = read_packet(&mut stream).await?; // handshake

    if packet_id != 0 {
        return Err(Error::other(""))
    }
    
    match read_handshake(&mut Cursor::new(data)).await? {
        Handshake::Status => {
            let packet_id = read_packet(&mut stream).await?.0; // status request
            if packet_id != 0 {
                return Err(Error::other(""))
            }

            if send_status_resp(&mut stream, server_icon).await.is_ok() { // status response
                if let Ok((packet_id, data)) = read_packet(&mut stream).await { // ping request
                    if packet_id == 1 && data.len() == 8 {
                        write_packet(&mut stream, 1, &data).await.unwrap_or(()); // pong
                    }
                }
            }

            Ok(format!("STATUS `{}`", stream.peer_addr()?.ip()))
        },
        Handshake::Login => {
            let (packet_id, data) = read_packet(&mut stream).await?; // login start
            if packet_id != 0 {
                return Err(Error::other(""))
            }

            let username = read_string(&mut Cursor::new(data)).await?.0;
            let uuid = Uuid::new_v3(&Uuid::NAMESPACE_DNS, format!("OfflinePlayer:{username}").as_bytes());

            write_packet(&mut stream, 2, &[ // login success
                uuid.as_bytes(),
                &prefix_str_len(&username)[..],
                &write_varint(0),
            ].concat()).await?;
            
            Ok(format!("JOIN `{}`, username: `{username}`", stream.peer_addr()?.ip()))
        },
    }
}

async fn send_status_resp(stream: &mut TcpStream, server_icon: Option<String>) -> Result<(), Error> {
    let status_response = fs::read_to_string("status_resp.json").await
        .expect("couldn't find status_resp.json");

    let mut parsed: Value = serde_json::from_str(&status_response).expect("failed to parse status_resp.json");

    if let Some(icon) = server_icon {
        parsed["favicon"] = json!(icon);
    }

    let json_str = serde_json::to_string(&parsed).unwrap();

    write_packet(stream, 0, &prefix_str_len(&json_str)).await?;
    Ok(())
}

async fn write_packet(stream: &mut TcpStream, packet_id: i32, data: &[u8]) -> Result<(), Error> {
    let packet_id = write_varint(packet_id);
    let packet_len = write_varint((packet_id.len() + data.len()).try_into().unwrap());

    stream.write_all(&[packet_len.as_slice(), packet_id.as_slice(), data].concat()).await
}

async fn read_packet(stream: &mut TcpStream) -> Result<(i32, Vec<u8>), Error> {
    let total_packet_len = read_varint(stream).await?.0;
    let (packet_id, packet_id_len) = read_varint(stream).await?;

    let data_len = total_packet_len - packet_id_len;
    let mut data_buf = vec![0u8; data_len.try_into().unwrap()];

    stream.read_exact(&mut data_buf).await?;

    Ok((packet_id, data_buf))
}

enum Handshake {
    Status,
    Login
}

async fn read_handshake<T: AsyncRead + Unpin>(byte_iter: &mut T) -> Result<Handshake, Error> {
    read_varint(byte_iter).await?; // protocol
    read_string(byte_iter).await?; // server address

    for _ in 0..2 { // port
        byte_iter.read_u8().await?;
    }

    let next_state = read_varint(byte_iter).await?.0;
    match next_state {
        1 => Ok(Handshake::Status),
        2 => Ok(Handshake::Login),
        _ => Err(Error::other(""))
    }

}