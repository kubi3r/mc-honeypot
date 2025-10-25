use std::fs;
use std::io::{Bytes, Error, Read, Write};
use std::net::{TcpListener, TcpStream};
use base64::Engine;
use mc_honeypot::{read_varint, write_varint, read_string, prefix_str_len, send_webhook};
use serde_json::{json, Value};
use uuid::Uuid;
use clap::Parser;
use base64::{engine::general_purpose};

#[derive(Parser, Debug)]
struct Args {
    /// Webhook to send logs to
    #[arg(short, long)]
    webhook: Option<String>,

    /// Path to server icon
    #[arg(short, long)]
    server_icon: Option<String>
}


fn main() {
    let args = Args::parse();

    let mut server_icon = None;
    if let Some(ref icon_path) = args.server_icon {
        let image_bytes = fs::read(icon_path).unwrap_or_else(|_| panic!("couldn't find image at {icon_path}"));
        let base64_encoded = general_purpose::STANDARD.encode(image_bytes);

        server_icon = Some(format!("data:image/png;base64,{base64_encoded}"));
    }

    let listener = TcpListener::bind("127.0.0.1:25565").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Ok(message) = handle_connection(stream, &server_icon) {
                    println!("{message}");

                    if let Some(webhook) = &args.webhook {
                        if let Err(e) = send_webhook(message, webhook) {
                            println!("failed to send messsage to webhook: {e}")
                        }
                    }
                }

            },
            Err(e) => println!("connection error: {e}")
        }
    }
}

fn handle_connection(mut stream: TcpStream, server_icon: &Option<String>) -> Result<String, Error> {
    let (packet_id, data) = read_packet(&mut stream)?; // handshake

    if packet_id != 0 {
        return Err(Error::other(""))
    }

    match read_handshake(&mut data.bytes())? {
        Handshake::Status => {
            let packet_id = read_packet(&mut stream)?.0; // status request
            if packet_id != 0 {
                return Err(Error::other(""))
            }

            if send_status_resp(&mut stream, server_icon).is_ok() { // status response
                if let Ok((packet_id, data)) = read_packet(&mut stream) { // ping request
                    if packet_id == 1 && data.len() == 8 {
                        write_packet(&mut stream, 1, &data).unwrap_or(()); // pong
                    }
                }
            }

            Ok(format!("STATUS `{}`", stream.peer_addr()?.ip()))
        },
        Handshake::Login => {
            let (packet_id, data) = read_packet(&mut stream)?; // login start
            if packet_id != 0 {
                return Err(Error::other(""))
            }

            let mut byte_iter = data.bytes();

            let username = read_string(&mut byte_iter)?.0;
            let uuid = Uuid::new_v3(&Uuid::NAMESPACE_DNS, format!("OfflinePlayer:{username}").as_bytes());

            write_packet(&mut stream, 2, &[ // login success
                uuid.as_bytes(),
                &prefix_str_len(&username)[..],
                &write_varint(0),
            ].concat())?;
            
            Ok(format!("JOIN `{}`, username: `{username}`", stream.peer_addr()?.ip()))
        },
    }
}

fn send_status_resp(stream: &mut TcpStream, server_icon: &Option<String>) -> Result<(), Error> {
    let status_response = fs::read_to_string("status_resp.json")
        .expect("couldn't find status_resp.json");

    let mut parsed: Value = serde_json::from_str(&status_response).expect("failed to parse status_resp.json");

    if let Some(icon) = server_icon {
        parsed["favicon"] = json!(icon);
    }

    let json_str = serde_json::to_string(&parsed).unwrap();

    write_packet(stream, 0, &prefix_str_len(&json_str))?;
    Ok(())
}

fn write_packet(stream: &mut TcpStream, packet_id: i32, data: &[u8]) -> Result<(), Error> {
    let packet_id = write_varint(packet_id);
    let packet_len = write_varint((packet_id.len() + data.len()).try_into().unwrap());

    stream.write_all(&[packet_len.as_slice(), packet_id.as_slice(), data].concat())
}

fn read_packet(stream: &mut TcpStream) -> Result<(i32, Vec<u8>), Error> {
    let mut byte_iter = stream.bytes();

    let total_packet_len = read_varint(&mut byte_iter)?.0;
    let (packet_id, packet_id_len) = read_varint(&mut byte_iter)?;

    let data_len = total_packet_len - packet_id_len;
    let mut data_buf = vec![0u8; data_len.try_into().unwrap()];

    stream.read_exact(&mut data_buf)?;

    Ok((packet_id, data_buf))
}

enum Handshake {
    Status,
    Login
}

fn read_handshake<T>(byte_iter: &mut Bytes<T>) -> Result<Handshake, Error>
where T: Read
{
    read_varint(byte_iter)?; // protocol
    read_string(byte_iter)?; // server address

    for _ in 0..2 { // port
        byte_iter.next();
    }

    let next_state = read_varint(byte_iter)?.0;
    match next_state {
        1 => Ok(Handshake::Status),
        2 => Ok(Handshake::Login),
        _ => Err(Error::other(""))
    }

}