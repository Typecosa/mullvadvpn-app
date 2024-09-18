use crate::config::Obfuscator;
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub async fn forward(obfuscator: impl Obfuscator, client_stream: TcpStream) -> io::Result<()> {
    let server_connection = TcpStream::connect(obfuscator.addr()).await?;
    let write_obfuscator = obfuscator.clone();
    let (server_read, server_write) = server_connection.into_split();
    let (client_read, client_write) = client_stream.into_split();
    let ((), ()) = tokio::try_join!(
        forward_inner(obfuscator, client_read, server_write),
        forward_inner(write_obfuscator, server_read, client_write)
    )?;
    Ok(())
}

async fn forward_inner(
    mut obfuscator: impl Obfuscator,
    mut source: impl AsyncRead + Unpin,
    mut sink: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 1024 * 64];
    while let Ok(n_bytes_read) = source.read(&mut buf).await {
        if n_bytes_read == 0 {
            break;
        }
        let bytes_received = &mut buf[..n_bytes_read];

        obfuscator.obfuscate(bytes_received);
        sink.write_all(bytes_received).await?;
    }
    Ok(())
}
