use futures::prelude::*;
use libp2p::request_response;
use libp2p::StreamProtocol;

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

/// Largest `/sync` request accepted. Control requests are kilobyte sized.
const MAX_SYNC_REQUEST_BYTES: usize = 1024 * 1024;
/// Largest `/sync` response accepted.
const MAX_SYNC_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Read a whole frame of at most `limit` bytes, refusing a longer one.
///
/// `take(limit)` followed by `read_to_end` returned `Ok` for an oversize
/// frame and dropped the rest, so the caller decoded a truncated payload.
/// Protobuf reads absent fields as defaults, so a truncated frame decodes
/// into a different, valid-looking message instead of being refused. One
/// byte past the limit is read; if it is there, the frame is too long.
async fn read_bounded<T>(io: &mut T, limit: usize) -> std::io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(limit as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sync frame exceeds {limit} bytes"),
        ));
    }
    Ok(buf)
}

// `request_response::Codec` used to be an `#[async_trait]` trait; upstream
// moved it to native `-> impl Future + Send` methods, so the attribute now
// conflicts with the declaration (E0195: lifetime bounds do not match).
impl request_response::Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // `/sync` requests are buffered before the handshake, ban and
        // rate-limit checks, so the ceiling is the only thing between a
        // stranger and a large allocation. Control requests are kilobyte
        // sized; the ceiling is 1 MiB.
        read_bounded(io, MAX_SYNC_REQUEST_BYTES).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_bounded(io, MAX_SYNC_RESPONSE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if req.len() > MAX_SYNC_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("sync request exceeds {MAX_SYNC_REQUEST_BYTES} bytes"),
            ));
        }
        io.write_all(&req).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if resp.len() > MAX_SYNC_RESPONSE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("sync response exceeds {MAX_SYNC_RESPONSE_BYTES} bytes"),
            ));
        }
        io.write_all(&resp).await?;
        io.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::Cursor;

    #[test]
    fn a_frame_at_the_limit_is_read_whole() {
        let frame = vec![7u8; 16];
        let mut io = Cursor::new(frame.clone());
        let got = block_on(read_bounded(&mut io, 16)).unwrap();
        assert_eq!(got, frame);
    }

    /// An oversize frame is refused, not truncated into a shorter message
    /// that still decodes.
    #[test]
    fn a_frame_past_the_limit_is_refused_not_truncated() {
        let mut io = Cursor::new(vec![7u8; 17]);
        let err = block_on(read_bounded(&mut io, 16)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn blg_147_sync_codec_refuses_oversize_writes_symmetrically() {
        use libp2p::request_response::Codec as _;
        let mut codec = SyncCodec;
        let proto = StreamProtocol::new("/budlum/sync/1.0.0");

        let mut sink_req: Vec<u8> = Vec::new();
        let req_err = block_on(codec.write_request(
            &proto,
            &mut sink_req,
            vec![0u8; MAX_SYNC_REQUEST_BYTES + 1],
        ))
        .unwrap_err();
        assert_eq!(req_err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(sink_req.is_empty());

        let mut sink_resp: Vec<u8> = Vec::new();
        let resp_err = block_on(codec.write_response(
            &proto,
            &mut sink_resp,
            vec![0u8; MAX_SYNC_RESPONSE_BYTES + 1],
        ))
        .unwrap_err();
        assert_eq!(resp_err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(sink_resp.is_empty());
    }
}
