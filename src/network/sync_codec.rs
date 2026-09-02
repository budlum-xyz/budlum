use futures::prelude::*;
use libp2p::request_response;
use libp2p::StreamProtocol;

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

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
        // HIGH (CWE-400, 2026-08-17): /sync requests are buffered BEFORE the
        // handshake/ban/rate-limit checks. A 10 MiB ceiling let a remote peer
        // connect and send small control requests (GetHeaders, GetBlocksRange)
        // to force large allocations.
        // Control requests are kilobyte sized; the ceiling was lowered to 1 MiB.
        let mut buf = Vec::new();
        let mut limited = io.take(1024 * 1024);
        limited.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut limited = io.take(10 * 1024 * 1024);
        limited.read_to_end(&mut buf).await?;
        Ok(buf)
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
        io.write_all(&resp).await?;
        io.close().await?;
        Ok(())
    }
}
