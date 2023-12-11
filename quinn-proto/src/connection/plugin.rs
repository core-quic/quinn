use bytes::Buf;
use pluginop::{
    api::{CTPError, ConnectionToPlugin, ToPluginizableConnection},
    common::{
        quic::{
            ConnectionField, ExtensionFrame, Frame, Header, HeaderExt, KPacketNumberSpace,
            MaxDataFrame, PaddingFrame, PathChallengeFrame, PathResponseFrame, QVal,
        },
        Bytes, PluginVal,
    },
    FromWithPH, TryFromWithPH,
};

use crate::{frame, packet, transport_error, Side};

use super::CoreConnection;

impl ConnectionToPlugin for CoreConnection {
    fn get_connection(
        &self,
        field: pluginop::common::quic::ConnectionField,
        w: &mut [u8],
    ) -> bincode::Result<()> {
        let pv: PluginVal = match field {
            ConnectionField::MaxTxData => self.streams.max_data().into(),
            ConnectionField::IsEstablished => self.state.is_established().into(),
            ConnectionField::IsServer => (self.side() == Side::Server).into(),
            f => todo!("{f:?}"),
        };
        bincode::serialize_into(w, &pv)
    }

    fn set_connection(
        &mut self,
        field: pluginop::common::quic::ConnectionField,
        value: &[u8],
    ) -> Result<(), pluginop::api::CTPError> {
        let pv: PluginVal =
            bincode::deserialize_from(value).map_err(|_| CTPError::SerializeError)?;
        match field {
            ConnectionField::MaxTxData => self
                .streams
                .set_max_data(pv.try_into().map_err(|_| CTPError::BadType)?),
            _ => todo!(),
        };
        Ok(())
    }

    fn get_recovery(
        &self,
        _w: &mut [u8],
        _field: pluginop::common::quic::RecoveryField,
    ) -> bincode::Result<()> {
        todo!()
    }

    fn set_recovery(&mut self, _field: pluginop::common::quic::RecoveryField, _value: &[u8]) {
        todo!()
    }
}

impl ToPluginizableConnection<Self> for CoreConnection {
    fn set_pluginizable_connection(&mut self, pc: *mut pluginop::PluginizableConnection<Self>) {
        self.pc = Some(pluginop::ParentReferencer::new(pc));

        // TODO: maybe needed for other structures.
    }

    fn get_pluginizable_connection(
        &mut self,
    ) -> Option<&mut pluginop::PluginizableConnection<Self>> {
        self.pc.as_deref_mut()
    }
}

impl<CTP: ConnectionToPlugin> FromWithPH<frame::Frame, CTP> for PluginVal {
    fn from_with_ph(value: frame::Frame, _ph: &mut pluginop::handler::PluginHandler<CTP>) -> Self {
        let frame = match value {
            frame::Frame::Padding(l) => Frame::Padding(PaddingFrame { length: l }),
            frame::Frame::Ping => todo!(),
            frame::Frame::Ack(a) => {
                let mut ar_cnt = 0;
                let mut first_range = a.largest;
                let mut first = true;
                for range in a.iter() {
                    if !first {
                        ar_cnt += 1;
                    } else {
                        first_range = *range.start();
                    }
                    // TODO: store ranges.
                    first = false;
                }
                Frame::ACK(pluginop::common::quic::ACKFrame {
                    largest_acknowledged: a.largest,
                    ack_delay: a.delay,
                    ack_range_count: ar_cnt,
                    first_ack_range: first_range,
                    ack_ranges: Bytes {
                        tag: 99,
                        max_read_len: 0,
                        max_write_len: 0,
                    },
                    ecn_counts: None,
                })
            }
            frame::Frame::ResetStream(_) => todo!(),
            frame::Frame::StopSending(_) => todo!(),
            frame::Frame::Crypto(_) => todo!(),
            frame::Frame::NewToken { token: _ } => todo!(),
            frame::Frame::Stream(_) => todo!(),
            frame::Frame::MaxData(vi) => Frame::MaxData(MaxDataFrame {
                maximum_data: vi.into(),
            }),
            frame::Frame::MaxStreamData { id: _, offset: _ } => todo!(),
            frame::Frame::MaxStreams { dir: _, count: _ } => todo!(),
            frame::Frame::DataBlocked { offset: _ } => todo!(),
            frame::Frame::StreamDataBlocked { id: _, offset: _ } => todo!(),
            frame::Frame::StreamsBlocked { dir: _, limit: _ } => todo!(),
            frame::Frame::NewConnectionId(_) => todo!(),
            frame::Frame::RetireConnectionId { sequence: _ } => todo!(),
            frame::Frame::PathChallenge(data) => Frame::PathChallenge(PathChallengeFrame { data }),
            frame::Frame::PathResponse(data) => Frame::PathResponse(PathResponseFrame { data }),
            frame::Frame::Close(_) => todo!(),
            frame::Frame::Datagram(_) => todo!(),
            frame::Frame::Invalid { ty, reason } => {
                println!("{} {}", ty, reason);
                todo!()
            }
            frame::Frame::HandshakeDone => todo!(),
            frame::Frame::Extension { frame_type, tag } => {
                Frame::Extension(ExtensionFrame { frame_type, tag })
            }
        };
        Self::QUIC(QVal::Frame(frame))
    }
}

impl<CTP: ConnectionToPlugin> FromWithPH<packet::Header, CTP> for PluginVal {
    fn from_with_ph(value: packet::Header, ph: &mut pluginop::handler::PluginHandler<CTP>) -> Self {
        // FIXME
        let hdr = match value {
            packet::Header::Initial {
                dst_cid: _,
                src_cid: _,
                token: _,
                number: _,
                version: _,
            } => todo!(),
            packet::Header::Long {
                ty: _,
                dst_cid: _,
                src_cid: _,
                number: _,
                version: _,
            } => todo!(),
            packet::Header::Retry {
                dst_cid: _,
                src_cid: _,
                version: _,
            } => todo!(),
            packet::Header::Short {
                spin,
                key_phase,
                dst_cid,
                number,
            } => {
                let first = 0x40
                    | (spin as u8 * 0x20)
                    | (key_phase as u8 * 0x04)
                    | ((number.len() - 1) as u8);
                let dcid_bytes = ph.add_bytes_content(dst_cid.to_vec().into());
                Header {
                    first,
                    version: None,
                    destination_cid: dcid_bytes,
                    source_cid: None,
                    supported_versions: None,
                    ext: Some(HeaderExt {
                        // TODO.
                        packet_number: None,
                        packet_number_len: Some(number.len() as u8),
                        token: None,
                        key_phase: Some(key_phase),
                    }),
                }
            }
            packet::Header::VersionNegotiate {
                random: _,
                src_cid: _,
                dst_cid: _,
            } => todo!(),
        };
        Self::QUIC(QVal::Header(hdr))
    }
}

impl<CTP: ConnectionToPlugin> FromWithPH<packet::SpaceId, CTP> for PluginVal {
    fn from_with_ph(value: packet::SpaceId, _: &mut pluginop::handler::PluginHandler<CTP>) -> Self {
        let pns = match value {
            packet::SpaceId::Initial => KPacketNumberSpace::Initial,
            packet::SpaceId::Handshake => KPacketNumberSpace::Handshake,
            packet::SpaceId::Data => KPacketNumberSpace::ApplicationData,
        };
        Self::QUIC(QVal::PacketNumberSpace(pns))
    }
}

impl From<i64> for transport_error::Error {
    fn from(_value: i64) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TryFromCoreQuinnError {
    BadFrame,
}

impl<CTP: ConnectionToPlugin> TryFromWithPH<PluginVal, CTP> for frame::Frame {
    type Error = TryFromCoreQuinnError;

    fn try_from_with_ph(
        value: PluginVal,
        _ph: &pluginop::handler::PluginHandler<CTP>,
    ) -> Result<Self, Self::Error> {
        let f = if let PluginVal::QUIC(QVal::Frame(f)) = value {
            f
        } else {
            return Err(TryFromCoreQuinnError::BadFrame);
        };
        let quinn_frame = match f {
            Frame::Extension(e) => Self::Extension {
                frame_type: e.frame_type,
                tag: e.tag,
            },
            Frame::Padding(p) => Self::Padding(p.length),
            Frame::PathChallenge(pc) => Self::PathChallenge(pc.data),
            f => todo!("{f:?}"),
        };
        Ok(quinn_frame)
    }
}
