use pluginop::{
    api::{CTPError, ConnectionToPlugin, ToPluginizableConnection},
    common::{
        quic::{ConnectionField, Frame, Header, HeaderExt, KPacketNumberSpace, MaxDataFrame, QVal},
        PluginVal,
    },
    FromWithPH,
};

use crate::{frame, packet, transport_error};

use super::CoreConnection;

impl ConnectionToPlugin for CoreConnection {
    fn get_connection(
        &self,
        field: pluginop::common::quic::ConnectionField,
        w: &mut [u8],
    ) -> bincode::Result<()> {
        let pv: PluginVal = match field {
            ConnectionField::MaxTxData => self.streams.max_data().into(),
            _ => todo!(),
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

impl ToPluginizableConnection<CoreConnection> for CoreConnection {
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
            frame::Frame::Padding => todo!(),
            frame::Frame::Ping => todo!(),
            frame::Frame::Ack(_) => todo!(),
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
            frame::Frame::PathChallenge(_) => todo!(),
            frame::Frame::PathResponse(_) => todo!(),
            frame::Frame::Close(_) => todo!(),
            frame::Frame::Datagram(_) => todo!(),
            frame::Frame::Invalid { ty: _, reason: _ } => todo!(),
            frame::Frame::HandshakeDone => todo!(),
        };
        PluginVal::QUIC(QVal::Frame(frame))
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
        PluginVal::QUIC(QVal::Header(hdr))
    }
}

impl<CTP: ConnectionToPlugin> FromWithPH<packet::SpaceId, CTP> for PluginVal {
    fn from_with_ph(value: packet::SpaceId, _: &mut pluginop::handler::PluginHandler<CTP>) -> Self {
        let pns = match value {
            packet::SpaceId::Initial => KPacketNumberSpace::Initial,
            packet::SpaceId::Handshake => KPacketNumberSpace::Handshake,
            packet::SpaceId::Data => KPacketNumberSpace::ApplicationData,
        };
        PluginVal::QUIC(QVal::PacketNumberSpace(pns))
    }
}

impl From<i64> for transport_error::Error {
    fn from(_value: i64) -> Self {
        todo!()
    }
}
