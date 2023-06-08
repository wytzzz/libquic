// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_packet_generator.h"

#include "base/logging.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"

using base::StringPiece;

namespace net {

QuicPacketGenerator::QuicPacketGenerator(QuicConnectionId connection_id,
                                         QuicFramer* framer,
                                         QuicRandom* random_generator,
                                         QuicBufferAllocator* buffer_allocator,
                                         DelegateInterface* delegate)
    : delegate_(delegate),
      packet_creator_(connection_id,
                      framer,
                      random_generator,
                      buffer_allocator,
                      delegate),
      batch_mode_(false),
      should_send_ack_(false),
      should_send_stop_waiting_(false) {}

QuicPacketGenerator::~QuicPacketGenerator() {
  QuicUtils::DeleteFrames(&queued_control_frames_);
}

void QuicPacketGenerator::SetShouldSendAck(bool also_send_stop_waiting) {

  if (packet_creator_.has_ack()) {
    // Ack already queued, nothing to do.
    return;
  }
  //如果需要发送停止等待帧，同时已经有一个停止等待帧被排队等待发送了，那么这是一个错误的状态，应该报告一个 bug 并返回
  if (also_send_stop_waiting && packet_creator_.has_stop_waiting()) {
    QUIC_BUG << "Should only ever be one pending stop waiting frame.";
    return;
  }

  should_send_ack_ = true;
  should_send_stop_waiting_ = also_send_stop_waiting;
  //方法将已经排队的数据帧发送出去，如果 flush 参数为 false，则数据帧会被缓存到发送队列中，等待下一次发送。
  SendQueuedFrames(/*flush=*/false);
}

void QuicPacketGenerator::AddControlFrame(const QuicFrame& frame) {
  queued_control_frames_.push_back(frame);
  SendQueuedFrames(/*flush=*/false);
}

//这个方法主要实现向QuicPacketGenerator中添加应用层数据,并进行序列化、发送的逻辑。
//它会根据空间判断是否需要先发送已有的数据包,同时也考虑到加密数据流的特殊处理逻辑。在序列化和发送完所有数据后,会返回消耗信息
QuicConsumedData QuicPacketGenerator::ConsumeData(
    QuicStreamId id,
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    QuicAckListenerInterface* listener) {

//判断是否为加密数据流,如果是,fin帧应该不出现。。
  bool has_handshake = (id == kCryptoStreamId);
  QUIC_BUG_IF(has_handshake && fin)
      << "Handshake packets should never send a fin";
  // To make reasoning about crypto frames easier, we don't combine them with
  // other retransmittable frames in a single packet.

  //并根据是否有待重传的加密帧,判断是否立即发送已序列化的数据包。这是因为不希望加密帧与其他重传帧在同一个数据包中,以方便日后理解和解析
  const bool flush =
      has_handshake && packet_creator_.HasPendingRetransmittableFrames();
  SendQueuedFrames(flush);

  size_t total_bytes_consumed = 0;
  bool fin_consumed = false;

  //检查是否有足够的空间来写入一个stream_frame，。
  if (!packet_creator_.HasRoomForStreamFrame(id, offset)) {
      //如果没有，则将之前的数据包发送出去,把空间留出来给下一个stream frame.
    packet_creator_.Flush();
  }

  if (!fin && (iov.total_length == 0)) {
    QUIC_BUG << "Attempt to consume empty data without FIN.";
    return QuicConsumedData(0, false);
  }

  //循环调用packet_creator_的ConsumeData()方法,生成数据帧并添加到数据包中,直到数据全部消耗完或数据包已满。
  //ShouldGeneratePacket在connection中判断能够发送数据到网络中,主要考虑了拥塞控制.
  while (delegate_->ShouldGeneratePacket(
      HAS_RETRANSMITTABLE_DATA, has_handshake ? IS_HANDSHAKE : NOT_HANDSHAKE)) {
    QuicFrame frame;
    //创建stream frame,并添加到packet中.
    if (!packet_creator_.ConsumeData(id, iov, total_bytes_consumed,
                                     offset + total_bytes_consumed, fin,
                                     has_handshake, &frame)) {
      // The creator is always flushed if there's not enough room for a new
      // stream frame before ConsumeData, so ConsumeData should always succeed.
      QUIC_BUG << "Failed to ConsumeData, stream:" << id;
      return QuicConsumedData(0, false);
    }

    // A stream frame is created and added.
    size_t bytes_consumed = frame.stream_frame->data_length;
    //每生成一个数据帧,就调用AddAckListener()为其添加ACK监听器,并累加消耗的字节数。如果fin也被消费,fin_consumed设置为true。
    if (listener != nullptr) {
      //添加ack监听.
      packet_creator_.AddAckListener(listener, bytes_consumed);
    }

    //split frame
    total_bytes_consumed += bytes_consumed;
    fin_consumed = fin && total_bytes_consumed == iov.total_length;
    DCHECK(total_bytes_consumed == iov.total_length ||
           (bytes_consumed > 0 && packet_creator_.HasPendingFrames()));

    //如果不在批处理模式,每个数据包完成后立即调用Flush()发送
    if (!InBatchMode()) {
      packet_creator_.Flush();
    }

    //消耗完数据,最后一个包不再批处理模式下,直接退出.
    if (total_bytes_consumed == iov.total_length) {
      // We're done writing the data. Exit the loop.
      // We don't make this a precondition because we could have 0 bytes of data
      // if we're simply writing a fin.
      break;
    }
    // TODO(ianswett): Move to having the creator flush itself when it's full.
    //发送数据包
    packet_creator_.Flush();
  }

  // Don't allow the handshake to be bundled with other retransmittable frames.
  //如果生成的是加密数据流的帧,则在所有数据被消耗完后立即调用SendQueuedFrames()发送,这是因为加密帧不与其他帧捆绑
  if (has_handshake) {
    SendQueuedFrames(/*flush=*/true);
  }

  DCHECK(InBatchMode() || !packet_creator_.HasPendingFrames());
  //返回消耗的总字节数和fin是否被消耗。
  return QuicConsumedData(total_bytes_consumed, fin_consumed);
}

QuicConsumedData QuicPacketGenerator::ConsumeDataFastPath(
    QuicStreamId id,
    const QuicIOVector& iov,
    QuicStreamOffset offset,
    bool fin,
    QuicAckListenerInterface* listener) {
  DCHECK_NE(id, kCryptoStreamId);
  size_t total_bytes_consumed = 0;
  while (total_bytes_consumed < iov.total_length &&
         delegate_->ShouldGeneratePacket(HAS_RETRANSMITTABLE_DATA,
                                         NOT_HANDSHAKE)) {
    // Serialize and encrypt the packet.
    size_t bytes_consumed = 0;
    packet_creator_.CreateAndSerializeStreamFrame(
        id, iov, total_bytes_consumed, offset + total_bytes_consumed, fin,
        listener, &bytes_consumed);
    total_bytes_consumed += bytes_consumed;
  }

  return QuicConsumedData(total_bytes_consumed,
                          fin && (total_bytes_consumed == iov.total_length));
}

void QuicPacketGenerator::GenerateMtuDiscoveryPacket(
    QuicByteCount target_mtu,
    QuicAckListenerInterface* listener) {
  // MTU discovery frames must be sent by themselves.
  if (!packet_creator_.CanSetMaxPacketLength()) {
    QUIC_BUG << "MTU discovery packets should only be sent when no other "
             << "frames needs to be sent.";
    return;
  }
  const QuicByteCount current_mtu = GetCurrentMaxPacketLength();

  // The MTU discovery frame is allocated on the stack, since it is going to be
  // serialized within this function.
  QuicMtuDiscoveryFrame mtu_discovery_frame;
  QuicFrame frame(mtu_discovery_frame);

  // Send the probe packet with the new length.
  SetMaxPacketLength(target_mtu);
  const bool success = packet_creator_.AddPaddedSavedFrame(frame);
  if (listener != nullptr) {
    packet_creator_.AddAckListener(listener, 0);
  }
  packet_creator_.Flush();
  // The only reason AddFrame can fail is that the packet is too full to fit in
  // a ping.  This is not possible for any sane MTU.
  DCHECK(success);

  // Reset the packet length back.
  SetMaxPacketLength(current_mtu);
}

//判断是否还能往packet添加数据包
bool QuicPacketGenerator::CanSendWithNextPendingFrameAddition() const {
  DCHECK(HasPendingFrames());

  HasRetransmittableData retransmittable =
      (should_send_ack_ || should_send_stop_waiting_)
          ? NO_RETRANSMITTABLE_DATA
          : HAS_RETRANSMITTABLE_DATA;
  if (retransmittable == HAS_RETRANSMITTABLE_DATA) {
    DCHECK(!queued_control_frames_.empty());  // These are retransmittable.
  }


  //生成ack frame
  return delegate_->ShouldGeneratePacket(retransmittable, NOT_HANDSHAKE);
}

//将缓存起来的控制帧尝试添加到packet中.
void QuicPacketGenerator::SendQueuedFrames(bool flush) {
  // Only add pending frames if we are SURE we can then send the whole packet.
  //查看是否有pending frame.
  //否有待发送的数据帧（即有没有 pending frame），如果有，则将下一个待发送的数据帧添加到数据包中，直到不能再添加为止。
  while (HasPendingFrames() &&
         (flush || CanSendWithNextPendingFrameAddition())) {
    AddNextPendingFrame();
  }
  //如果设置了 flush 参数或者不在批处理模式中，就会packet发送出去。
  if (flush || !InBatchMode()) {
    packet_creator_.Flush();
  }
}

bool QuicPacketGenerator::InBatchMode() {
  return batch_mode_;
}

void QuicPacketGenerator::StartBatchOperations() {
  batch_mode_ = true;
}

void QuicPacketGenerator::FinishBatchOperations() {
  batch_mode_ = false;
  SendQueuedFrames(/*flush=*/false);
}

void QuicPacketGenerator::FlushAllQueuedFrames() {
  SendQueuedFrames(/*flush=*/true);
}

bool QuicPacketGenerator::HasQueuedFrames() const {
  return packet_creator_.HasPendingFrames() || HasPendingFrames();
}

bool QuicPacketGenerator::IsPendingPacketEmpty() const {
  return !packet_creator_.HasPendingFrames();
}

bool QuicPacketGenerator::HasPendingFrames() const {
  return should_send_ack_ || should_send_stop_waiting_ ||
         !queued_control_frames_.empty();
}

//这个方法实现了根据当前数据包空间,尝试添加下一条待发送的控制帧(ACK或STOP_WAITING)的逻辑
bool QuicPacketGenerator::AddNextPendingFrame() {

    //如果should_send_ack_标记为true,说明有ACK帧需要发送。
    // 调用GetUpdatedAckFrame()获取最新的ACK帧,尝试添加到当前数据包。如果添加成功,设置should_send_ack_为false。返回是否添加成功
  if (should_send_ack_) {
    should_send_ack_ =
        !packet_creator_.AddSavedFrame(delegate_->GetUpdatedAckFrame());
    return !should_send_ack_;
  }
  //如果should_send_stop_waiting_标记为true,说明有STOP_WAITING帧需要发送。调用PopulateStopWaitingFrame()生成最新的STOP_WAITING帧,尝试添加到当前数据包
  if (should_send_stop_waiting_) {
    delegate_->PopulateStopWaitingFrame(&pending_stop_waiting_frame_);
    // If we can't this add the frame now, then we still need to do so later.
    should_send_stop_waiting_ =
        !packet_creator_.AddSavedFrame(QuicFrame(&pending_stop_waiting_frame_));
    // Return success if we have cleared out this flag (i.e., added the frame).
    // If we still need to send, then the frame is full, and we have failed.
    return !should_send_stop_waiting_;
  }

  QUIC_BUG_IF(queued_control_frames_.empty())
      << "AddNextPendingFrame called with no queued control frames.";
  //如果queued_control_frames_不为空,取出最后一个控制帧,尝试添加到当前数据包。如果添加成功,从queued_control_frames_中弹出该帧。返回是否添加成功
  if (!packet_creator_.AddSavedFrame(queued_control_frames_.back())) {
    // Packet was full.
    return false;
  }
  queued_control_frames_.pop_back();
  return true;
}

void QuicPacketGenerator::StopSendingVersion() {
  packet_creator_.StopSendingVersion();
}

void QuicPacketGenerator::SetDiversificationNonce(
    const DiversificationNonce& nonce) {
  packet_creator_.SetDiversificationNonce(nonce);
}

QuicPacketNumber QuicPacketGenerator::packet_number() const {
  return packet_creator_.packet_number();
}

QuicByteCount QuicPacketGenerator::GetCurrentMaxPacketLength() const {
  return packet_creator_.max_packet_length();
}

void QuicPacketGenerator::SetMaxPacketLength(QuicByteCount length) {
  DCHECK(packet_creator_.CanSetMaxPacketLength());
  packet_creator_.SetMaxPacketLength(length);
}

QuicEncryptedPacket* QuicPacketGenerator::SerializeVersionNegotiationPacket(
    const QuicVersionVector& supported_versions) {
  return packet_creator_.SerializeVersionNegotiationPacket(supported_versions);
}

void QuicPacketGenerator::ReserializeAllFrames(
    const PendingRetransmission& retransmission,
    char* buffer,
    size_t buffer_len) {
  packet_creator_.ReserializeAllFrames(retransmission, buffer, buffer_len);
}

void QuicPacketGenerator::UpdateSequenceNumberLength(
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  return packet_creator_.UpdatePacketNumberLength(least_packet_awaited_by_peer,
                                                  max_packets_in_flight);
}

void QuicPacketGenerator::SetConnectionIdLength(uint32_t length) {
  if (length == 0) {
    packet_creator_.set_connection_id_length(PACKET_0BYTE_CONNECTION_ID);
  } else {
    packet_creator_.set_connection_id_length(PACKET_8BYTE_CONNECTION_ID);
  }
}

void QuicPacketGenerator::set_encryption_level(EncryptionLevel level) {
  packet_creator_.set_encryption_level(level);
}

void QuicPacketGenerator::SetEncrypter(EncryptionLevel level,
                                       QuicEncrypter* encrypter) {
  packet_creator_.SetEncrypter(level, encrypter);
}

void QuicPacketGenerator::SetCurrentPath(
    QuicPathId path_id,
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  packet_creator_.SetCurrentPath(path_id, least_packet_awaited_by_peer,
                                 max_packets_in_flight);
}

}  // namespace net
