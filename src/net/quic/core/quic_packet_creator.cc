// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_packet_creator.h"

#include <algorithm>

#include "base/logging.h"
#include "base/macros.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_data_writer.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"

using base::StringPiece;
using std::make_pair;
using std::max;
using std::min;
using std::pair;
using std::string;
using std::vector;

namespace net {

QuicPacketCreator::QuicPacketCreator(QuicConnectionId connection_id,
                                     QuicFramer* framer,
                                     QuicRandom* random_generator,
                                     QuicBufferAllocator* buffer_allocator,
                                     DelegateInterface* delegate)
    : delegate_(delegate),
      debug_delegate_(nullptr),
      framer_(framer),
      random_bool_source_(random_generator),
      buffer_allocator_(buffer_allocator),
      send_version_in_packet_(framer->perspective() == Perspective::IS_CLIENT),
      send_path_id_in_packet_(false),
      next_packet_number_length_(PACKET_1BYTE_PACKET_NUMBER),
      have_diversification_nonce_(false),
      max_packet_length_(0),
      connection_id_length_(PACKET_8BYTE_CONNECTION_ID),
      packet_size_(0),
      connection_id_(connection_id),
      packet_(kDefaultPathId,
              0,
              PACKET_1BYTE_PACKET_NUMBER,
              nullptr,
              0,
              0,
              false,
              false) {
  SetMaxPacketLength(kDefaultMaxPacketSize);
}

QuicPacketCreator::~QuicPacketCreator() {
  QuicUtils::DeleteFrames(&packet_.retransmittable_frames);
}

void QuicPacketCreator::SetEncrypter(EncryptionLevel level,
                                     QuicEncrypter* encrypter) {
  framer_->SetEncrypter(level, encrypter);
  //最大明文size.
  max_plaintext_size_ = framer_->GetMaxPlaintextSize(max_packet_length_);
}

bool QuicPacketCreator::CanSetMaxPacketLength() const {
  // |max_packet_length_| should not be changed mid-packet.
  return queued_frames_.empty();
}

void QuicPacketCreator::SetMaxPacketLength(QuicByteCount length) {
  DCHECK(CanSetMaxPacketLength());

  // Avoid recomputing |max_plaintext_size_| if the length does not actually
  // change.
  if (length == max_packet_length_) {
    return;
  }

  max_packet_length_ = length;
  max_plaintext_size_ = framer_->GetMaxPlaintextSize(max_packet_length_);
}

void QuicPacketCreator::MaybeUpdatePacketNumberLength() {
  DCHECK(!FLAGS_quic_simple_packet_number_length_2);
  if (!queued_frames_.empty()) {
    // Don't change creator state if there are frames queued.
    return;
  }

  // Update packet number length only on packet boundary.
  packet_.packet_number_length = next_packet_number_length_;
}

// Stops serializing version of the protocol in packets sent after this call.
// A packet that is already open might send kQuicVersionSize bytes less than the
// maximum packet size if we stop sending version before it is serialized.
void QuicPacketCreator::StopSendingVersion() {
  DCHECK(send_version_in_packet_);
  send_version_in_packet_ = false;
  if (packet_size_ > 0) {
    DCHECK_LT(kQuicVersionSize, packet_size_);
    packet_size_ -= kQuicVersionSize;
  }
}

void QuicPacketCreator::SetDiversificationNonce(
    const DiversificationNonce& nonce) {
  DCHECK(!have_diversification_nonce_);
  have_diversification_nonce_ = true;
  diversification_nonce_ = nonce;
}

void QuicPacketCreator::UpdatePacketNumberLength(
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  if (FLAGS_quic_simple_packet_number_length_2 && !queued_frames_.empty()) {
    // Don't change creator state if there are frames queued.
    QUIC_BUG << "Called UpdatePacketNumberLength with " << queued_frames_.size()
             << " queued_frames.  First frame type:"
             << queued_frames_.front().type
             << " last frame type:" << queued_frames_.back().type;
    return;
  }

  DCHECK_LE(least_packet_awaited_by_peer, packet_.packet_number + 1);
  const QuicPacketNumber current_delta =
      packet_.packet_number + 1 - least_packet_awaited_by_peer;
  const uint64_t delta = max(current_delta, max_packets_in_flight);
  if (FLAGS_quic_simple_packet_number_length_2) {
    packet_.packet_number_length =
        QuicFramer::GetMinSequenceNumberLength(delta * 4);
  } else {
    next_packet_number_length_ =
        QuicFramer::GetMinSequenceNumberLength(delta * 4);
  }
}

//所以,这个方法主要用于将应用层数据构造为QUIC STREAM帧,并尝试添加到数据包中进行发送。
// 其中,对加密数据流的数据进行了特殊检查,确保CHLO不会跨数据包发送。只有在有足够空间且未发送敏感数据的情况下,才可以成功添加构造的STREAM帧
bool QuicPacketCreator::ConsumeData(QuicStreamId id,
                                    QuicIOVector iov,
                                    size_t iov_offset,
                                    QuicStreamOffset offset,
                                    bool fin,
                                    bool needs_full_padding,
                                    QuicFrame* frame) {
  if (!HasRoomForStreamFrame(id, offset)) {
    return false;
  }

  //考虑packet剩余空间和用户数据的size,生成一个frame
  CreateStreamFrame(id, iov, iov_offset, offset, fin, frame);
  // Explicitly disallow multi-packet CHLOs.
  //如果是加密数据流且 constructed STREAM帧长度大于等于CHLO长度,且第一个字节值为kCHLO,
  //则检查constructed STREAM帧长度是否等于iov长度。如果不等,显示错误,因为CHLO不能跨数据包,并关闭连接
  if (id == kCryptoStreamId &&
      frame->stream_frame->data_length >= sizeof(kCHLO) &&
      strncmp(frame->stream_frame->data_buffer,
              reinterpret_cast<const char*>(&kCHLO), sizeof(kCHLO)) == 0) {
    DCHECK_EQ(static_cast<size_t>(0), iov_offset);
    if (frame->stream_frame->data_length < iov.iov->iov_len) {
      const string error_details = "Client hello won't fit in a single packet.";
      QUIC_BUG << error_details << " Constructed stream frame length: "
               << frame->stream_frame->data_length
               << " CHLO length: " << iov.iov->iov_len;
      delegate_->OnUnrecoverableError(QUIC_CRYPTO_CHLO_TOO_LARGE, error_details,
                                      ConnectionCloseSource::FROM_SELF);
      delete frame->stream_frame;
      return false;
    }
  }
  //将生成的stream frame添加到packet中
  if (!AddFrame(*frame, /*save_retransmittable_frames=*/true)) {
    // Fails if we try to write unencrypted stream data.
    delete frame->stream_frame;
    return false;
  }
  //如果需要完整填充,设置num_padding_bytes为-1,表示添加最大数量的填充。
  if (needs_full_padding) {
    packet_.num_padding_bytes = -1;
  }
  return true;
}

bool QuicPacketCreator::HasRoomForStreamFrame(QuicStreamId id,
                                              QuicStreamOffset offset) {
  return BytesFree() > QuicFramer::GetMinStreamFrameSize(id, offset, true);
}

// static
size_t QuicPacketCreator::StreamFramePacketOverhead(
    QuicVersion version,
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    bool include_path_id,
    bool include_diversification_nonce,
    QuicPacketNumberLength packet_number_length,
    QuicStreamOffset offset) {
  return GetPacketHeaderSize(version, connection_id_length, include_version,
                             include_path_id, include_diversification_nonce,
                             packet_number_length) +
         // Assumes this is a stream with a single lone packet.
         QuicFramer::GetMinStreamFrameSize(1u, offset, true);
}

void QuicPacketCreator::CreateStreamFrame(QuicStreamId id,
                                          QuicIOVector iov,
                                          size_t iov_offset,
                                          QuicStreamOffset offset,
                                          bool fin,
                                          QuicFrame* frame) {
  //检查数据包最大长度是否大于STREAM帧头部开销,以确保STREAM帧可以容纳在当前数据包中。
  DCHECK_GT(max_packet_length_,
            StreamFramePacketOverhead(framer_->version(), connection_id_length_,
                                      kIncludeVersion, kIncludePathId,
                                      IncludeNonceInPublicHeader(),
                                      PACKET_6BYTE_PACKET_NUMBER, offset));


  //如果必要,调用MaybeUpdatePacketNumberLength()更新数据包序号字段长度。
  if (!FLAGS_quic_simple_packet_number_length_2) {
    MaybeUpdatePacketNumberLength();
  }

  //使用QUIC_BUG_IF宏确保有足够空间可以添加STREAM帧。如果没有显示错误
  QUIC_BUG_IF(!HasRoomForStreamFrame(id, offset))
      << "No room for Stream frame, BytesFree: " << BytesFree()
      << " MinStreamFrameSize: "
      << QuicFramer::GetMinStreamFrameSize(id, offset, true);

  if (iov_offset == iov.total_length) {
    QUIC_BUG_IF(!fin) << "Creating a stream frame with no data or fin.";
    // Create a new packet for the fin, if necessary.
    *frame = QuicFrame(new QuicStreamFrame(id, true, offset, StringPiece()));
    return;
  }

  //计算iov中剩余的数据量和当前packet还能放入的负载大小的最小值作为这次要构造的STREAM帧数据量bytes_consumed。
  const size_t data_size = iov.total_length - iov_offset;
  size_t min_frame_size = QuicFramer::GetMinStreamFrameSize(
      id, offset, /* last_frame_in_packet= */ true);
  size_t bytes_consumed = min<size_t>(BytesFree() - min_frame_size, data_size);

  //如果数据量 bytes_consumed刚好消耗完iov中所有剩余数据,并且设置了fin,则设置set_fin为true,表明这是最后一个STREAM帧
  bool set_fin = fin && bytes_consumed == data_size;  // Last frame.
  //调用NewStreamBuffer()方法分配bytes_consumed大小的内存空间buffer,用以存放要发送的数据
  UniqueStreamBuffer buffer =
      NewStreamBuffer(buffer_allocator_, bytes_consumed);
  //调用CopyToBuffer()方法将iov中的数据复制到buffer中
  CopyToBuffer(iov, iov_offset, bytes_consumed, buffer.get());
  //构造QuicStreamFrame,设置id、set_fin、offset、data_length为bytes_consumed和std::move(buffer)
  *frame = QuicFrame(new QuicStreamFrame(id, set_fin, offset, bytes_consumed,
                                         std::move(buffer)));
}

// static
void QuicPacketCreator::CopyToBuffer(QuicIOVector iov,
                                     size_t iov_offset,
                                     size_t length,
                                     char* buffer) {
  int iovnum = 0;
  while (iovnum < iov.iov_count && iov_offset >= iov.iov[iovnum].iov_len) {
    iov_offset -= iov.iov[iovnum].iov_len;
    ++iovnum;
  }
  DCHECK_LE(iovnum, iov.iov_count);
  DCHECK_LE(iov_offset, iov.iov[iovnum].iov_len);
  if (iovnum >= iov.iov_count || length == 0) {
    return;
  }

  // Unroll the first iteration that handles iov_offset.
  const size_t iov_available = iov.iov[iovnum].iov_len - iov_offset;
  size_t copy_len = min(length, iov_available);

  // Try to prefetch the next iov if there is at least one more after the
  // current. Otherwise, it looks like an irregular access that the hardware
  // prefetcher won't speculatively prefetch. Only prefetch one iov because
  // generally, the iov_offset is not 0, input iov consists of 2K buffers and
  // the output buffer is ~1.4K.
  if (copy_len == iov_available && iovnum + 1 < iov.iov_count) {
    // TODO(ckrasic) - this is unused without prefetch()
    // char* next_base = static_cast<char*>(iov.iov[iovnum + 1].iov_base);
    // char* next_base = static_cast<char*>(iov.iov[iovnum + 1].iov_base);
    // Prefetch 2 cachelines worth of data to get the prefetcher started; leave
    // it to the hardware prefetcher after that.
    // TODO(ckrasic) - investigate what to do about prefetch directives.
    // prefetch(next_base, PREFETCH_HINT_T0);
    if (iov.iov[iovnum + 1].iov_len >= 64) {
      // TODO(ckrasic) - investigate what to do about prefetch directives.
      // prefetch(next_base + CACHELINE_SIZE, PREFETCH_HINT_T0);
    }
  }

  const char* src = static_cast<char*>(iov.iov[iovnum].iov_base) + iov_offset;
  while (true) {
    memcpy(buffer, src, copy_len);
    length -= copy_len;
    buffer += copy_len;
    if (length == 0 || ++iovnum >= iov.iov_count) {
      break;
    }
    src = static_cast<char*>(iov.iov[iovnum].iov_base);
    copy_len = min(length, iov.iov[iovnum].iov_len);
  }
  QUIC_BUG_IF(length > 0) << "Failed to copy entire length to buffer.";
}

void QuicPacketCreator::ReserializeAllFrames(
    const PendingRetransmission& retransmission,
    char* buffer,
    size_t buffer_len) {
  DCHECK(queued_frames_.empty());
  DCHECK_EQ(0, packet_.num_padding_bytes);
  QUIC_BUG_IF(retransmission.retransmittable_frames.empty())
      << "Attempt to serialize empty packet";
  const QuicPacketNumberLength saved_length = packet_.packet_number_length;
  const QuicPacketNumberLength saved_next_length = next_packet_number_length_;
  const EncryptionLevel default_encryption_level = packet_.encryption_level;

  // Temporarily set the packet number length and change the encryption level.
  packet_.packet_number_length = retransmission.packet_number_length;
  if (!FLAGS_quic_simple_packet_number_length_2) {
    next_packet_number_length_ = retransmission.packet_number_length;
  }
  packet_.num_padding_bytes = retransmission.num_padding_bytes;
  // Only preserve the original encryption level if it's a handshake packet or
  // if we haven't gone forward secure.
  if (retransmission.has_crypto_handshake ||
      packet_.encryption_level != ENCRYPTION_FORWARD_SECURE) {
    packet_.encryption_level = retransmission.encryption_level;
  }

  // Serialize the packet and restore packet number length state.
  for (const QuicFrame& frame : retransmission.retransmittable_frames) {
    bool success = AddFrame(frame, false);
    QUIC_BUG_IF(!success) << " Failed to add frame of type:" << frame.type
                          << " num_frames:"
                          << retransmission.retransmittable_frames.size()
                          << " retransmission.packet_number_length:"
                          << retransmission.packet_number_length
                          << " packet_.packet_number_length:"
                          << packet_.packet_number_length;
  }
  SerializePacket(buffer, buffer_len);
  packet_.original_path_id = retransmission.path_id;
  packet_.original_packet_number = retransmission.packet_number;
  packet_.transmission_type = retransmission.transmission_type;
  OnSerializedPacket();
  // Restore old values.
  if (!FLAGS_quic_simple_packet_number_length_2) {
    // OnSerializedPacket updates the packet_number_length, so it's incorrect to
    // restore it here.
    packet_.packet_number_length = saved_length;
    next_packet_number_length_ = saved_next_length;
  }
  packet_.encryption_level = default_encryption_level;
}


//用来序列化当前数据包中的所有待发送帧,并通知上层。
void QuicPacketCreator::Flush() {
  if (!HasPendingFrames()) {
    return;
  }

  // TODO(rtenneti): Change the default 64 alignas value (used the default
  // value from CACHELINE_SIZE).
  //定义seralized_packet_buffer数组,长度为kMaxPacketSize,用于存放序列化后的数据包数据。
  ALIGNAS(64) char seralized_packet_buffer[kMaxPacketSize];
  //序列化一批frames
  SerializePacket(seralized_packet_buffer, kMaxPacketSize);
  //通知上层.
  OnSerializedPacket();
}

void QuicPacketCreator::OnSerializedPacket() {
  if (packet_.encrypted_buffer == nullptr) {
    const string error_details = "Failed to SerializePacket.";
    QUIC_BUG << error_details;
    delegate_->OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET,
                                    error_details,
                                    ConnectionCloseSource::FROM_SELF);
    return;
  }

  //通知上层
  delegate_->OnSerializedPacket(&packet_);
  //清空packet
  ClearPacket();
  // Maximum packet size may be only enacted while no packet is currently being
  // constructed, so here we have a good opportunity to actually change it.
  if (CanSetMaxPacketLength()) {
    SetMaxPacketLength(max_packet_length_);
  }
}

void QuicPacketCreator::ClearPacket() {
  packet_.has_ack = false;
  packet_.has_stop_waiting = false;
  packet_.has_crypto_handshake = NOT_HANDSHAKE;
  packet_.num_padding_bytes = 0;
  packet_.original_path_id = kInvalidPathId;
  packet_.original_packet_number = 0;
  packet_.transmission_type = NOT_RETRANSMISSION;
  packet_.encrypted_buffer = nullptr;
  packet_.encrypted_length = 0;
  DCHECK(packet_.retransmittable_frames.empty());
  packet_.listeners.clear();
}

void QuicPacketCreator::CreateAndSerializeStreamFrame(
    QuicStreamId id,
    const QuicIOVector& iov,
    QuicStreamOffset iov_offset,
    QuicStreamOffset stream_offset,
    bool fin,
    QuicAckListenerInterface* listener,
    size_t* num_bytes_consumed) {
  DCHECK(queued_frames_.empty());
  // Write out the packet header
  QuicPacketHeader header;
  FillPacketHeader(&header);
  ALIGNAS(64) char encrypted_buffer[kMaxPacketSize];
  QuicDataWriter writer(arraysize(encrypted_buffer), encrypted_buffer);
  if (!framer_->AppendPacketHeader(header, &writer)) {
    QUIC_BUG << "AppendPacketHeader failed";
    return;
  }

  // Create a Stream frame with the remaining space.
  QUIC_BUG_IF(iov_offset == iov.total_length && !fin)
      << "Creating a stream frame with no data or fin.";
  const size_t remaining_data_size = iov.total_length - iov_offset;
  const size_t min_frame_size = QuicFramer::GetMinStreamFrameSize(
      id, stream_offset, /* last_frame_in_packet= */ true);
  const size_t available_size =
      max_plaintext_size_ - writer.length() - min_frame_size;
  const size_t bytes_consumed =
      min<size_t>(available_size, remaining_data_size);

  const bool set_fin = fin && (bytes_consumed == remaining_data_size);
  UniqueStreamBuffer stream_buffer =
      NewStreamBuffer(buffer_allocator_, bytes_consumed);
  CopyToBuffer(iov, iov_offset, bytes_consumed, stream_buffer.get());
  std::unique_ptr<QuicStreamFrame> frame(new QuicStreamFrame(
      id, set_fin, stream_offset, bytes_consumed, std::move(stream_buffer)));
  DVLOG(1) << "Adding frame: " << *frame;

  // TODO(ianswett): AppendTypeByte and AppendStreamFrame could be optimized
  // into one method that takes a QuicStreamFrame, if warranted.
  if (!framer_->AppendTypeByte(QuicFrame(frame.get()),
                               /* no stream frame length */ true, &writer)) {
    QUIC_BUG << "AppendTypeByte failed";
    return;
  }
  if (!framer_->AppendStreamFrame(*frame, /* no stream frame length */ true,
                                  &writer)) {
    QUIC_BUG << "AppendStreamFrame failed";
    return;
  }

  size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.path_id, packet_.packet_number,
      GetStartOfEncryptedData(framer_->version(), header), writer.length(),
      arraysize(encrypted_buffer), encrypted_buffer);
  if (encrypted_length == 0) {
    QUIC_BUG << "Failed to encrypt packet number " << header.packet_number;
    return;
  }
  // TODO(ianswett): Optimize the storage so RetransmitableFrames can be
  // unioned with a QuicStreamFrame and a UniqueStreamBuffer.
  *num_bytes_consumed = bytes_consumed;
  packet_size_ = 0;
  packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
  packet_.encrypted_buffer = encrypted_buffer;
  packet_.encrypted_length = encrypted_length;
  if (listener != nullptr) {
    packet_.listeners.emplace_back(listener, bytes_consumed);
  }
  packet_.retransmittable_frames.push_back(QuicFrame(frame.release()));
  OnSerializedPacket();
}

bool QuicPacketCreator::HasPendingFrames() const {
  return !queued_frames_.empty();
}

bool QuicPacketCreator::HasPendingRetransmittableFrames() const {
  return !packet_.retransmittable_frames.empty();
}

size_t QuicPacketCreator::ExpansionOnNewFrame() const {
  // If the last frame in the packet is a stream frame, then it will expand to
  // include the stream_length field when a new frame is added.
  bool has_trailing_stream_frame =
      !queued_frames_.empty() && queued_frames_.back().type == STREAM_FRAME;
  return has_trailing_stream_frame ? kQuicStreamPayloadLengthSize : 0;
}

//过计算当前数据包剩余空间与新帧开销,实现了判断当前数据包是否有足够空间添加新帧的逻辑
size_t QuicPacketCreator::BytesFree() {
    //max_plaintext_size_是否大于等于当前数据包大小PacketSize()。
    //max_plaintext_size_表示数据包最大的明文负载大小,PacketSize()返回当前数据包的总大小。
  DCHECK_GE(max_plaintext_size_, PacketSize());
  //计算当前数据包大小加上在添加新帧后expansion的大小,取二者最小值
  //从max_plaintext_size_中减去上一步计算得到的最小值,得到剩余的空间字节数
  return max_plaintext_size_ -
         min(max_plaintext_size_, PacketSize() + ExpansionOnNewFrame());
}

size_t QuicPacketCreator::PacketSize() {
    //1.之前已经计算过,直接返回
  if (!queued_frames_.empty()) {
    return packet_size_;
  }
  // Update packet number length on packet boundary.
  if (!FLAGS_quic_simple_packet_number_length_2) {
    packet_.packet_number_length = next_packet_number_length_;
  }

  //
  packet_size_ = GetPacketHeaderSize(
      framer_->version(), connection_id_length_, send_version_in_packet_,
      send_path_id_in_packet_, IncludeNonceInPublicHeader(),
      packet_.packet_number_length);
  return packet_size_;
}

bool QuicPacketCreator::AddSavedFrame(const QuicFrame& frame) {
  return AddFrame(frame, /*save_retransmittable_frames=*/true);
}

bool QuicPacketCreator::AddPaddedSavedFrame(const QuicFrame& frame) {
  if (AddFrame(frame, /*save_retransmittable_frames=*/true)) {
    packet_.num_padding_bytes = -1;
    return true;
  }
  return false;
}

void QuicPacketCreator::AddAckListener(QuicAckListenerInterface* listener,
                                       QuicPacketLength length) {
  DCHECK(!queued_frames_.empty());
  packet_.listeners.emplace_back(listener, length);
}


//尝试序列化frames->packet
void QuicPacketCreator::SerializePacket(char* encrypted_buffer,
                                        size_t encrypted_buffer_len) {
  DCHECK_LT(0u, encrypted_buffer_len);
  QUIC_BUG_IF(queued_frames_.empty()) << "Attempt to serialize empty packet";
  QuicPacketHeader header;
  // FillPacketHeader increments packet_number_.
  //填充packet头部信息
  FillPacketHeader(&header);

  //判断是否需要padding以配合加密算法.
  MaybeAddPadding();

  DCHECK_GE(max_plaintext_size_, packet_size_);
  // Use the packet_size_ instead of the buffer size to ensure smaller
  // packet sizes are properly used.

  //frame->packet
  size_t length = framer_->BuildDataPacket(header, queued_frames_,
                                           encrypted_buffer, packet_size_);
  if (length == 0) {
    QUIC_BUG << "Failed to serialize " << queued_frames_.size() << " frames.";
    return;
  }

  // ACK Frames will be truncated due to length only if they're the only frame
  // in the packet, and if packet_size_ was set to max_plaintext_size_. If
  // truncation due to length occurred, then GetSerializedFrameLength will have
  // returned all bytes free.
  bool possibly_truncated_by_length = packet_size_ == max_plaintext_size_ &&
                                      queued_frames_.size() == 1 &&
                                      queued_frames_.back().type == ACK_FRAME;
  // Because of possible truncation, we can't be confident that our
  // packet size calculation worked correctly.
  if (!possibly_truncated_by_length) {
    DCHECK_EQ(packet_size_, length);
  }
  //加密
  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.path_id, packet_.packet_number,
      GetStartOfEncryptedData(framer_->version(), header), length,
      encrypted_buffer_len, encrypted_buffer);
  if (encrypted_length == 0) {
    QUIC_BUG << "Failed to encrypt packet number " << packet_.packet_number;
    return;
  }

  //保存packet
  packet_size_ = 0;
  queued_frames_.clear();
  packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
  packet_.encrypted_buffer = encrypted_buffer;
  packet_.encrypted_length = encrypted_length;
}

QuicEncryptedPacket* QuicPacketCreator::SerializeVersionNegotiationPacket(
    const QuicVersionVector& supported_versions) {
  DCHECK_EQ(Perspective::IS_SERVER, framer_->perspective());
  QuicEncryptedPacket* encrypted = QuicFramer::BuildVersionNegotiationPacket(
      connection_id_, supported_versions);
  DCHECK(encrypted);
  DCHECK_GE(max_packet_length_, encrypted->length());
  return encrypted;
}

// TODO(jri): Make this a public method of framer?
SerializedPacket QuicPacketCreator::NoPacket() {
  return SerializedPacket(kInvalidPathId, 0, PACKET_1BYTE_PACKET_NUMBER,
                          nullptr, 0, 0, false, false);
}

void QuicPacketCreator::FillPacketHeader(QuicPacketHeader* header) {
  header->public_header.connection_id = connection_id_;
  header->public_header.connection_id_length = connection_id_length_;
  header->public_header.multipath_flag = send_path_id_in_packet_;
  header->public_header.reset_flag = false;
  header->public_header.version_flag = send_version_in_packet_;
  if (IncludeNonceInPublicHeader()) {
    DCHECK_EQ(Perspective::IS_SERVER, framer_->perspective());
    header->public_header.nonce = &diversification_nonce_;
  } else {
    header->public_header.nonce = nullptr;
  }
  header->path_id = packet_.path_id;
  header->packet_number = ++packet_.packet_number;
  header->public_header.packet_number_length = packet_.packet_number_length;
  header->entropy_flag = random_bool_source_.RandBool();
}

bool QuicPacketCreator::ShouldRetransmit(const QuicFrame& frame) {
  switch (frame.type) {
    case ACK_FRAME:
    case PADDING_FRAME:
    case STOP_WAITING_FRAME:
    case MTU_DISCOVERY_FRAME:
      return false;
    default:
      return true;
  }
}



//主要用于将指定的数据帧添加到当前数据包中,并进行相应的标记和状态更新。它需要判断数据包加密状态和剩余空间来决定是否可以添加帧。
bool QuicPacketCreator::AddFrame(const QuicFrame& frame,
                                 bool save_retransmittable_frames) {
  DVLOG(1) << "Adding frame: " << frame;
  //如果待添加的数据帧是STREAM帧,且当前数据包未加密,则报告错误并返回false。因为未加密的数据包不允许发送STREAM数据
  if (frame.type == STREAM_FRAME &&
      frame.stream_frame->stream_id != kCryptoStreamId &&
      packet_.encryption_level == ENCRYPTION_NONE) {
    const string error_details = "Cannot send stream data without encryption.";
    QUIC_BUG << error_details;
    delegate_->OnUnrecoverableError(
        QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA, error_details,
        ConnectionCloseSource::FROM_SELF);
    return false;
  }

  if (!FLAGS_quic_simple_packet_number_length_2) {
    MaybeUpdatePacketNumberLength();
  }

  //调用framer_的GetSerializedFrameLength()方法计算待添加帧的序列化长度。
  size_t frame_len = framer_->GetSerializedFrameLength(
      frame, BytesFree(), queued_frames_.empty(), true,
      packet_.packet_number_length);
  //如果当前帧无法添加返回0,进而调用Flush()方法发送当前数据包,并返回false.
  if (frame_len == 0) {
    // Current open packet is full.
    Flush();
    return false;
  }
  DCHECK_LT(0u, packet_size_);
  //更新当前数据包大小packet_size_,增加ExpansionOnNewFrame()和序列化长度frame_len。
  packet_size_ += ExpansionOnNewFrame() + frame_len;

    //如果待添加的帧需要重传,则将其添加到重传队列和待发送队列中。如果是加密数据流的帧,则标记当前数据包为包含加密握手数据。
    if (save_retransmittable_frames && ShouldRetransmit(frame)) {
    if (packet_.retransmittable_frames.empty()) {
      packet_.retransmittable_frames.reserve(2);
    }
    packet_.retransmittable_frames.push_back(frame);
    queued_frames_.push_back(frame);
    //如果该数据帧是加密握手数据，则将当前数据包标记为包含已经加密的数据。
    if (frame.type == STREAM_FRAME &&
        frame.stream_frame->stream_id == kCryptoStreamId) {
      packet_.has_crypto_handshake = IS_HANDSHAKE;
    }
  //直接添加到缓存队列中
  } else {
    queued_frames_.push_back(frame);
  }

  //如果添加的是ACK帧,则标记当前数据包包含ACK;如果是STOP_WAITING帧,标记包含该帧。
  if (frame.type == ACK_FRAME) {
    packet_.has_ack = true;
  }
  if (frame.type == STOP_WAITING_FRAME) {
    packet_.has_stop_waiting = true;
  }
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnFrameAddedToPacket(frame);
  }

  return true;
}

void QuicPacketCreator::MaybeAddPadding() {
  if (packet_.num_padding_bytes == 0) {
    return;
  }

  if (BytesFree() == 0) {
    // Don't pad full packets.
    return;
  }

  bool success =
      AddFrame(QuicFrame(QuicPaddingFrame(packet_.num_padding_bytes)), false);
  DCHECK(success);
}

void QuicPacketCreator::SetCurrentPath(
    QuicPathId path_id,
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  if (packet_.path_id == path_id) {
    return;
  }

  if (HasPendingFrames()) {
    QUIC_BUG << "Unable to change paths when a packet is under construction.";
    return;
  }
  // Save current packet number and load switching path's packet number.
  multipath_packet_number_[packet_.path_id] = packet_.packet_number;
  std::unordered_map<QuicPathId, QuicPacketNumber>::iterator it =
      multipath_packet_number_.find(path_id);
  // If path_id is not in the map, it's a new path. Set packet_number to 0.
  packet_.packet_number = it == multipath_packet_number_.end() ? 0 : it->second;
  packet_.path_id = path_id;
  DCHECK(packet_.path_id != kInvalidPathId);
  // Send path in packet if current path is not the default path.
  send_path_id_in_packet_ = packet_.path_id != kDefaultPathId ? true : false;
  // Switching path needs to update packet number length.
  UpdatePacketNumberLength(least_packet_awaited_by_peer, max_packets_in_flight);
}

bool QuicPacketCreator::IncludeNonceInPublicHeader() {
  return have_diversification_nonce_ &&
         packet_.encryption_level == ENCRYPTION_INITIAL;
}

QuicPacketCreator::QuicRandomBoolSource::QuicRandomBoolSource(
    QuicRandom* random)
    : random_(random), bit_bucket_(0), bit_mask_(0) {}

QuicPacketCreator::QuicRandomBoolSource::~QuicRandomBoolSource() {}

bool QuicPacketCreator::QuicRandomBoolSource::RandBool() {
  if (bit_mask_ == 0) {
    bit_bucket_ = random_->RandUint64();
    bit_mask_ = 1;
  }
  bool result = ((bit_bucket_ & bit_mask_) != 0);
  bit_mask_ <<= 1;
  return result;
}

}  // namespace net
