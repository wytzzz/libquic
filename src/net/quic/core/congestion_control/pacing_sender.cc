// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/pacing_sender.h"

#include <string>

#include "net/quic/core/quic_flags.h"

using std::min;

namespace net {
namespace {

// The estimated system alarm granularity.
static const QuicTime::Delta kAlarmGranularity =
    QuicTime::Delta::FromMilliseconds(1);

// Configured maximum size of the burst coming out of quiescence.  The burst
// is never larger than the current CWND in packets.
static const uint32_t kInitialUnpacedBurst = 10;

}  // namespace

PacingSender::PacingSender()
    : sender_(nullptr),
      max_pacing_rate_(QuicBandwidth::Zero()),
      burst_tokens_(kInitialUnpacedBurst),
      last_delayed_packet_sent_time_(QuicTime::Zero()),
      ideal_next_packet_send_time_(QuicTime::Zero()),
      was_last_send_delayed_(false) {}

PacingSender::~PacingSender() {}

void PacingSender::set_sender(SendAlgorithmInterface* sender) {
  DCHECK(sender != nullptr);
  sender_ = sender;
}


void PacingSender::OnCongestionEvent(
    bool rtt_updated,
    QuicByteCount bytes_in_flight,
    const SendAlgorithmInterface::CongestionVector& acked_packets,
    const SendAlgorithmInterface::CongestionVector& lost_packets) {
  DCHECK(sender_ != nullptr);
  //进入丢包恢复,不能在burst发包了.
  if (!lost_packets.empty()) {
    // Clear any burst tokens when entering recovery.
    burst_tokens_ = 0;
  }
  sender_->OnCongestionEvent(rtt_updated, bytes_in_flight, acked_packets,
                             lost_packets);
}

bool PacingSender::OnPacketSent(
    QuicTime sent_time,
    QuicByteCount bytes_in_flight,
    QuicPacketNumber packet_number,
    QuicByteCount bytes,
    HasRetransmittableData has_retransmittable_data) {
  DCHECK(sender_ != nullptr);
  //首先调用底层Sender的OnPacketSent()方法,获取是否应计算在flight中
  const bool in_flight =
      sender_->OnPacketSent(sent_time, bytes_in_flight, packet_number, bytes,
                            has_retransmittable_data);
  //如果是非重传数据,则直接返回.
  if (has_retransmittable_data != HAS_RETRANSMITTABLE_DATA) {
    return in_flight;
  }
  // If in recovery, the connection is not coming out of quiescence.
  //判断是否从静止变为活跃状态,是的话还是允许增加一些burst的.
  if (bytes_in_flight == 0 && !sender_->InRecovery()) {
    // Add more burst tokens anytime the connection is leaving quiescence, but
    // limit it to the equivalent of a single bulk write, not exceeding the
    // current CWND in packets.
    //kInitialUnpacedBurst 的最小值和CWND允许的最大未限速包
    burst_tokens_ = min(
        kInitialUnpacedBurst,
        static_cast<uint32_t>(sender_->GetCongestionWindow() / kDefaultTCPMSS));
  }

  //如果有burst tokens
  if (burst_tokens_ > 0) {
    --burst_tokens_;
    was_last_send_delayed_ = false;
    last_delayed_packet_sent_time_ = QuicTime::Zero();
    //立即发送
    ideal_next_packet_send_time_ = QuicTime::Zero();
    return in_flight;
  }

  //如果不能burst发送,则需要平滑发送了.


  // The next packet should be sent as soon as the current packet has been
  // transferred.  PacingRate is based on bytes in flight including this packet.
  //计算发包延迟
  QuicTime::Delta delay =
      PacingRate(bytes_in_flight + bytes).TransferTime(bytes);
  // If the last send was delayed, and the alarm took a long time to get
  // invoked, allow the connection to make up for lost time.
  //如果上一个包已经被延迟了,看看能不能补偿一下提前发送
  if (was_last_send_delayed_) {
    ideal_next_packet_send_time_ = ideal_next_packet_send_time_ + delay;
    // The send was application limited if it takes longer than the
    // pacing delay between sent packets.
    //判断是否为应用受限状态
    const bool application_limited =
        last_delayed_packet_sent_time_.IsInitialized() &&
        sent_time > last_delayed_packet_sent_time_ + delay;
    //如果 ideal_next_packet_send_time_(下一个延迟包应该发送的时间) 小于 当前包的实际发送时间,表示正在补偿 lost time。
      const bool making_up_for_lost_time =
        ideal_next_packet_send_time_ <= sent_time;
    // As long as we're making up time and not application limited,
    // continue to consider the packets delayed, allowing the packets to be
    // sent immediately.
    //非应用受限状态下,发送得太慢了,标记为被延迟ile.
    if (making_up_for_lost_time && !application_limited) {
      last_delayed_packet_sent_time_ = sent_time;
    } else {
        //应用受限立即发送
      was_last_send_delayed_ = false;
      last_delayed_packet_sent_time_ = QuicTime::Zero();
    }
  //表示上一个包没有被延迟
  } else {
    //设置下一个包的发送时间
    ideal_next_packet_send_time_ =
        std::max(ideal_next_packet_send_time_ + delay, sent_time + delay);
  }
  return in_flight;
}


QuicTime::Delta PacingSender::TimeUntilSend(
    QuicTime now,
    QuicByteCount bytes_in_flight) const {
  DCHECK(sender_ != nullptr);
  //
  QuicTime::Delta time_until_send =
      sender_->TimeUntilSend(now, bytes_in_flight);

  if (burst_tokens_ > 0 || bytes_in_flight == 0) {
    // Don't pace if we have burst tokens available or leaving quiescence.
    return time_until_send;
  }

  if (!time_until_send.IsZero()) {
    DCHECK(time_until_send.IsInfinite());
    // The underlying sender prevents sending.
    return time_until_send;
  }

  //如果大于kAlarmGranularity(一个固定值),标记为延迟发送
  // If the next send time is within the alarm granularity, send immediately.
  if (ideal_next_packet_send_time_ > now + kAlarmGranularity) {
    DVLOG(1) << "Delaying packet: "
             << (ideal_next_packet_send_time_ - now).ToMicroseconds();
    was_last_send_delayed_ = true;
    return ideal_next_packet_send_time_ - now;
  }

  DVLOG(1) << "Sending packet now";
  return QuicTime::Delta::Zero();
}

QuicBandwidth PacingSender::PacingRate(QuicByteCount bytes_in_flight) const {
  DCHECK(sender_ != nullptr);
  if (!max_pacing_rate_.IsZero()) {
    return QuicBandwidth::FromBitsPerSecond(
        min(max_pacing_rate_.ToBitsPerSecond(),
            sender_->PacingRate(bytes_in_flight).ToBitsPerSecond()));
  }
  return sender_->PacingRate(bytes_in_flight);
}

}  // namespace net
