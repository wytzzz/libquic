// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/general_loss_algorithm.h"

#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_protocol.h"

namespace net {

namespace {

// The minimum delay before a packet will be considered lost,
// regardless of SRTT.  Half of the minimum TLP, since the loss algorithm only
// triggers when a nack has been receieved for the packet.
static const size_t kMinLossDelayMs = 5;

// Default fraction of an RTT the algorithm waits before determining a packet is
// lost due to early retransmission by time based loss detection.
static const int kDefaultLossDelayShift = 2;
// Default fraction of an RTT when doing adaptive loss detection.
static const int kDefaultAdaptiveLossDelayShift = 4;

}  // namespace

GeneralLossAlgorithm::GeneralLossAlgorithm()
    : loss_detection_timeout_(QuicTime::Zero()),
      largest_sent_on_spurious_retransmit_(0),
      loss_type_(kNack),
      reordering_shift_(kDefaultLossDelayShift) {}

GeneralLossAlgorithm::GeneralLossAlgorithm(LossDetectionType loss_type)
    : loss_detection_timeout_(QuicTime::Zero()),
      largest_sent_on_spurious_retransmit_(0),
      loss_type_(loss_type),
      reordering_shift_(loss_type == kAdaptiveTime
                            ? kDefaultAdaptiveLossDelayShift
                            : kDefaultLossDelayShift) {}

LossDetectionType GeneralLossAlgorithm::GetLossDetectionType() const {
  return loss_type_;
}

void GeneralLossAlgorithm::SetLossDetectionType(LossDetectionType loss_type) {
  loss_detection_timeout_ = QuicTime::Zero();
  largest_sent_on_spurious_retransmit_ = 0;
  loss_type_ = loss_type;
  reordering_shift_ = loss_type == kAdaptiveTime
                          ? kDefaultAdaptiveLossDelayShift
                          : kDefaultLossDelayShift;
}

// Uses nack counts to decide when packets are lost.
void GeneralLossAlgorithm::DetectLosses(
    const QuicUnackedPacketMap& unacked_packets,
    QuicTime time,
    const RttStats& rtt_stats,
    QuicPacketNumber largest_newly_acked,
    SendAlgorithmInterface::CongestionVector* packets_lost) {

  loss_detection_timeout_ = QuicTime::Zero();
  QuicTime::Delta max_rtt =
      std::max(rtt_stats.previous_srtt(), rtt_stats.latest_rtt());
  QuicTime::Delta loss_delay =
      std::max(QuicTime::Delta::FromMilliseconds(kMinLossDelayMs),
               max_rtt + (max_rtt >> reordering_shift_));

  //
  QuicPacketNumber packet_number = unacked_packets.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets.begin();
       it != unacked_packets.end() && packet_number <= largest_newly_acked;
       ++it, ++packet_number) {
    if (!it->in_flight) {
      continue;
    }


    if (loss_type_ == kNack) {
      // FACK based loss detection.
      //向前3个序号
      if (largest_newly_acked - packet_number >=
          kNumberOfNacksBeforeRetransmission) {
        packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
        continue;
      }
    }

    // Only early retransmit(RFC5827) when the last packet gets acked and
    // there are retransmittable packets in flight.
    // This also implements a timer-protected variant of FACK.

    //。如果当前的丢包检测类型是kTime或kAdaptiveTime，或者当前包是最后一个未确认的包并且它是可重传的，
    // 则会使用基于时间的检测算法来判断该包是否已经丢失。
    if ((!it->retransmittable_frames.empty() &&
         unacked_packets.largest_sent_packet() == largest_newly_acked) ||
        (loss_type_ == kTime || loss_type_ == kAdaptiveTime)) {
        //计算超时时间
      QuicTime when_lost = it->sent_time + loss_delay;

        //未超时
      if (time < when_lost) {
        loss_detection_timeout_ = when_lost;
        break;
      }
      //超时,基于绝对发送时间判断丢包
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }

    // NACK-based loss detection allows for a max reordering window of 1 RTT.
    //基于相对发送时间判断丢包
    //如果发现该包的相对发送时间（即该包的发送时间相对于最新确认的包的发送时间）超过了一个RTT的时间，则认为该包已经丢失。
    //这个检测窗口的大小是1个RTT，因为基于NACK的丢包检测算法可以容忍一个RTT的乱序。
    if (it->sent_time + rtt_stats.smoothed_rtt() <
        unacked_packets.GetTransmissionInfo(largest_newly_acked).sent_time) {
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }
  }
}


QuicTime GeneralLossAlgorithm::GetLossTimeout() const {
  return loss_detection_timeout_;
}


void GeneralLossAlgorithm::SpuriousRetransmitDetected(
    const QuicUnackedPacketMap& unacked_packets,
    QuicTime time,
    const RttStats& rtt_stats,
    QuicPacketNumber spurious_retransmission) {
    //该算法会判断当前的丢包检测类型是否为kAdaptiveTime，以及当前的reordering_shift_是否非零。如果不是，则直接返回。
  if (loss_type_ != kAdaptiveTime || reordering_shift_ == 0) {
    return;
  }

  //
  if (spurious_retransmission <= largest_sent_on_spurious_retransmit_) {
    return;
  }
  largest_sent_on_spurious_retransmit_ = unacked_packets.largest_sent_packet();
  // Calculate the extra time needed so this wouldn't have been declared lost.
  // Extra time needed is based on how long it's been since the spurious
  // retransmission was sent, because the SRTT and latest RTT may have changed.
  //算法会计算出extra_time_needed，即当前时间与虚假重传包的发送时间之间的时间差，然后将reordering_shift_逐渐减小，
  //直到计算出的proposed_extra_time大于等于extra_time_needed或者reordering_shift_为0为止

  //该算法只适用于基于时间的丢包检测算法，因为只有在该算法中才存在灵敏度的问题。在基于NACK的丢包检测算法中，
  //虚假重传不会导致错误的丢包判断，因为该算法是基于相对发送时间的
  //计算乱序早发的时间,作为delay的叠加. 即delay+extra_delay.
  QuicTime::Delta extra_time_needed =
      time -
      unacked_packets.GetTransmissionInfo(spurious_retransmission).sent_time;
  // Increase the reordering fraction until enough time would be allowed.
  QuicTime::Delta max_rtt =
      std::max(rtt_stats.previous_srtt(), rtt_stats.latest_rtt());
  QuicTime::Delta proposed_extra_time(QuicTime::Delta::Zero());
  do {
    proposed_extra_time = max_rtt >> reordering_shift_;
    --reordering_shift_;
  } while (proposed_extra_time < extra_time_needed && reordering_shift_ > 0);
}

}  // namespace net
