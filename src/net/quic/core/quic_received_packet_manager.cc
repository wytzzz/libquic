// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_received_packet_manager.h"

#include <limits>
#include <utility>

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_connection_stats.h"
#include "net/quic/core/quic_flags.h"

using std::max;
using std::min;
using std::numeric_limits;

namespace net {

namespace {

// The maximum number of packets to ack immediately after a missing packet for
// fast retransmission to kick in at the sender.  This limit is created to
// reduce the number of acks sent that have no benefit for fast retransmission.
// Set to the number of nacks needed for fast retransmit plus one for protection
// against an ack loss
const size_t kMaxPacketsAfterNewMissing = 4;
}

QuicReceivedPacketManager::EntropyTracker::EntropyTracker()
    : packets_entropy_hash_(0), first_gap_(1), largest_observed_(0) {}

QuicReceivedPacketManager::EntropyTracker::~EntropyTracker() {}

QuicPacketEntropyHash QuicReceivedPacketManager::EntropyTracker::EntropyHash(
    QuicPacketNumber packet_number) const {
  DCHECK_LE(packet_number, largest_observed_);
  if (packet_number == largest_observed_) {
    return packets_entropy_hash_;
  }

  DCHECK_GE(packet_number, first_gap_);
  DCHECK_EQ(first_gap_ + packets_entropy_.size() - 1, largest_observed_);
  QuicPacketEntropyHash hash = packets_entropy_hash_;
  ReceivedEntropyHashes::const_reverse_iterator it = packets_entropy_.rbegin();
  for (QuicPacketNumber i = 0; i < (largest_observed_ - packet_number);
       ++i, ++it) {
    hash ^= it->first;
  }
  return hash;
}

void QuicReceivedPacketManager::EntropyTracker::RecordPacketEntropyHash(
    QuicPacketNumber packet_number,
    QuicPacketEntropyHash entropy_hash) {
  if (packet_number < first_gap_) {
    DVLOG(1) << "Ignoring received packet entropy for packet_number:"
             << packet_number
             << " less than largest_peer_packet_number:" << first_gap_;
    return;
  }
  // RecordPacketEntropyHash is only intended to be called once per packet.
  DCHECK(packet_number > largest_observed_ ||
         !packets_entropy_[packet_number - first_gap_].second);

  packets_entropy_hash_ ^= entropy_hash;

  // Optimize the typical case of no gaps.
  if (packet_number == largest_observed_ + 1 && packets_entropy_.empty()) {
    ++first_gap_;
    largest_observed_ = packet_number;
    return;
  }
  if (packet_number > largest_observed_) {
    for (QuicPacketNumber i = 0; i < (packet_number - largest_observed_ - 1);
         ++i) {
      packets_entropy_.push_back(std::make_pair(0, false));
    }
    packets_entropy_.push_back(std::make_pair(entropy_hash, true));
    largest_observed_ = packet_number;
  } else {
    packets_entropy_[packet_number - first_gap_] =
        std::make_pair(entropy_hash, true);
    AdvanceFirstGapAndGarbageCollectEntropyMap();
  }

  DVLOG(2) << "setting cumulative received entropy hash to: "
           << static_cast<int>(packets_entropy_hash_)
           << " updated with packet number " << packet_number
           << " entropy hash: " << static_cast<int>(entropy_hash);
}

void QuicReceivedPacketManager::EntropyTracker::SetCumulativeEntropyUpTo(
    QuicPacketNumber packet_number,
    QuicPacketEntropyHash entropy_hash) {
  DCHECK_LE(packet_number, largest_observed_);
  if (packet_number < first_gap_) {
    DVLOG(1) << "Ignoring set entropy at:" << packet_number
             << " less than first_gap_:" << first_gap_;
    return;
  }
  while (first_gap_ < packet_number) {
    ++first_gap_;
    if (!packets_entropy_.empty()) {
      packets_entropy_.pop_front();
    }
  }
  // Compute the current entropy by XORing in all entropies received including
  // and since packet_number.
  packets_entropy_hash_ = entropy_hash;
  for (ReceivedEntropyHashes::const_iterator it = packets_entropy_.begin();
       it != packets_entropy_.end(); ++it) {
    packets_entropy_hash_ ^= it->first;
  }

  // Garbage collect entries from the beginning of the map.
  AdvanceFirstGapAndGarbageCollectEntropyMap();
}

void QuicReceivedPacketManager::EntropyTracker::
    AdvanceFirstGapAndGarbageCollectEntropyMap() {
  while (!packets_entropy_.empty() && packets_entropy_.front().second) {
    ++first_gap_;
    packets_entropy_.pop_front();
  }
}

QuicReceivedPacketManager::QuicReceivedPacketManager(QuicConnectionStats* stats)
    : peer_least_packet_awaiting_ack_(0),
      ack_frame_updated_(false),
      time_largest_observed_(QuicTime::Zero()),
      stats_(stats) {
  ack_frame_.largest_observed = 0;
  ack_frame_.entropy_hash = 0;
}

QuicReceivedPacketManager::~QuicReceivedPacketManager() {}

void QuicReceivedPacketManager::RecordPacketReceived(
    QuicByteCount bytes,
    const QuicPacketHeader& header,
    QuicTime receipt_time) {
  QuicPacketNumber packet_number = header.packet_number;
  //检查该报文对端是否还在等待?
  DCHECK(IsAwaitingPacket(packet_number));

  if (!ack_frame_updated_) {
    ack_frame_.received_packet_times.clear();
  }
  ack_frame_updated_ = true;

  if (ack_frame_.missing) {
    // Adds the range of packet numbers from max(largest observed + 1, least
    // awaiting ack) up to packet_number not including packet_number.
    ack_frame_.packets.Add(
        max(ack_frame_.largest_observed + 1, peer_least_packet_awaiting_ack_),
        packet_number);
  } else {
    ack_frame_.packets.Add(header.packet_number);
  }

  //检查报文号与largest observed 的关系:
  //如果当前报文号小于largest observed(意味着乱序):
  if (ack_frame_.largest_observed > packet_number) {
    if (ack_frame_.missing) {
      // We've gotten one of the out of order packets - remove it from our
      // "missing packets" list.
      DVLOG(1) << "Removing " << packet_number << " from missing list";
      ack_frame_.packets.Remove(packet_number);
    }

    // Record how out of order stats.
    ++stats_->packets_reordered;
    stats_->max_sequence_reordering =
        max(stats_->max_sequence_reordering,
            ack_frame_.largest_observed - packet_number);
    int64_t reordering_time_us =
        (receipt_time - time_largest_observed_).ToMicroseconds();
    stats_->max_time_reordering_us =
        max(stats_->max_time_reordering_us, reordering_time_us);
  }


  if (packet_number > ack_frame_.largest_observed) {
    ack_frame_.largest_observed = packet_number;
    time_largest_observed_ = receipt_time;
  }


  if (ack_frame_.missing) {
    entropy_tracker_.RecordPacketEntropyHash(packet_number,
                                             header.entropy_hash);
  }

  //增加应答时间
  ack_frame_.received_packet_times.push_back(
      std::make_pair(packet_number, receipt_time));
}

bool QuicReceivedPacketManager::IsMissing(QuicPacketNumber packet_number) {
  if (ack_frame_.missing) {
    return ack_frame_.packets.Contains(packet_number);
  }
  return packet_number < ack_frame_.largest_observed &&
         !ack_frame_.packets.Contains(packet_number);
}

bool QuicReceivedPacketManager::IsAwaitingPacket(
    QuicPacketNumber packet_number) {
  return ::net::IsAwaitingPacket(ack_frame_, packet_number,
                                 peer_least_packet_awaiting_ack_);
}

namespace {
struct isTooLarge {
  explicit isTooLarge(QuicPacketNumber n) : largest_observed_(n) {}
  QuicPacketNumber largest_observed_;

  // Return true if the packet in p is too different from largest_observed_
  // to express.
  bool operator()(const std::pair<QuicPacketNumber, QuicTime>& p) const {
    return largest_observed_ - p.first >= numeric_limits<uint8_t>::max();
  }
};
}  // namespace


//生成ACK帧需要的 QuicAckFrame 结构
//返回一个包含该ACK帧的QuicFrame
const QuicFrame QuicReceivedPacketManager::GetUpdatedAckFrame(
    QuicTime approximate_now) {
    //首先标记ACK帧已更新
  ack_frame_updated_ = false;
  //如果ACK帧表示缺失报文,则计算其熵和
  if (ack_frame_.missing) {
    ack_frame_.entropy_hash = EntropyHash(ack_frame_.largest_observed);
  }

    //计算ACK延迟时间
    //如果未接收报文,则设置为无限大
    //则,取 approximate_now 和 time_largest_observed_之间的时间差
  if (time_largest_observed_ == QuicTime::Zero()) {
    // We have received no packets.
    ack_frame_.ack_delay_time = QuicTime::Delta::Infinite();
  } else {
    // Ensure the delta is zero if approximate now is "in the past".
    ack_frame_.ack_delay_time = approximate_now < time_largest_observed_
                                    ? QuicTime::Delta::Zero()
                                    : approximate_now - time_largest_observed_;
  }

  //清除报文接收时间列表中时间太不连续的已接收报文
  //使用QuicAckFrame结构体创建一个QuicFrame对象
  // Clear all packet times if any are too far from largest observed.
  // It's expected this is extremely rare.
  for (PacketTimeVector::iterator it = ack_frame_.received_packet_times.begin();
       it != ack_frame_.received_packet_times.end();) {
    if (ack_frame_.largest_observed - it->first >=
        numeric_limits<uint8_t>::max()) {
      it = ack_frame_.received_packet_times.erase(it);
    } else {
      ++it;
    }
  }
    //返回QuicFrame
  return QuicFrame(&ack_frame_);
}

QuicPacketEntropyHash QuicReceivedPacketManager::EntropyHash(
    QuicPacketNumber packet_number) const {
  return entropy_tracker_.EntropyHash(packet_number);
}

bool QuicReceivedPacketManager::DontWaitForPacketsBefore(
    QuicPacketNumber least_unacked) {
  peer_least_packet_awaiting_ack_ = least_unacked;
  return ack_frame_.packets.RemoveUpTo(least_unacked);
}


//根据对端的StopWaiting帧,更新本地的内部状态
void QuicReceivedPacketManager::UpdatePacketInformationSentByPeer(
    const QuicStopWaitingFrame& stop_waiting) {
  // ValidateAck() should fail if peer_least_packet_awaiting_ack shrinks.
  DCHECK_LE(peer_least_packet_awaiting_ack_, stop_waiting.least_unacked);
  //获取StopWaiting帧的least_unacked字段,表示peer不再等待小于此值的包。
  if (stop_waiting.least_unacked > peer_least_packet_awaiting_ack_) {
    bool packets_updated = DontWaitForPacketsBefore(stop_waiting.least_unacked);
    if (packets_updated) {
        //如果之前有缺失包(ack_frame_.missing 为true),由于部分包永远收不到了,需要更新熵:
      if (ack_frame_.missing) {
        DVLOG(1) << "Updating entropy hashed since we missed packets";
        // There were some missing packets that we won't ever get now.
        // Recalculate the received entropy hash.
        entropy_tracker_.SetCumulativeEntropyUpTo(stop_waiting.least_unacked,
                                                  stop_waiting.entropy_hash);
      }
      // Ack frame gets updated because packets set is updated because of stop
      // waiting frame.
      //设置标志 ack_frame_updated_为true,表示ACK帧需要更新
      ack_frame_updated_ = true;
    }
  }
  //要求最小包号大于等于peer_least_packet_awaiting_ack_
  DCHECK(ack_frame_.packets.Empty() ||
         ack_frame_.packets.Min() >= peer_least_packet_awaiting_ack_);
}

bool QuicReceivedPacketManager::HasMissingPackets() const {
  if (ack_frame_.missing) {
    return !ack_frame_.packets.Empty();
  }

  return ack_frame_.packets.NumIntervals() > 1 ||
         (!ack_frame_.packets.Empty() &&
          ack_frame_.packets.Min() >
              max(QuicPacketNumber(1), peer_least_packet_awaiting_ack_));
}

//此函数检查是否存在新的待报告的丢失报文
bool QuicReceivedPacketManager::HasNewMissingPackets() const {

    //且最大缺失报文号与已接收最大报文号之差符合阈值
  if (ack_frame_.missing) {
    return !ack_frame_.packets.Empty() &&
           (ack_frame_.largest_observed - ack_frame_.packets.Max()) <=
               kMaxPacketsAfterNewMissing;
  }

  return HasMissingPackets() &&
         ack_frame_.packets.LastIntervalLength() <= kMaxPacketsAfterNewMissing;
}

size_t QuicReceivedPacketManager::NumTrackedPackets() const {
  return entropy_tracker_.size();
}

void QuicReceivedPacketManager::SetVersion(QuicVersion version) {
  ack_frame_.missing = version <= QUIC_VERSION_33;
}

bool QuicReceivedPacketManager::ack_frame_updated() const {
  return ack_frame_updated_;
}

QuicPacketNumber QuicReceivedPacketManager::GetLargestObserved() const {
  return ack_frame_.largest_observed;
}

}  // namespace net
