// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/tcp_cubic_sender_bytes.h"

#include <algorithm>

#include "net/quic/core/congestion_control/prr_sender.h"
#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_flags.h"

using std::max;
using std::min;

namespace net {

namespace {
// Constants based on TCP defaults.
// The minimum cwnd based on RFC 3782 (TCP NewReno) for cwnd reductions on a
// fast retransmission.
const QuicByteCount kDefaultMinimumCongestionWindow = 2 * kDefaultTCPMSS;
}  // namespace

TcpCubicSenderBytes::TcpCubicSenderBytes(
    const QuicClock* clock,
    const RttStats* rtt_stats,
    bool reno,
    QuicPacketCount initial_tcp_congestion_window,
    QuicPacketCount max_congestion_window,
    QuicConnectionStats* stats)
    : TcpCubicSenderBase(clock, rtt_stats, reno, stats),
      cubic_(clock),
      num_acked_packets_(0),
      congestion_window_(initial_tcp_congestion_window * kDefaultTCPMSS),
      min_congestion_window_(kDefaultMinimumCongestionWindow),
      max_congestion_window_(max_congestion_window * kDefaultTCPMSS),
      slowstart_threshold_(max_congestion_window * kDefaultTCPMSS),
      initial_tcp_congestion_window_(initial_tcp_congestion_window *
                                     kDefaultTCPMSS),
      initial_max_tcp_congestion_window_(max_congestion_window *
                                         kDefaultTCPMSS),
      min_slow_start_exit_window_(min_congestion_window_) {}

TcpCubicSenderBytes::~TcpCubicSenderBytes() {}

//设置带宽和rtt,设置cnwd
void TcpCubicSenderBytes::SetCongestionWindowFromBandwidthAndRtt(
    QuicBandwidth bandwidth,
    QuicTime::Delta rtt) {
    //bandwidth -> cwnd
  QuicByteCount new_congestion_window = bandwidth.ToBytesPerPeriod(rtt);
  //[min_congestion_window_ ,kMaxResumptionCongestionWindow * kDefaultTCPMSS]
  if (FLAGS_quic_no_lower_bw_resumption_limit) {
    // Limit new CWND if needed.
    congestion_window_ =
        max(min_congestion_window_,
            min(new_congestion_window,
                kMaxResumptionCongestionWindow * kDefaultTCPMSS));
  //[kMinCongestionWindowForBandwidthResumption * kDefaultTCPMSS, kMaxResumptionCongestionWindow * kDefaultTCPMSS]
  } else {
    congestion_window_ =
        max(min(new_congestion_window,
                kMaxResumptionCongestionWindow * kDefaultTCPMSS),
            kMinCongestionWindowForBandwidthResumption * kDefaultTCPMSS);
  }
}

void TcpCubicSenderBytes::SetCongestionWindowInPackets(
    QuicPacketCount congestion_window) {
  congestion_window_ = congestion_window * kDefaultTCPMSS;
}

void TcpCubicSenderBytes::SetMinCongestionWindowInPackets(
    QuicPacketCount congestion_window) {
  min_congestion_window_ = congestion_window * kDefaultTCPMSS;
}

void TcpCubicSenderBytes::SetNumEmulatedConnections(int num_connections) {
  TcpCubicSenderBase::SetNumEmulatedConnections(num_connections);
  cubic_.SetNumConnections(num_connections_);
}

void TcpCubicSenderBytes::ExitSlowstart() {
  slowstart_threshold_ = congestion_window_;
}

void TcpCubicSenderBytes::OnPacketLost(QuicPacketNumber packet_number,
                                       QuicByteCount lost_bytes,
                                       QuicByteCount bytes_in_flight) {
  // TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
  // already sent should be treated as a single loss event, since it's expected.
  //把多个lost认为是一个lost.
  //第一个lost来的时候,largest_sent_at_last_cutback_ = max_send.
  //如果在largest_sent_at_last_cutback_之前丢的包都
  //首先检查如果丢失的数据包是之前已经发送的,则忽略(可能是由于延迟)。
  if (packet_number <= largest_sent_at_last_cutback_) {
      //在慢速启动中拥塞
    if (last_cutback_exited_slowstart_) {
      ++stats_->slowstart_packets_lost;
      stats_->slowstart_bytes_lost += lost_bytes;
      //如果仍在缓慢启动模式中遇到数据包丢失
      //则对拥塞窗口进行较大幅度的减小,以快速减少发送速度,并将慢启动阈值设置为当前窗口,退出缓慢启动模式
      if (slow_start_large_reduction_) {
        // Reduce congestion window by lost_bytes for every loss.
        congestion_window_ =
            max(congestion_window_ - lost_bytes, min_slow_start_exit_window_);
        slowstart_threshold_ = congestion_window_;
      }
    }
    DVLOG(1) << "Ignoring loss for largest_missing:" << packet_number
             << " because it was sent prior to the last CWND cutback.";
    return;
  }


  ++stats_->tcp_loss_events;
  //在缓慢启动模式下,拥塞窗口以指数级增长。一旦发生丢包,很可能表示网络已拥塞。
  //所以数据包丢失时,TCP会退出缓慢启动模式,进入拥塞避免(congestion avoidance)模式
  last_cutback_exited_slowstart_ = InSlowStart();
  if (InSlowStart()) {
    ++stats_->slowstart_packets_lost;
  }

  if (!no_prr_) {
    prr_.OnPacketLost(bytes_in_flight);
  }

  // TODO(jri): Separate out all of slow start into a separate class.
  //如果慢速启动中,并且允许在慢启动阶段快速降低cwnd
  if (slow_start_large_reduction_ && InSlowStart()) {
    DCHECK_LT(kDefaultTCPMSS, congestion_window_);
    //检查拥塞窗口大于等于 2 倍初始慢启动窗口,会将最小慢启动退出窗口设为当前值的一半
    if (congestion_window_ >= 2 * initial_tcp_congestion_window_) {
      min_slow_start_exit_window_ = congestion_window_ / 2;
    }
    //然后将拥塞窗口减少 kDefaultTCPMSS 的值,以快速减小发送速度
    congestion_window_ = congestion_window_ - kDefaultTCPMSS;
  //如果是reno拥塞控制算法,,则应用 RenoBeta() 公式更新窗口
  } else if (reno_) {
      // Cubic 算法,则调用 Cubic 公式更新窗口大小
    congestion_window_ = congestion_window_ * RenoBeta();
  } else {
    congestion_window_ =
        cubic_.CongestionWindowAfterPacketLoss(congestion_window_);
  }

  if (congestion_window_ < min_congestion_window_) {
    congestion_window_ = min_congestion_window_;
  }

  //慢启动阈值设为当前拥塞窗口,退出慢启动模式
  slowstart_threshold_ = congestion_window_;
  //重置上次减小拥塞窗口时发送的最大包序号
  largest_sent_at_last_cutback_ = largest_sent_packet_number_;
  // Reset packet count from congestion avoidance mode. We start counting again
  // when we're out of recovery.
    //重置确认包计数,开始新的周期
  num_acked_packets_ = 0;
  DVLOG(1) << "Incoming loss; congestion window: " << congestion_window_
           << " slowstart threshold: " << slowstart_threshold_;
}

QuicByteCount TcpCubicSenderBytes::GetCongestionWindow() const {
  return congestion_window_;
}

QuicByteCount TcpCubicSenderBytes::GetSlowStartThreshold() const {
  return slowstart_threshold_;
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
void TcpCubicSenderBytes::MaybeIncreaseCwnd(
    QuicPacketNumber acked_packet_number,
    QuicByteCount acked_bytes,
    QuicByteCount bytes_in_flight) {
    //首先检查是否仍处于拥塞控制的恢复(recovery)状态,如果是则直接返回。
  QUIC_BUG_IF(InRecovery()) << "Never increase the CWND during recovery.";
  // Do not increase the congestion window unless the sender is close to using
  // the current window.

  //不是满负载状态,就是应用受限状态.
  //如果为应用受限状态,不增加窗口.
  if (!IsCwndLimited(bytes_in_flight)) {
    cubic_.OnApplicationLimited();
    return;
  }

  //检查是否拥塞窗口已满,如果是则直接返回。
  if (congestion_window_ >= max_congestion_window_) {
    return;
  }

  //满启动阶段,倍数增.
  if (InSlowStart()) {
    // TCP slow start, exponential growth, increase by one for each ACK.
    congestion_window_ += kDefaultTCPMSS;
    DVLOG(1) << "Slow start; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
    return;
  }

  //在拥塞避免阶段
  // Congestion avoidance.

  //reno
  if (reno_) {
    // Classic Reno congestion avoidance.
    ++num_acked_packets_;
    // Divide by num_connections to smoothly increase the CWND at a faster rate
    // than conventional Reno.
    //当计数器大于拥塞窗口大小除以 MSS 之后
    //则增加一个 MSS 的拥塞窗口大小
    if (num_acked_packets_ * num_connections_ >=
        congestion_window_ / kDefaultTCPMSS) {
      congestion_window_ += kDefaultTCPMSS;
      num_acked_packets_ = 0;
    }

    DVLOG(1) << "Reno; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_
             << " congestion window count: " << num_acked_packets_;
  //cubic
  } else {
    congestion_window_ =
        min(max_congestion_window_,
            cubic_.CongestionWindowAfterAck(acked_bytes, congestion_window_,
                                            rtt_stats_->min_rtt()));
    DVLOG(1) << "Cubic; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
  }
}



void TcpCubicSenderBytes::HandleRetransmissionTimeout() {
    //一朝回到解放前
  cubic_.Reset();
  slowstart_threshold_ = congestion_window_ / 2;
  congestion_window_ = min_congestion_window_;
}

void TcpCubicSenderBytes::OnConnectionMigration() {
  TcpCubicSenderBase::OnConnectionMigration();
  cubic_.Reset();
  num_acked_packets_ = 0;
  congestion_window_ = initial_tcp_congestion_window_;
  max_congestion_window_ = initial_max_tcp_congestion_window_;
  slowstart_threshold_ = initial_max_tcp_congestion_window_;
}

CongestionControlType TcpCubicSenderBytes::GetCongestionControlType() const {
  return reno_ ? kRenoBytes : kCubicBytes;
}

}  // namespace net
