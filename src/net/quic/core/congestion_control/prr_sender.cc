// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/prr_sender.h"

#include "net/quic/core/quic_protocol.h"

namespace net {

namespace {
// Constant based on TCP defaults.
const QuicByteCount kMaxSegmentSize = kDefaultTCPMSS;
}  // namespace

PrrSender::PrrSender()
    : bytes_sent_since_loss_(0),
      bytes_delivered_since_loss_(0),
      ack_count_since_loss_(0),
      bytes_in_flight_before_loss_(0) {}

void PrrSender::OnPacketSent(QuicByteCount sent_bytes) {
  bytes_sent_since_loss_ += sent_bytes;
}

void PrrSender::OnPacketLost(QuicByteCount bytes_in_flight) {
  bytes_sent_since_loss_ = 0;
  bytes_in_flight_before_loss_ = bytes_in_flight;
  bytes_delivered_since_loss_ = 0;
  ack_count_since_loss_ = 0;
}

void PrrSender::OnPacketAcked(QuicByteCount acked_bytes) {
  bytes_delivered_since_loss_ += acked_bytes;
  ++ack_count_since_loss_;
}

//计算发送时间
QuicTime::Delta PrrSender::TimeUntilSend(
    QuicByteCount congestion_window,
    QuicByteCount bytes_in_flight,
    QuicByteCount slowstart_threshold) const {
  //   if (FLAGS_?? && bytes_in_flight < congestion_window) {
  //     return QuicTime::Delta::Zero();
  //   }
  // Return QuicTime::Zero In order to ensure limited transmit always works.
  //数据量很少,直接发送
  if (bytes_sent_since_loss_ == 0 || bytes_in_flight < kMaxSegmentSize) {
    return QuicTime::Delta::Zero();
  }
  //如果拥塞窗口大于正在传输中的字节数(bytes_in_flight),表示处于PRR-SSRB阶段:
  //PRR-SSRB模式下,PRR算法会限制每次ACK只发送1个MSS大小的数据,防止突发重传
  if (congestion_window > bytes_in_flight) {
    // During PRR-SSRB, limit outgoing packets to 1 extra MSS per ack, instead
    // of sending the entire available window. This prevents burst retransmits
    // when more packets are lost than the CWND reduction.
    //   limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
    //计算限制值:已接收字节 + ACK数量*MSS
    //如果限制值大于已发送字节,返回无限时延,暂不发送数据
    if (bytes_delivered_since_loss_ + ack_count_since_loss_ * kMaxSegmentSize <=
        bytes_sent_since_loss_) {
      return QuicTime::Delta::Infinite();
    }
    return QuicTime::Delta::Zero();
  }
  //否则,实现PRR算法
  // Implement Proportional Rate Reduction (RFC6937).
  // Checks a simplified version of the PRR formula that doesn't use division:
  // AvailableSendWindow =
  //   CEIL(prr_delivered * ssthresh / BytesInFlightAtLoss) - prr_sent
  //计算可发送窗口大小,如果可发送窗口大于已发送字节,返回0时延,立即发送数据
  //已接收字节*慢启动阈值 / 丢包前正在传输字节
  if (bytes_delivered_since_loss_ * slowstart_threshold >
      bytes_sent_since_loss_ * bytes_in_flight_before_loss_) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::Infinite();
}

}  // namespace net
