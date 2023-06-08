// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_crypto_server_stream.h"

#include <memory>

#include "base/base64.h"
#include "crypto/secure_hash.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/crypto_utils.h"
#include "net/quic/core/crypto/quic_crypto_server_config.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/quic_server_session_base.h"

using base::StringPiece;
using std::string;

namespace net {

QuicCryptoServerStreamBase::QuicCryptoServerStreamBase(QuicSession* session)
    : QuicCryptoStream(session) {}

// TODO(jokulik): Once stateless rejects support is inherent in the version
// number, this function will likely go away entirely.
// static
bool QuicCryptoServerStreamBase::DoesPeerSupportStatelessRejects(
    const CryptoHandshakeMessage& message) {
  const QuicTag* received_tags;
  size_t received_tags_length;
  QuicErrorCode error =
      message.GetTaglist(kCOPT, &received_tags, &received_tags_length);
  if (error != QUIC_NO_ERROR) {
    return false;
  }
  for (size_t i = 0; i < received_tags_length; ++i) {
    if (received_tags[i] == kSREJ) {
      return true;
    }
  }
  return false;
}

QuicCryptoServerStream::QuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    bool use_stateless_rejects_if_peer_supported,
    QuicSession* session,
    Helper* helper)
    : QuicCryptoServerStreamBase(session),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      validate_client_hello_cb_(nullptr),
      helper_(helper),
      num_handshake_messages_(0),
      num_handshake_messages_with_server_nonces_(0),
      send_server_config_update_cb_(nullptr),
      num_server_config_update_messages_sent_(0),
      use_stateless_rejects_if_peer_supported_(
          use_stateless_rejects_if_peer_supported),
      peer_supports_stateless_rejects_(false),
      chlo_packet_size_(0) {
  DCHECK_EQ(Perspective::IS_SERVER, session->connection()->perspective());
}

QuicCryptoServerStream::~QuicCryptoServerStream() {
  CancelOutstandingCallbacks();
}

void QuicCryptoServerStream::CancelOutstandingCallbacks() {
  // Detach from the validation callback.  Calling this multiple times is safe.
  if (validate_client_hello_cb_ != nullptr) {
    validate_client_hello_cb_->Cancel();
    validate_client_hello_cb_ = nullptr;
  }
  if (send_server_config_update_cb_ != nullptr) {
    send_server_config_update_cb_->Cancel();
    send_server_config_update_cb_ = nullptr;
  }
}

void QuicCryptoServerStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QuicCryptoServerStreamBase::OnHandshakeMessage(message);
  ++num_handshake_messages_;
  chlo_packet_size_ = session()->connection()->GetCurrentPacket().length();

  // Do not process handshake messages after the handshake is confirmed.
  if (handshake_confirmed_) {
    CloseConnectionWithDetails(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE,
                               "Unexpected handshake message from client");
    return;
  }

  if (message.tag() != kCHLO) {
    CloseConnectionWithDetails(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                               "Handshake packet not CHLO");
    return;
  }

  if (validate_client_hello_cb_ != nullptr) {
    // Already processing some other handshake message.  The protocol
    // does not allow for clients to send multiple handshake messages
    // before the server has a chance to respond.
    CloseConnectionWithDetails(
        QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO,
        "Unexpected handshake message while processing CHLO");
    return;
  }

  //对传入的message握手消息(HandshakeMessage类型)计算HASH,并将结果存入chlo_hash_输出参数中
  CryptoUtils::HashHandshakeMessage(message, &chlo_hash_);

  std::unique_ptr<ValidateCallback> cb(new ValidateCallback(this));
  validate_client_hello_cb_ = cb.get();
  //验证
  crypto_config_->ValidateClientHello(
      message, session()->connection()->peer_address().address(),
      session()->connection()->self_address().address(), version(),
      session()->connection()->clock(), &crypto_proof_, std::move(cb));
}

void QuicCryptoServerStream::FinishProcessingHandshakeMessage(
    const ValidateClientHelloResultCallback::Result& result,
    std::unique_ptr<ProofSource::Details> details) {
  const CryptoHandshakeMessage& message = result.client_hello;

  // Clear the callback that got us here.
  DCHECK(validate_client_hello_cb_ != nullptr);
  validate_client_hello_cb_ = nullptr;

  if (use_stateless_rejects_if_peer_supported_) {
    peer_supports_stateless_rejects_ = DoesPeerSupportStatelessRejects(message);
  }

  CryptoHandshakeMessage reply;
  DiversificationNonce diversification_nonce;
  string error_details;
  //调用ProcessClientHello()处理CHLO消息。如果失败,关闭连接并返回。
  QuicErrorCode error =
      ProcessClientHello(result, std::move(details), &reply,
                         &diversification_nonce, &error_details);

  if (error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(error, error_details);
    return;
  }

  //如果reply消息的标签不是kSHLO,则发送reply消息。如果是SREJ,还需要保留crypto包以进行重传。然后关闭连接并返回。
  if (reply.tag() != kSHLO) {
    if (reply.tag() == kSREJ) {
      DCHECK(use_stateless_rejects_if_peer_supported_);
      DCHECK(peer_supports_stateless_rejects_);
      // Before sending the SREJ, cause the connection to save crypto packets
      // so that they can be added to the time wait list manager and
      // retransmitted.
      session()->connection()->EnableSavingCryptoPackets();
    }
    //发送reject数据包
    SendHandshakeMessage(reply);

    if (reply.tag() == kSREJ) {
      DCHECK(use_stateless_rejects_if_peer_supported_);
      DCHECK(peer_supports_stateless_rejects_);
      DCHECK(!handshake_confirmed());
      DVLOG(1) << "Closing connection "
               << session()->connection()->connection_id()
               << " because of a stateless reject.";
      session()->connection()->CloseConnection(
          QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT, "stateless reject",
          ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return;
  }

  // If we are returning a SHLO then we accepted the handshake.  Now
  // process the negotiated configuration options as part of the
  // session config.
  //如果reply消息是SHLO,继续处理。调用服务器QuicConfig的ProcessPeerHello()处理CHLO中的参数。如果失败,关闭连接并返回。
  QuicConfig* config = session()->config();
  OverrideQuicConfigDefaults(config);
  //server 参数协商
  error = config->ProcessPeerHello(message, CLIENT, &error_details);
  if (error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(error, error_details);
    return;
  }

  //调用session()->OnConfigNegotiated()进行参数协商后的处理。
  session()->OnConfigNegotiated();

  //将QuicConfig的参数添加到reply(SHLO)消息中。
  config->ToHandshakeMessage(&reply);

  // Receiving a full CHLO implies the client is prepared to decrypt with
  // the new server write key.  We can start to encrypt with the new server
  // write key.
  //
  // NOTE: the SHLO will be encrypted with the new server write key.
  //设置ENCRYPTION_INITIAL级别的加密器和解密器。开始使用新服务端写密钥加密数据。
  session()->connection()->SetEncrypter(
      ENCRYPTION_INITIAL,
      crypto_negotiated_params_.initial_crypters.encrypter.release());
  session()->connection()->SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Set the decrypter immediately so that we no longer accept unencrypted
  // packets.
  session()->connection()->SetDecrypter(
      ENCRYPTION_INITIAL,
      crypto_negotiated_params_.initial_crypters.decrypter.release());
  if (version() > QUIC_VERSION_32) {
    session()->connection()->SetDiversificationNonce(diversification_nonce);
  }


  //发送reply(SHLO)消息
  SendHandshakeMessage(reply);

  session()->connection()->SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      crypto_negotiated_params_.forward_secure_crypters.encrypter.release());
  session()->connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  session()->connection()->SetAlternativeDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      crypto_negotiated_params_.forward_secure_crypters.decrypter.release(),
      false /* don't latch */);

  //标记加密已建立和握手确认完成。
  encryption_established_ = true;
  handshake_confirmed_ = true;
  //调用session()->OnCryptoHandshakeEvent(HANDSHAKE_CONFIRMED)进行确认后的处理。
  session()->OnCryptoHandshakeEvent(QuicSession::HANDSHAKE_CONFIRMED);
}

void QuicCryptoServerStream::SendServerConfigUpdate(
    const CachedNetworkParameters* cached_network_params) {
  if (!handshake_confirmed_) {
    return;
  }

  if (FLAGS_enable_async_get_proof) {
    if (send_server_config_update_cb_ != nullptr) {
      DVLOG(1)
          << "Skipped server config update since one is already in progress";
      return;
    }

    std::unique_ptr<SendServerConfigUpdateCallback> cb(
        new SendServerConfigUpdateCallback(this));
    send_server_config_update_cb_ = cb.get();
    crypto_config_->BuildServerConfigUpdateMessage(
        session()->connection()->version(), chlo_hash_,
        previous_source_address_tokens_,
        session()->connection()->self_address().address(),
        session()->connection()->peer_address().address(),
        session()->connection()->clock(),
        session()->connection()->random_generator(), compressed_certs_cache_,
        crypto_negotiated_params_, cached_network_params, std::move(cb));
    return;
  }

  CryptoHandshakeMessage server_config_update_message;
  if (!crypto_config_->BuildServerConfigUpdateMessage(
          session()->connection()->version(), chlo_hash_,
          previous_source_address_tokens_,
          session()->connection()->self_address().address(),
          session()->connection()->peer_address().address(),
          session()->connection()->clock(),
          session()->connection()->random_generator(), compressed_certs_cache_,
          crypto_negotiated_params_, cached_network_params,
          &server_config_update_message)) {
    DVLOG(1) << "Server: Failed to build server config update (SCUP)!";
    return;
  }

  DVLOG(1) << "Server: Sending server config update: "
           << server_config_update_message.DebugString();
  const QuicData& data = server_config_update_message.GetSerialized();
  WriteOrBufferData(StringPiece(data.data(), data.length()), false, nullptr);

  ++num_server_config_update_messages_sent_;
}

QuicCryptoServerStream::SendServerConfigUpdateCallback::
    SendServerConfigUpdateCallback(QuicCryptoServerStream* parent)
    : parent_(parent) {}

void QuicCryptoServerStream::SendServerConfigUpdateCallback::Cancel() {
  parent_ = nullptr;
}

// From BuildServerConfigUpdateMessageResultCallback
void QuicCryptoServerStream::SendServerConfigUpdateCallback::Run(
    bool ok,
    const CryptoHandshakeMessage& message) {
  if (parent_ == nullptr) {
    return;
  }
  parent_->FinishSendServerConfigUpdate(ok, message);
}

void QuicCryptoServerStream::FinishSendServerConfigUpdate(
    bool ok,
    const CryptoHandshakeMessage& message) {
  // Clear the callback that got us here.
  DCHECK(send_server_config_update_cb_ != nullptr);
  send_server_config_update_cb_ = nullptr;

  if (!ok) {
    DVLOG(1) << "Server: Failed to build server config update (SCUP)!";
    return;
  }

  DVLOG(1) << "Server: Sending server config update: " << message.DebugString();
  const QuicData& data = message.GetSerialized();
  WriteOrBufferData(StringPiece(data.data(), data.length()), false, nullptr);

  ++num_server_config_update_messages_sent_;
}

void QuicCryptoServerStream::OnServerHelloAcked() {
  session()->connection()->OnHandshakeComplete();
}

uint8_t QuicCryptoServerStream::NumHandshakeMessages() const {
  return num_handshake_messages_;
}

uint8_t QuicCryptoServerStream::NumHandshakeMessagesWithServerNonces() const {
  return num_handshake_messages_with_server_nonces_;
}

int QuicCryptoServerStream::NumServerConfigUpdateMessagesSent() const {
  return num_server_config_update_messages_sent_;
}

const CachedNetworkParameters*
QuicCryptoServerStream::PreviousCachedNetworkParams() const {
  return previous_cached_network_params_.get();
}

bool QuicCryptoServerStream::UseStatelessRejectsIfPeerSupported() const {
  return use_stateless_rejects_if_peer_supported_;
}

bool QuicCryptoServerStream::PeerSupportsStatelessRejects() const {
  return peer_supports_stateless_rejects_;
}

void QuicCryptoServerStream::SetPeerSupportsStatelessRejects(
    bool peer_supports_stateless_rejects) {
  peer_supports_stateless_rejects_ = peer_supports_stateless_rejects;
}

void QuicCryptoServerStream::SetPreviousCachedNetworkParams(
    CachedNetworkParameters cached_network_params) {
  previous_cached_network_params_.reset(
      new CachedNetworkParameters(cached_network_params));
}

bool QuicCryptoServerStream::GetBase64SHA256ClientChannelID(
    string* output) const {
  if (!encryption_established_ ||
      crypto_negotiated_params_.channel_id.empty()) {
    return false;
  }

  const string& channel_id(crypto_negotiated_params_.channel_id);
  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  hash->Update(channel_id.data(), channel_id.size());
  uint8_t digest[32];
  hash->Finish(digest, sizeof(digest));

  base::Base64Encode(
      string(reinterpret_cast<const char*>(digest), sizeof(digest)), output);
  // Remove padding.
  size_t len = output->size();
  if (len >= 2) {
    if ((*output)[len - 1] == '=') {
      len--;
      if ((*output)[len - 1] == '=') {
        len--;
      }
      output->resize(len);
    }
  }
  return true;
}

//这个函数ProcessClientHello()处理CHLO消息并生成SHLO/SREJ回复
QuicErrorCode QuicCryptoServerStream::ProcessClientHello(
    const ValidateClientHelloResultCallback::Result& result,
    std::unique_ptr<ProofSource::Details> proof_source_details,
    CryptoHandshakeMessage* reply,
    DiversificationNonce* out_diversification_nonce,
    string* error_details) {
  const CryptoHandshakeMessage& message = result.client_hello;
  //调用helper_->CanAcceptClientHello()校验CHLO消息。如果失败,返回QUIC_HANDSHAKE_FAILED。
  if (!helper_->CanAcceptClientHello(
          message, session()->connection()->self_address(), error_details)) {
    return QUIC_HANDSHAKE_FAILED;
  }

  //如果CHLO消息包含服务器随机数,增加num_handshake_messages_with_server_nonces_计数。
  if (!result.info.server_nonce.empty()) {
    ++num_handshake_messages_with_server_nonces_;
  }
  //如果CHLO消息包含带宽估计,保存到previous_cached_network_params_。
  // Store the bandwidth estimate from the client.
  if (result.cached_network_params.bandwidth_estimate_bytes_per_second() > 0) {
    previous_cached_network_params_.reset(
        new CachedNetworkParameters(result.cached_network_params));
  }
  //保存source_address_tokens到previous_source_address_tokens_。
  previous_source_address_tokens_ = result.info.source_address_tokens;

  //生成服务器指定的连接ID,用于无状态拒绝。
  const bool use_stateless_rejects_in_crypto_config =
      use_stateless_rejects_if_peer_supported_ &&
      peer_supports_stateless_rejects_;
  QuicConnection* connection = session()->connection();
  const QuicConnectionId server_designated_connection_id =
      GenerateConnectionIdForReject(use_stateless_rejects_in_crypto_config);
  //从clienthello中解析出crypto_negotiated_params_ & crypto_proof_
  return crypto_config_->ProcessClientHello(
      result, /*reject_only=*/false, connection->connection_id(),
      connection->self_address().address(), connection->peer_address(),
      version(), connection->supported_versions(),
      use_stateless_rejects_in_crypto_config, server_designated_connection_id,
      connection->clock(), connection->random_generator(),
      compressed_certs_cache_, &crypto_negotiated_params_, &crypto_proof_,
      QuicCryptoStream::CryptoMessageFramingOverhead(version()),
      chlo_packet_size_, reply, out_diversification_nonce, error_details);
}

void QuicCryptoServerStream::OverrideQuicConfigDefaults(QuicConfig* config) {}

QuicCryptoServerStream::ValidateCallback::ValidateCallback(
    QuicCryptoServerStream* parent)
    : parent_(parent) {}

void QuicCryptoServerStream::ValidateCallback::Cancel() {
  parent_ = nullptr;
}

void QuicCryptoServerStream::ValidateCallback::Run(
    std::unique_ptr<Result> result,
    std::unique_ptr<ProofSource::Details> details) {
  if (parent_ != nullptr) {
    parent_->FinishProcessingHandshakeMessage(*result, std::move(details));
  }
}

QuicConnectionId QuicCryptoServerStream::GenerateConnectionIdForReject(
    bool use_stateless_rejects) {
  if (!use_stateless_rejects) {
    return 0;
  }
  return helper_->GenerateConnectionIdForReject(
      session()->connection()->connection_id());
}

}  // namespace net
