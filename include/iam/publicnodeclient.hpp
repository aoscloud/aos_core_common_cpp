/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PUBLICNODECLIENT_HPP_
#define PUBLICNODECLIENT_HPP_

#include <atomic>
#include <condition_variable>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/channel.h>
#include <grpcpp/security/credentials.h>

#include <aos/common/crypto.hpp>
#include <aos/common/cryptoutils.hpp>
#include <aos/common/tools/error.hpp>
#include <aos/iam/certhandler.hpp>

#include <iamanager/v5/iamanager.grpc.pb.h>

#include "utils/time.hpp"

namespace aos::common::iam {
/**
 * @brief Context for the crypto certificates.
 */
struct CryptoCertContext {
    std::string                      mCertStorage;
    std::string                      mCACert;
    aos::cryptoutils::CertLoaderItf* certLoader;
    aos::crypto::x509::ProviderItf*  cryptoProvider;
};

/**
 * @brief Interface for the connection callback.
 */
class ConnectionCallbackItf {
public:
    virtual ~ConnectionCallbackItf() = default;

    virtual bool OnConnected() = 0;
};

/**
 * @brief Public node client interface.
 */
class PublicNodeClientItf : public ConnectionCallbackItf {
public:
    /**
     * @brief Initialize the client.
     *
     * @param certContext certificate context.
     * @param provisioningMode provisioning mode.
     * @return Error error code.
     */
    Error Init(const CryptoCertContext& certContext, bool provisioningMode);

    /**
     * @brief Run the client.
     *
     * @param url URL of the public node.
     * @param reconnectInterval interval for reconnection.
     */
    void Run(const std::string& url, aos::common::utils::Duration reconnectInterval);

    /**
     * @brief Close the client.
     */
    void Close();

private:
    using StreamPtr = std::unique_ptr<
        grpc::ClientReaderWriterInterface<iamanager::v5::IAMOutgoingMessages, iamanager::v5::IAMIncomingMessages>>;

protected:
    StreamPtr mStream;

private:
    using PublicNodeService        = iamanager::v5::IAMPublicNodesService;
    using PublicNodeServiceStubPtr = std::unique_ptr<PublicNodeService::StubInterface>;
    using HandlerFunc              = std::function<bool(const iamanager::v5::IAMIncomingMessages&)>;

    virtual Error GetCert(const std::string& certType, aos::iam::certhandler::CertInfo& certInfo)    = 0;
    virtual bool  ProcessStartProvisioning(const iamanager::v5::StartProvisioningRequest& request)   = 0;
    virtual bool  ProcessFinishProvisioning(const iamanager::v5::FinishProvisioningRequest& request) = 0;
    virtual bool  ProcessDeprovision(const iamanager::v5::DeprovisionRequest& request)               = 0;
    virtual bool  ProcessPauseNode(const iamanager::v5::PauseNodeRequest& request)                   = 0;
    virtual bool  ProcessResumeNode(const iamanager::v5::ResumeNodeRequest& request)                 = 0;
    virtual bool  ProcessCreateKey(const iamanager::v5::CreateKeyRequest& request)                   = 0;
    virtual bool  ProcessApplyCert(const iamanager::v5::ApplyCertRequest& request)                   = 0;
    virtual bool  ProcessGetCertTypes(const iamanager::v5::GetCertTypesRequest& request)             = 0;

    void ConnectionLoop(const std::string& url, utils::Duration reconnectInterval) noexcept;
    void HandleIncomingMessages();
    bool RegisterNode(const std::string& url);
    void InitializeHandlers();

    std::vector<std::shared_ptr<grpc::ChannelCredentials>>                                      mCredentialList;
    std::unordered_map<iamanager::v5::IAMIncomingMessages::IAMIncomingMessageCase, HandlerFunc> mHandlers;

    std::unique_ptr<grpc::ClientContext> mRegisterNodeCtx;
    PublicNodeServiceStubPtr             mPublicNodeServiceStub;

    std::thread             mConnectionThread;
    std::condition_variable mShutdownCV;
    std::atomic<bool>       mShutdown {};
    std::mutex              mShutdownLock;
};

} // namespace aos::common::iam

#endif // PUBLICNODECLIENT_HPP_
