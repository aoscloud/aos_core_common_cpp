/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "iam/publicnodeclient.hpp"
#include "utils/grpchelper.hpp"

namespace aos::common::iam {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error PublicNodeClientItf::Init(const CryptoCertContext& certContext, bool provisioningMode)
{
    InitializeHandlers();

    if (provisioningMode) {
        mCredentialList.push_back(grpc::InsecureChannelCredentials());
        if (!certContext.mCACert.empty()) {
            mCredentialList.push_back(utils::GetTLSClientCredentials(certContext.mCACert.c_str()));
        }

        return ErrorEnum::eNone;
    }

    aos::iam::certhandler::CertInfo certInfo;

    auto err = GetCert(certContext.mCertStorage, certInfo);
    if (!err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    mCredentialList.push_back(aos::common::utils::GetMTLSClientCredentials(
        certInfo, certContext.mCACert.c_str(), *certContext.certLoader, *certContext.cryptoProvider));

    return ErrorEnum::eNone;
}

void PublicNodeClientItf::Close()
{
    mShutdown = true;
    {
        std::unique_lock lock {mShutdownLock};

        if (mRegisterNodeCtx) {
            mRegisterNodeCtx->TryCancel();
        }

        mShutdownCV.notify_all();
    }

    if (mConnectionThread.joinable()) {
        mConnectionThread.join();
    }
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

void PublicNodeClientItf::Run(const std::string& url, aos::common::utils::Duration reconnectInterval)
{
    mConnectionThread = std::thread(&PublicNodeClientItf::ConnectionLoop, this, url, reconnectInterval);
}

void PublicNodeClientItf::ConnectionLoop(
    const std::string& url, aos::common::utils::Duration reconnectInterval) noexcept
{
    while (true) {
        try {
            if (RegisterNode(url)) {
                HandleIncomingMessages();
            }
        } catch (const std::exception& e) {
        }

        std::unique_lock lock {mShutdownLock};

        mShutdownCV.wait_for(lock, reconnectInterval, [this]() { return mShutdown.load(); });
        if (mShutdown) {
            break;
        }
    }
}

void PublicNodeClientItf::InitializeHandlers()
{
    mHandlers = {
        {iamanager::v5::IAMIncomingMessages::kStartProvisioningRequest,
            [this](const iamanager::v5::IAMIncomingMessages& msg) {
                return ProcessStartProvisioning(msg.start_provisioning_request());
            }},
        {iamanager::v5::IAMIncomingMessages::kFinishProvisioningRequest,
            [this](const iamanager::v5::IAMIncomingMessages& msg) {
                return ProcessFinishProvisioning(msg.finish_provisioning_request());
            }},
        {iamanager::v5::IAMIncomingMessages::kDeprovisionRequest,
            [this](const iamanager::v5::IAMIncomingMessages& msg) {
                return ProcessDeprovision(msg.deprovision_request());
            }},
        {iamanager::v5::IAMIncomingMessages::kPauseNodeRequest,
            [this](
                const iamanager::v5::IAMIncomingMessages& msg) { return ProcessPauseNode(msg.pause_node_request()); }},
        {iamanager::v5::IAMIncomingMessages::kResumeNodeRequest,
            [this](const iamanager::v5::IAMIncomingMessages& msg) {
                return ProcessResumeNode(msg.resume_node_request());
            }},
        {iamanager::v5::IAMIncomingMessages::kCreateKeyRequest,
            [this](
                const iamanager::v5::IAMIncomingMessages& msg) { return ProcessCreateKey(msg.create_key_request()); }},
        {iamanager::v5::IAMIncomingMessages::kApplyCertRequest,
            [this](
                const iamanager::v5::IAMIncomingMessages& msg) { return ProcessApplyCert(msg.apply_cert_request()); }},
        {iamanager::v5::IAMIncomingMessages::kGetCertTypesRequest,
            [this](const iamanager::v5::IAMIncomingMessages& msg) {
                return ProcessGetCertTypes(msg.get_cert_types_request());
            }},
    };
}

bool PublicNodeClientItf::RegisterNode(const std::string& url)
{
    for (const auto& credentials : mCredentialList) {
        if (mShutdown) {
            return false;
        }

        auto channel = grpc::CreateCustomChannel(url, credentials, grpc::ChannelArguments());
        if (!channel) {
            continue;
        }

        {
            std::unique_lock lock {mShutdownLock};

            mPublicNodeServiceStub = PublicNodeService::NewStub(channel);
            if (!mPublicNodeServiceStub) {
                continue;
            }

            mRegisterNodeCtx = std::make_unique<grpc::ClientContext>();
            mStream          = mPublicNodeServiceStub->RegisterNode(mRegisterNodeCtx.get());
            if (!mStream) {
                continue;
            }
        }

        if (!OnConnected()) {
            continue;
        }

        return true;
    }

    return false;
}

void PublicNodeClientItf::HandleIncomingMessages()
{
    iamanager::v5::IAMIncomingMessages incomingMsg;

    while (mStream->Read(&incomingMsg)) {
        if (auto it = mHandlers.find(incomingMsg.IAMIncomingMessage_case()); it != mHandlers.end()) {
            if (auto ok = it->second(incomingMsg); !ok) {
                break;
            }
        }
    }
}

} // namespace aos::common::iam
