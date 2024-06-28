/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024s EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <optional>

#include <aos/common/tools/error.hpp>

#include "iam/publicnodeclient.hpp"
#include "stubs/publicnodesservice.hpp"

#include <gmock/gmock.h>

using namespace testing;

using namespace aos::common::iam;

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

class TestIamPublicNodeClient : public PublicNodeClientItf {
public:
    MOCK_METHOD(
        aos::Error, GetCert, (const std::string& certType, aos::iam::certhandler::CertInfo& certInfo), (override));
    MOCK_METHOD(bool, OnConnected, (), (override));

    bool ProcessStartProvisioning([[maybe_unused]] const iamanager::v5::StartProvisioningRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_start_provisioning_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessFinishProvisioning([[maybe_unused]] const iamanager::v5::FinishProvisioningRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_finish_provisioning_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessDeprovision([[maybe_unused]] const iamanager::v5::DeprovisionRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_deprovision_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessPauseNode([[maybe_unused]] const iamanager::v5::PauseNodeRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_pause_node_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessResumeNode([[maybe_unused]] const iamanager::v5::ResumeNodeRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_resume_node_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessCreateKey([[maybe_unused]] const iamanager::v5::CreateKeyRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_create_key_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessApplyCert([[maybe_unused]] const iamanager::v5::ApplyCertRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_apply_cert_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    bool ProcessGetCertTypes([[maybe_unused]] const iamanager::v5::GetCertTypesRequest& request) override
    {
        iamanager::v5::IAMIncomingMessages incomingMsg;
        incomingMsg.mutable_get_cert_types_request();

        SetIncomingMessage(incomingMsg);

        return true;
    }

    iamanager::v5::IAMIncomingMessages GetIncomingMessage()
    {
        std::unique_lock lock {mIncomingMsgLock};

        mIncomingMsgCV.wait_for(lock, kTimeout, [this] { return mReceivedMsg; });

        mReceivedMsg = false;

        return mIncomingMsg;
    }

private:
    constexpr static std::chrono::seconds kTimeout = std::chrono::seconds(5);

    void SetIncomingMessage(const iamanager::v5::IAMIncomingMessages& message)
    {
        std::lock_guard lock {mIncomingMsgLock};

        mIncomingMsg = message;
        mReceivedMsg = true;
        mIncomingMsgCV.notify_all();
    }

    iamanager::v5::IAMIncomingMessages mIncomingMsg;
    std::mutex                         mIncomingMsgLock;
    std::condition_variable            mIncomingMsgCV;
    bool                               mReceivedMsg = false;
};

class PublicNodeClientTest : public Test {
protected:
    void SetUp() override
    {
        mService.emplace("localhost:8001");
        mClient.emplace();

        auto err = mClient->Init(CryptoCertContext(), true);
        ASSERT_EQ(err, aos::ErrorEnum::eNone);

        mClient->Run("localhost:8001", std::chrono::seconds(1));
    }

    void TearDown() override { mClient->Close(); }

    std::optional<TestPublicNodeService>   mService;
    std::optional<TestIamPublicNodeClient> mClient;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(PublicNodeClientTest, IncomingMessageTest)
{
    EXPECT_CALL(*mClient, OnConnected()).WillOnce(Return(true));
    EXPECT_TRUE(mService->WaitForConnection());

    iamanager::v5::IAMIncomingMessages incomingMsg;

    // send StartProvisioningRequest
    incomingMsg.mutable_start_provisioning_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    auto msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kStartProvisioningRequest);

    // send FinishProvisioningRequest
    incomingMsg.mutable_finish_provisioning_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kFinishProvisioningRequest);

    // send DeprovisionRequest
    incomingMsg.mutable_deprovision_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kDeprovisionRequest);

    // send PauseNodeRequest
    incomingMsg.mutable_pause_node_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kPauseNodeRequest);

    // send ResumeNodeRequest
    incomingMsg.mutable_resume_node_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kResumeNodeRequest);

    // send CreateKeyRequest
    incomingMsg.mutable_create_key_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kCreateKeyRequest);

    // send ApplyCertRequest
    incomingMsg.mutable_apply_cert_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kApplyCertRequest);

    // send GetCertTypesRequest
    incomingMsg.mutable_get_cert_types_request();
    EXPECT_TRUE(mService->SendIncomingMessage(incomingMsg));

    msg = mClient->GetIncomingMessage();
    EXPECT_EQ(msg.IAMIncomingMessage_case(), iamanager::v5::IAMIncomingMessages::kGetCertTypesRequest);
}
