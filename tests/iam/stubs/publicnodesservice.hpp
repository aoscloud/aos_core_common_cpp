/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024s EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <grpcpp/server_builder.h>

#include <iamanager/v5/iamanager.grpc.pb.h>

/**
 * @brief Test public node service stub.
 */
class TestPublicNodeService : public iamanager::v5::IAMPublicNodesService::Service {
public:
    /**
     * @brief Constructor.
     *
     * @param url server url.
     */
    TestPublicNodeService(const std::string& url)
    {
        mStream                 = nullptr;
        const auto& credentials = grpc::InsecureServerCredentials();

        mServer = CreatePublicServer(url, credentials);
    }

    /**
     * @brief Register node.
     *
     * @param context server context.
     * @param stream server stream.
     * @return grpc::Status status.
     */
    grpc::Status RegisterNode(grpc::ServerContext*                                                        context,
        grpc::ServerReaderWriter<iamanager::v5::IAMIncomingMessages, iamanager::v5::IAMOutgoingMessages>* stream)
    {
        try {
            mRegisterNodeContext = context;
            mStream              = stream;

            iamanager::v5::IAMOutgoingMessages incomingMsg;

            mConnected = true;
            mConnectionCV.notify_all();

            while (stream->Read(&incomingMsg)) { };
        } catch (const std::exception& e) {
        }

        return grpc::Status::OK;
    }

    /**
     * @brief Send incoming message.
     *
     * @param message incoming message.
     * @return bool true if success.
     */
    bool SendIncomingMessage(const iamanager::v5::IAMIncomingMessages& message) { return mStream->Write(message); }

    /**
     * @brief Wait for connection.
     *
     * @return bool true if success.
     */
    bool WaitForConnection()
    {
        std::unique_lock lock {mConnectionLock};

        mConnectionCV.wait_for(lock, kTimeout, [this] { return mConnected; });

        return mConnected;
    }

private:
    constexpr static std::chrono::seconds kTimeout = std::chrono::seconds(5);

    std::unique_ptr<grpc::Server> CreatePublicServer(
        const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials)
    {
        grpc::ServerBuilder builder;

        builder.AddListeningPort(addr, credentials);
        builder.RegisterService(static_cast<iamanager::v5::IAMPublicNodesService::Service*>(this));

        return builder.BuildAndStart();
    }

    grpc::ServerContext*          mRegisterNodeContext;
    std::unique_ptr<grpc::Server> mServer;
    grpc::ServerReaderWriter<iamanager::v5::IAMIncomingMessages, iamanager::v5::IAMOutgoingMessages>* mStream;
    std::mutex                                                                                        mConnectionLock;
    std::condition_variable                                                                           mConnectionCV;
    bool mConnected = false;
};
