#pragma once

#include <grpcpp/grpcpp.h>
#include "user.grpc.pb.h"

class UserServiceImpl final : public dragonbreath::grpc::UserService::Service {
public:
    grpc::Status GetUser(::grpc::ServerContext* context,
                         const dragonbreath::grpc::GetUserRequest* request,
                         dragonbreath::grpc::GetUserResponse* response) override;
};
