
#include "UserServiceImpl.h"

#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"

#include <json/value.h>
#include <json/writer.h>

#include <stdexcept>
#include <string>

using dragonbreath::grpc::GetUserRequest;
using dragonbreath::grpc::GetUserResponse;
using dragonbreath::grpc::UserProfile;

namespace {
std::string recordId(const Json::Value& user) {
    if (!user.isMember("id")) {
        return "";
    }
    return user["id"].asString();
}

std::string stringField(const Json::Value& value, const std::string& key) {
    if (!value.isMember(key)) {
        return "";
    }
    const auto& field = value[key];
    if (field.isString()) {
        return field.asString();
    }
    if (field.isNumeric()) {
        return field.asString();
    }
    if (!field.isNull()) {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        return Json::writeString(builder, field);
    }
    return "";
}
}

grpc::Status UserServiceImpl::GetUser(::grpc::ServerContext* context,
                                      const GetUserRequest* request,
                                      GetUserResponse* response) {
    const std::string peer = context ? context->peer() : "";
    const std::string methodTag = "UserService.GetUser";
    logging::info("UserServiceImpl.cc", "UserServiceImpl", "GetUser", "grpc", __LINE__,
                  "incoming GetUser request from " + peer, methodTag);

    if (!request || request->id().empty()) {
        logging::warn("UserServiceImpl.cc", "UserServiceImpl", "GetUser", "grpc", __LINE__,
                      "missing id in GetUser request from " + peer, methodTag, "id is required");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "id is required");
    }

    try {
        SurrealClient db;
        auto user = db.selectById("user", request->id());
        if (user.isNull() || !user.isMember("id")) {
            logging::warn("UserServiceImpl.cc", "UserServiceImpl", "GetUser", "grpc", __LINE__,
                          "user not found for peer " + peer, methodTag, "user not found");
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "user not found");
        }

        UserProfile* profile = response->mutable_user();
        profile->set_id(recordId(user));
        profile->set_email(stringField(user, "email"));
        profile->set_role(stringField(user, "role"));
        profile->set_created_at(stringField(user, "created_at"));
        profile->set_updated_at(stringField(user, "updated_at"));

        logging::info("UserServiceImpl.cc", "UserServiceImpl", "GetUser", "grpc", __LINE__,
                      "user loaded successfully for peer " + peer, methodTag);
        return grpc::Status::OK;
    } catch (const std::exception& ex) {
        logging::error("UserServiceImpl.cc", "UserServiceImpl", "GetUser", "grpc", __LINE__,
                       "exception while fetching user for peer " + peer, methodTag, ex.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
    }
}
