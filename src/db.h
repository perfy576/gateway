#pragma once
#include <mysql/mysql.h>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using Rows = std::vector<std::vector<std::string>>;
std::string env(const char *name, const std::string& fallback = "");
class DbError : public std::runtime_error {
    unsigned code_;
public:
    explicit DbError(const std::string& message, unsigned code = 0)
        : std::runtime_error(message), code_(code) {}
    unsigned code() const { return code_; }
};
class Db {
    MYSQL *conn_ = nullptr;
    unsigned long long changed_ = 0, inserted_ = 0;
    bool in_transaction_ = false;
    std::uint64_t last_used_ms_ = 0;
    void connect();
    void reconnect(unsigned code, unsigned& attempts);
    void ensure_ready(unsigned& attempts);
public:
    Db();
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    Rows query(const std::string& sql, const std::vector<std::string>& args = {});
    void begin();
    void commit();
    void rollback();
    unsigned long long changed() const { return changed_; }
    unsigned long long inserted() const { return inserted_; }
};
Db& db();
void reset_db();
