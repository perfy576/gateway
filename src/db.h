#pragma once
#include <mysql/mysql.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using Rows = std::vector<std::vector<std::string>>;
std::string env(const char *name, const std::string& fallback = "");
class DbError : public std::runtime_error { using std::runtime_error::runtime_error; };
class Db {
    MYSQL *conn_ = nullptr;
    unsigned long long changed_ = 0, inserted_ = 0;
public:
    Db();
    ~Db();
    Rows query(const std::string& sql, const std::vector<std::string>& args = {});
    void begin();
    void commit();
    void rollback();
    unsigned long long changed() const { return changed_; }
    unsigned long long inserted() const { return inserted_; }
};
Db& db();
void reset_db();
