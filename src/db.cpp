#include "db.h"
#include <cstdlib>

std::string env(const char *name, const std::string& fallback) {
    const char *value = std::getenv(name);
    return value ? value : fallback;
}
Db::Db() {
    conn_ = mysql_init(nullptr);
    if (!conn_) throw DbError("mysql_init failed");
    unsigned timeout = 5;
    mysql_options(conn_, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    mysql_options(conn_, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(conn_, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
    mysql_options(conn_, MYSQL_SET_CHARSET_NAME, "utf8mb4");
    auto ca = env("DB_TLS_CA");
    mysql_ssl_set(conn_, nullptr, nullptr, ca.empty() ? nullptr : ca.c_str(), nullptr, nullptr);
    my_bool verify = env("DB_TLS_REQUIRED", "true") != "false";
    mysql_options(conn_, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &verify);
    if (!mysql_real_connect(conn_, env("DB_HOST").c_str(), env("DB_USER").c_str(),
          env("DB_PASSWORD").c_str(), env("DB_NAME", "gateway").c_str(),
          std::stoul(env("DB_PORT", "3306")), nullptr, CLIENT_SSL)) {
        std::string error = mysql_error(conn_);
        mysql_close(conn_); conn_ = nullptr;
        throw DbError(error);
    }
    if (!mysql_get_ssl_cipher(conn_) && env("DB_TLS_REQUIRED", "true") != "false") {
        mysql_close(conn_); conn_ = nullptr;
        throw DbError("Database TLS is required");
    }
}
Db::~Db() { if (conn_) mysql_close(conn_); }
void Db::begin() {
    if (mysql_autocommit(conn_,0)) throw DbError(mysql_error(conn_));
}
void Db::commit() {
    if (mysql_commit(conn_) || mysql_autocommit(conn_,1)) throw DbError(mysql_error(conn_));
}
void Db::rollback() {
    if (mysql_rollback(conn_) || mysql_autocommit(conn_,1)) throw DbError(mysql_error(conn_));
}
Rows Db::query(const std::string& sql, const std::vector<std::string>& args) {
    std::unique_ptr<MYSQL_STMT, decltype(&mysql_stmt_close)> stmt(mysql_stmt_init(conn_), mysql_stmt_close);
    auto fail = [&]() { throw DbError(stmt ? mysql_stmt_error(stmt.get()) : "mysql_stmt_init failed"); };
    if (!stmt || mysql_stmt_prepare(stmt.get(), sql.c_str(), sql.size())) fail();
    if (mysql_stmt_param_count(stmt.get()) != args.size()) throw DbError("Parameter count mismatch");
    std::vector<MYSQL_BIND> binds(args.size());
    for (size_t i = 0; i < args.size(); ++i) {
        binds[i] = {}; binds[i].buffer_type = MYSQL_TYPE_STRING;
        binds[i].buffer = const_cast<char *>(args[i].data()); binds[i].buffer_length = args[i].size();
    }
    if (!args.empty() && mysql_stmt_bind_param(stmt.get(), binds.data())) fail();
    my_bool update = 1;
    mysql_stmt_attr_set(stmt.get(), STMT_ATTR_UPDATE_MAX_LENGTH, &update);
    if (mysql_stmt_execute(stmt.get()) || mysql_stmt_store_result(stmt.get())) fail();
    changed_ = mysql_stmt_affected_rows(stmt.get());
    inserted_ = mysql_stmt_insert_id(stmt.get());
    std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> meta(mysql_stmt_result_metadata(stmt.get()), mysql_free_result);
    Rows result;
    if (!meta) return result;
    unsigned n = mysql_num_fields(meta.get());
    MYSQL_FIELD *fields = mysql_fetch_fields(meta.get());
    std::vector<MYSQL_BIND> outputs(n);
    std::vector<std::vector<char>> buffers(n);
    std::vector<unsigned long> lengths(n);
    std::vector<my_bool> nulls(n), errors(n);
    for (unsigned i = 0; i < n; ++i) {
        buffers[i].resize(fields[i].max_length + 1);
        outputs[i] = {}; outputs[i].buffer_type = MYSQL_TYPE_STRING;
        outputs[i].buffer = buffers[i].data(); outputs[i].buffer_length = buffers[i].size();
        outputs[i].length = &lengths[i]; outputs[i].is_null = &nulls[i]; outputs[i].error = &errors[i];
    }
    if (mysql_stmt_bind_result(stmt.get(), outputs.data())) fail();
    int status;
    while ((status = mysql_stmt_fetch(stmt.get())) == 0) {
        std::vector<std::string> row;
        for (unsigned i = 0; i < n; ++i) row.emplace_back(nulls[i] ? "" : std::string(buffers[i].data(), lengths[i]));
        result.push_back(std::move(row));
    }
    if (status != MYSQL_NO_DATA) fail();
    return result;
}
namespace {
    struct Connection {
        std::unique_ptr<Db> value;
        Connection() { mysql_thread_init(); }
        ~Connection() { value.reset(); mysql_thread_end(); }
    };
    thread_local Connection connection;
}
Db& db() {
    if (!connection.value) connection.value = std::make_unique<Db>();
    return *connection.value;
}
void reset_db() { connection.value.reset(); }
