#include "db.h"
#include "time_utils.h"
#include <iostream>
#include <unistd.h>

static unsigned connection_attempts = 0;
static bool refuse_connections = false;

extern "C" MYSQL *__real_mysql_real_connect(MYSQL *, const char *, const char *, const char *,
                                            const char *, unsigned, const char *, unsigned long);
extern "C" MYSQL *__wrap_mysql_real_connect(MYSQL *mysql, const char *host, const char *user,
    const char *password, const char *database, unsigned port, const char *socket, unsigned long flags) {
    ++connection_attempts;
    return __real_mysql_real_connect(mysql, refuse_connections ? "127.0.0.1" : host, user, password,
        database, refuse_connections ? 1 : port, socket, flags);
}

static void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}

static void expire_connection(Db& connection) {
    connection.query("SET SESSION wait_timeout=1");
    sleep(3);
}

int main() {
    mysql_library_init(0, nullptr, nullptr);
    mysql_thread_init();
    int status = 0;
    try {
        Db connection;
        auto original = connection.query("SELECT CONNECTION_ID()")[0][0];
        expire_connection(connection);
        auto replacement = connection.query("SELECT CONNECTION_ID()")[0][0];
        require(original != replacement, "Idle query did not reconnect");
        require(connection.query("SELECT ?", {"bound-value"})[0][0] == "bound-value",
                "Bound query failed after reconnect");
        std::cout << "Idle query reconnect passed\n";

        expire_connection(connection);
        connection.begin();
        require(connection.query("SELECT @@autocommit")[0][0] == "0",
                "Transaction did not begin after idle reconnect");
        connection.rollback();
        require(connection.query("SELECT @@autocommit")[0][0] == "1",
                "Rollback did not restore autocommit");
        std::cout << "Idle transaction start reconnect passed\n";

        bool invalid_sql = false;
        const auto before_invalid_sql = connection_attempts;
        try { connection.query("INVALID SQL FOR CONNECTION RECOVERY TEST"); }
        catch (const DbError& error) { invalid_sql = error.code() == 1064; }
        require(invalid_sql && connection_attempts == before_invalid_sql,
                "SQL errors must retain their code and must not reconnect");
        std::cout << "Non-connection errors do not reconnect\n";

        Db killer;
        auto live_id = std::to_string(std::stoull(connection.query("SELECT CONNECTION_ID()")[0][0]));
        const auto before_kill = connection_attempts;
        killer.query("KILL CONNECTION " + live_id);
        require(connection.query("SELECT 1")[0][0] == "1" && connection_attempts == before_kill + 1,
                "A dropped connection must recover when preparing the next statement");
        connection.begin();
        connection.commit();
        require(connection.query("SELECT @@autocommit")[0][0] == "1", "Commit did not restore autocommit");
        std::cout << "Dropped connection recovers before SQL execution\n";

        const auto marker = "db-recovery-test-" + std::to_string(getpid()) + "-" +
            std::to_string(monotonic_milliseconds());
        connection.begin();
        connection.query("INSERT INTO audit_logs(actor,action,detail,ip) VALUES(?,?,?,?)",
                         {"database-test", "test.uncommitted", marker, "127.0.0.1"});
        expire_connection(connection);
        bool failed = false;
        const auto before_transaction_loss = connection_attempts;
        try { connection.query("SELECT 1"); }
        catch (const DbError& error) { failed = error.code() != 0; }
        require(failed && connection_attempts == before_transaction_loss,
                "Lost transaction silently reconnected");
        Db observer;
        require(observer.query("SELECT COUNT(*) FROM audit_logs WHERE detail=?", {marker})[0][0] == "0",
                "Uncommitted transaction was persisted");
        std::cout << "Lost transaction fails without replay or partial commit\n";

        expire_connection(observer);
        const auto before_reconnect = connection_attempts;
        refuse_connections = true;
        bool unavailable = false;
        try { observer.query("SELECT 1"); }
        catch (const DbError& error) { unavailable = error.code() == 2002 || error.code() == 2003; }
        refuse_connections = false;
        require(unavailable && connection_attempts - before_reconnect == 3,
                "Reconnect attempts must stop after exactly three failures");
        require(observer.query("SELECT 1")[0][0] == "1", "Recovery after outage failed");
        std::cout << "Reconnect limit of three and recovery after outage passed\n";
    } catch (const std::exception& error) {
        std::cerr << "Database recovery test failed: " << error.what() << '\n';
        status = 1;
    }
    mysql_thread_end();
    mysql_library_end();
    return status;
}
