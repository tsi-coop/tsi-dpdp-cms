package org.tsicoop.dpdpcms.framework;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * PoolDB provides a thread-safe, singleton HikariCP connection pool.
 * Updated to prevent race conditions during initialization and optimize for
 * high-concurrency ExecutorService environments.
 */
public class PoolDB extends DB {

    // Volatile ensures visibility across threads during double-checked locking
    private static volatile HikariDataSource dataSource = null;

    /**
     * Initializes the HikariCP DataSource with thread-safety.
     */
    private static void initDataSource() {
        synchronized (PoolDB.class) {
            if (dataSource == null) {
                try {
                    // Register driver once
                    Class.forName("org.postgresql.Driver");

                    HikariConfig config = new HikariConfig();

                    // Database Connection Properties
                    String dbHost = SystemConfig.getAppConfig().getProperty("framework.db.host");
                    String dbName = SystemConfig.getAppConfig().getProperty("framework.db.name");
                    config.setJdbcUrl(dbHost + "/" + dbName);
                    config.setUsername(SystemConfig.getAppConfig().getProperty("framework.db.user"));
                    config.setPassword(SystemConfig.getAppConfig().getProperty("framework.db.password"));

                    // Pool Sizing & Timeouts
                    // For Jetty/ExecutorService: Ensure MaxPoolSize is slightly larger
                    // than the expected number of concurrent DB-heavy threads.
                    config.setMaximumPoolSize(15);
                    config.setMinimumIdle(5);
                    config.setConnectionTimeout(30000); // 30 seconds
                    config.setIdleTimeout(600000);     // 10 minutes
                    config.setMaxLifetime(1800000);    // 30 minutes

                    // Performance & Stability
                    config.addDataSourceProperty("cachePrepStmts", "true");
                    config.addDataSourceProperty("prepStmtCacheSize", "250");
                    config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
                    config.addDataSourceProperty("useServerPrepStmts", "true");

                    // Leak Detection: Helps identify unclosed connections in the ExecutorService
                    config.setLeakDetectionThreshold(2000); // 2 seconds

                    dataSource = new HikariDataSource(config);
                    System.out.println("HikariCP DataSource successfully initialized.");
                } catch (ClassNotFoundException e) {
                    throw new RuntimeException("PostgreSQL Driver not found", e);
                }
            }
        }
    }

    public PoolDB() throws SQLException {
        super();
        this.con = createConnection(true);
    }

    public PoolDB(boolean autocommit) throws SQLException {
        super();
        this.con = createConnection(autocommit);
    }

    public Connection getConnection() {
        return con;
    }

    public Connection createConnection(boolean autocommit) throws SQLException {
        if (dataSource == null) {
            initDataSource();
        }

        Connection connection = dataSource.getConnection();
        if (connection.getAutoCommit() != autocommit) {
            connection.setAutoCommit(autocommit);
        }
        return connection;
    }

    /**
     * Helper to check pool status (useful for debugging drops).
     */
    public static String getPoolStatus() {
        if (dataSource == null) return "Pool not initialized";
        return String.format("Active: %d, Idle: %d, Waiting: %d",
                dataSource.getHikariPoolMXBean().getActiveConnections(),
                dataSource.getHikariPoolMXBean().getIdleConnections(),
                dataSource.getHikariPoolMXBean().getThreadsAwaitingConnection());
    }
}