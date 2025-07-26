package org.tsicoop.dpdpcms.framework;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.SQLException;


@SuppressWarnings("unchecked")
public class PoolDB extends DB{

    // HikariCP DataSource instance
    private static HikariDataSource basicDataSource = null;

    // Static block to initialize the HikariCP DataSource once when the class is loaded
    private void initBasicDataSource() {

        // Create a HikariConfig object to hold the pool's configuration
        HikariConfig config = new HikariConfig();

        // --- Database Connection Properties (for PostgreSQL) ---
        // Replace 'localhost:5432' with your PostgreSQL host and port if different.
        // Replace 'your_database_name', 'your_username', and 'your_password' with your actual credentials.
        config.setJdbcUrl(SystemConfig.getAppConfig().getProperty("framework.db.host")+"/"+ SystemConfig.getAppConfig().getProperty("framework.db.name"));
        config.setUsername(SystemConfig.getAppConfig().getProperty("framework.db.user"));
        config.setPassword(SystemConfig.getAppConfig().getProperty("framework.db.password"));

        // --- HikariCP Specific Pool Properties (Highly Recommended for Performance) ---
        // Maximum number of connections in the pool. Adjust based on your application's concurrency needs.
        config.setMaximumPoolSize(10);
        // Minimum number of idle connections to maintain in the pool.
        config.setMinimumIdle(5);
        // Maximum waiting time for a connection from the pool. (30 seconds)
        config.setConnectionTimeout(30000);
        // Maximum amount of time a connection can sit idle in the pool before being evicted. (10 minutes)
        config.setIdleTimeout(600000); // milliseconds
        // Maximum lifetime of a connection in the pool. (30 minutes)
        config.setMaxLifetime(1800000); // milliseconds

        // --- DataSource Properties (passed directly to the JDBC driver or database) ---
        // Recommended for PostgreSQL to improve performance by caching prepared statements
        config.addDataSourceProperty("cachePrepStmts", "true");
        // Size of the PreparedStatement cache
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        // Max length of SQL in the PreparedStatement cache
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        // Create the HikariDataSource using the configured properties
        basicDataSource = new HikariDataSource(config);
        System.out.println("HikariCP DataSource initialized for PostgreSQL.");
    }


    public PoolDB() throws SQLException{
        super();
        con = createConnection(true);
    }

    public PoolDB(boolean autocommit) throws SQLException{
        super();
        con = createConnection(autocommit);
    }

    public Connection getConnection(){
        return con;
    }

    public Connection createConnection(boolean autocommit) throws SQLException {
        Connection connection = null;
        /*try {
            Class.forName("org.postgresql.Driver");
            connection = DriverManager.getConnection(   SystemConfig.getAppConfig().getProperty("framework.db.host")+"/"+ SystemConfig.getAppConfig().getProperty("framework.db.name"),
                                                            SystemConfig.getAppConfig().getProperty("framework.db.user"),
                                                            SystemConfig.getAppConfig().getProperty("framework.db.password"));
            if(!autocommit)
                connection.setAutoCommit(false);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return connection;*/
        try {
            Class.forName("org.postgresql.Driver");
            if (basicDataSource == null) {
                initBasicDataSource();
            }
            connection = basicDataSource.getConnection();
            connection.setAutoCommit(autocommit);
        }catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
		return connection;
    }
}