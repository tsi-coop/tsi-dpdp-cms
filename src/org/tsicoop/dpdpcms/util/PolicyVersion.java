package org.tsicoop.dpdpcms.util;

import org.tsicoop.dpdpcms.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Single place that decides what a consent policy "version" is and which one applies,
 * so record_consent, the wallet, and the policy lifecycle all resolve it the same way.
 */
public final class PolicyVersion {

    // consent_policies.version is VARCHAR(10): dotted numeric, e.g. 1, 1.0, 2.1.3
    private static final Pattern FORMAT = Pattern.compile("^\\d+(\\.\\d+){0,2}$");
    private static final int MAX_LENGTH = 10;

    private PolicyVersion() {}

    public static boolean isValid(String version) {
        return version != null && version.length() <= MAX_LENGTH && FORMAT.matcher(version).matches();
    }

    /**
     * The version of the policy that is currently ACTIVE for this fiduciary, or null if
     * the policy has no active version (or does not belong to the fiduciary).
     */
    public static String resolveActive(String policyId, UUID fiduciaryId) throws SQLException {
        String sql = "SELECT version FROM consent_policies " +
                "WHERE id = ? AND fiduciary_id = ? AND status = 'ACTIVE' AND effective_date <= NOW() " +
                "ORDER BY effective_date DESC, created_at DESC LIMIT 1";
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setObject(2, fiduciaryId);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString(1) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * For lifecycle calls (get/update/publish/delete) that omit 'version': the policy's only
     * non-archived version, or null when there are none or several (caller must then ask
     * for an explicit version).
     */
    public static String soleOpenVersion(String policyId) throws SQLException {
        String sql = "SELECT version FROM consent_policies WHERE id = ? AND status <> 'ARCHIVED' LIMIT 2";
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            rs = pstmt.executeQuery();
            if (!rs.next()) return null;
            String version = rs.getString(1);
            return rs.next() ? null : version;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }
}
