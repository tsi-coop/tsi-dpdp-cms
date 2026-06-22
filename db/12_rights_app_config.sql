-- Per-fiduciary configuration for the Data Principal Rights Dashboard
-- (web/rights/index.html + dashboard.html): which OTP delivery mode principal
-- login uses, the message template for real OTP delivery, and whether the
-- PCA QR code feature is enabled. The actual OTP delivery webhook URL/secret
-- reuses webhook_configs with category='OTP' (see Notification.java).
CREATE TABLE IF NOT EXISTS rights_app_config (
    fiduciary_id UUID PRIMARY KEY REFERENCES fiduciaries(id),
    otp_mode VARCHAR(20) NOT NULL DEFAULT 'DUMMY_OTP', -- DUMMY_OTP, EMAIL_OTP, MOBILE_OTP
    otp_message_template TEXT,                          -- e.g. "Your verification code is {{otp}}"
    pca_qr_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID
);
