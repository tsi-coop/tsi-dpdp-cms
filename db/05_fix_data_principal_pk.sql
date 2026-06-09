-- Fix data_principal primary key to be composite (user_id, fiduciary_id)
-- so the same principal ID can exist across multiple fiduciaries.
ALTER TABLE data_principal DROP CONSTRAINT data_principal_pkey;
ALTER TABLE data_principal ADD PRIMARY KEY (user_id, fiduciary_id);
