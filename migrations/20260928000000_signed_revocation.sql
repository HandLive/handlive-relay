-- Signed revocation, spec 00-common-specs 0.6.2 (HLREVOKE1) and 0.9.4.
-- revoked_at now holds the signed time of the statement and revoked_by its
-- signer; revoke_sig is the signature. Rows revoked before this change keep
-- revoke_sig NULL: they carry no statement and are never forwarded.
ALTER TABLE pairs
  ADD COLUMN revoke_sig BYTEA CHECK (octet_length(revoke_sig) = 64);
