ALTER TABLE driver_identity_submissions
    ALTER COLUMN cnic_front DROP NOT NULL,
    ALTER COLUMN cnic_back DROP NOT NULL,
    ADD CHECK ((cnic_front IS NULL) = (cnic_back IS NULL)),
    ADD CHECK (octet_length(cnic_front) <= 1048604 AND octet_length(cnic_back) <= 1048604) NOT VALID;

CREATE INDEX driver_identity_document_expiry ON driver_identity_submissions (submitted_at) WHERE cnic_front IS NOT NULL;
