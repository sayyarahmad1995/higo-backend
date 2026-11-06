ALTER TABLE driver_onboarding_applications ADD COLUMN document_schema smallint NOT NULL DEFAULT 1 CHECK (document_schema IN (1,2));
DO $migration$
DECLARE constraint_name text;
BEGIN
    SELECT conname INTO STRICT constraint_name FROM pg_constraint
    WHERE conrelid='driver_onboarding_applications'::regclass AND contype='c'
      AND pg_get_constraintdef(oid) LIKE '%submitted_at%cnic_front%registration_image%';
    EXECUTE format('ALTER TABLE driver_onboarding_applications DROP CONSTRAINT %I',constraint_name);
END;
$migration$;
ALTER TABLE driver_onboarding_applications ADD CHECK (
    document_schema=2 OR submitted_at IS NULL OR (cnic_front IS NOT NULL AND registration_image IS NOT NULL)
);
ALTER TABLE driver_onboarding_applications ALTER COLUMN document_schema SET DEFAULT 2;
CREATE TABLE driver_onboarding_documents (
    user_id bigint NOT NULL,
    application_version integer NOT NULL,
    kind text NOT NULL CHECK (kind IN ('selfie','cnic_front','cnic_back','license_front','license_back','registration',
        'exterior_front','exterior_rear','exterior_right','exterior_left','interior_front','interior_rear','additional')),
    image bytea NOT NULL CHECK (octet_length(image) BETWEEN 29 AND
        CASE WHEN kind IN ('cnic_front','cnic_back') THEN 1048604 ELSE 2097180 END),
    PRIMARY KEY (user_id, application_version,kind),
    FOREIGN KEY (user_id,application_version) REFERENCES driver_onboarding_applications(user_id,application_version) ON DELETE CASCADE
);
INSERT INTO driver_onboarding_documents(user_id,application_version,kind,image)
SELECT a.user_id,a.application_version,d.kind,d.image FROM driver_onboarding_applications a
CROSS JOIN LATERAL (VALUES ('cnic_front',a.cnic_front),('cnic_back',a.cnic_back),('registration',a.registration_image),('additional',a.insurance_image)) d(kind,image)
WHERE a.submitted_at IS NULL AND d.image IS NOT NULL AND octet_length(d.image)>=29;
UPDATE driver_onboarding_applications
SET document_schema=2, details=jsonb_set(details,'{step}','"0"'), draft_revision=draft_revision+1,
    cnic_front=NULL,cnic_back=NULL,registration_image=NULL,insurance_image=NULL
WHERE submitted_at IS NULL;
