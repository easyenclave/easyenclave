ALTER TABLE deployments
ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'api_key';
