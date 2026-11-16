ALTER TABLE services ADD COLUMN appid VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL;
UPDATE services SET appid=CONCAT('app_',id) WHERE appid IS NULL;
ALTER TABLE services MODIFY COLUMN appid VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 ADD UNIQUE KEY services_appid (appid);
