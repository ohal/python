USE parserdb

DROP INDEX hashindex ON hashes;
DROP INDEX emailindex ON emails;
DROP INDEX urlindex ON urls;

DROP TABLE IF EXISTS hashes, emails, urls;

CREATE TABLE IF NOT EXISTS hashes
    (hash CHAR(32) PRIMARY KEY,
    sign CHAR(4));

CREATE UNIQUE INDEX hashindex ON hashes(hash);

CREATE TABLE IF NOT EXISTS emails
    (email VARCHAR(255) PRIMARY KEY,
    ffrom INT UNSIGNED,
    fto INT UNSIGNED,
    fcc INT UNSIGNED,
    fbcc INT UNSIGNED,
    fbody INT UNSIGNED);

CREATE UNIQUE INDEX emailindex ON emails(email);

CREATE TABLE IF NOT EXISTS urls
    (url VARCHAR(255) PRIMARY KEY,
    reach BIT,
    cemails INT UNSIGNED,
    curls INT UNSIGNED);

CREATE UNIQUE INDEX urlindex ON urls(url);
