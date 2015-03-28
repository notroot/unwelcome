drop table if exists hosts;
drop table if exists unwelcome;

CREATE TABLE "hosts" (
	ip VARCHAR(16) NOT NULL, 
	first_seen DATETIME, 
	last_seen DATETIME, 
	times_seen INTEGER default 0, 
	times_banned INTEGER default 0, 
	PRIMARY KEY (ip)
);
CREATE TABLE unwelcome (
	ip VARCHAR(16) NOT NULL, 
	banned_on DATETIME, 
	banned_for INTEGER,
	PRIMARY KEY (ip)
);
CREATE TABLE configs (
	config TEXT,
	setting TEXT,
	PRIMARY KEY (config)
);

INSERT INTO configs VALUES ('last_run', datetime('now','-7 days'));
