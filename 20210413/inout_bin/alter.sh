#!/bin/sh
mysql sudb -e "alter table MGLOG add ipaddr varchar(100)"

mysql sudb -e "alter table SECMGLOG add ipaddr varchar(100)"

mysql sudb -e "alter table CallLOG add srcmac varchar(20)"
mysql sudb -e "alter table CallLOG add dstmac varchar(20)"

mysql sudb -e "alter table FileSyncLOG add srcip varchar(50)"
mysql sudb -e "alter table FileSyncLOG add dstip varchar(50)"
mysql sudb -e "alter table FileSyncLOG add taskname varchar(100)"
mysql sudb -e "alter table FileSyncLOG add d_path varchar(4096)"

mysql sudb -e "alter table LINKLOG add srcmac varchar(20)"
mysql sudb -e "alter table LINKLOG add dstmac varchar(20)"

mysql sudb -e "alter table FILTERLOG add service varchar(50)"
mysql sudb -e "alter table FILTERLOG add srcip varchar(50)"
mysql sudb -e "alter table FILTERLOG add dstip varchar(50)"
mysql sudb -e "alter table FILTERLOG add srcport varchar(50)"
mysql sudb -e "alter table FILTERLOG add dstport varchar(50)"

mysql sudb -e "alter table MGLOG modify opuser varchar(100)"
mysql sudb -e "alter table SECMGLOG modify opuser varchar(100)"
mysql sudb -e "alter table CallLOG modify opuser varchar(100)"
mysql sudb -e "alter table FILTERLOG modify opuser varchar(100)"

mysql sudb -e "alter table SYSTEM_STATUS modify net_flow BIGINT"

mysql sync_db -e "alter table dbsync_strategy_table add upsert tinyint(1) NOT NULL DEFAULT '0'"

mysql sync_db -e "ALTER TABLE dbsync_strategy MODIFY COLUMN sOwner VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy MODIFY COLUMN tOwner VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy MODIFY COLUMN sUserName VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy MODIFY COLUMN tUserName VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy MODIFY COLUMN sDataBase VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy MODIFY COLUMN tDataBase VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy_table MODIFY COLUMN sTableName VARCHAR(60) NOT NULL DEFAULT ''"
mysql sync_db -e "ALTER TABLE dbsync_strategy_table MODIFY COLUMN tTableName VARCHAR(60) NOT NULL DEFAULT ''"
