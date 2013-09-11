SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";
CREATE DATABASE IF NOT EXISTS `cyber_kippo` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `cyber_kippo`;

CREATE TABLE IF NOT EXISTS `auth` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` char(32) NOT NULL,
  `success` tinyint(1) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `cif` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` char(32) NOT NULL,
  `purpose` varchar(50) DEFAULT NULL,
  `asn` int(4) DEFAULT NULL,
  `asn_desc` tinytext,
  `portlist` text,
  `rir` varchar(15) DEFAULT NULL,
  `alternativeid` tinytext,
  `alternativeid_restriction` varchar(50) DEFAULT NULL,
  `cc` char(2) DEFAULT NULL,
  `severity` varchar(50) DEFAULT NULL,
  `assessment` varchar(50) DEFAULT NULL,
  `description` tinytext,
  `detecttime` datetime DEFAULT NULL,
  `reporttime` datetime DEFAULT NULL,
  `confidence` int(3) DEFAULT NULL,
  `restriction` varchar(50) DEFAULT NULL,
  `prefix` varchar(18) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `clients` (
  `id` int(4) NOT NULL AUTO_INCREMENT,
  `version` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `url` text NOT NULL,
  `outfile` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `session` (`session`,`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `input` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `realm` varchar(50) DEFAULT NULL,
  `success` tinyint(1) DEFAULT NULL,
  `input` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `session` (`session`,`timestamp`,`realm`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(15) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `sessions` (
  `id` char(32) NOT NULL,
  `starttime` datetime NOT NULL,
  `endtime` datetime DEFAULT NULL,
  `sensor` int(4) NOT NULL,
  `ip` varchar(15) NOT NULL DEFAULT '',
  `termsize` varchar(7) DEFAULT NULL,
  `client` int(4) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `starttime` (`starttime`,`sensor`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `ttylog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` char(32) NOT NULL,
  `ttylog` mediumblob NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
