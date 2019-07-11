/*
 Navicat Premium Data Transfer

 Source Server         : 
 Source Server Type    : MySQL
 Source Server Version : 50625
 Source Host           : 
 Source Schema         : spring-cloud-auth2-db

 Target Server Type    : MySQL
 Target Server Version : 50625
 File Encoding         : 65001

 Date: 11/07/2019 10:32:45
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for ClientDetails
-- ----------------------------
DROP TABLE IF EXISTS `ClientDetails`;
CREATE TABLE `ClientDetails` (
  `appId` varchar(128) COLLATE utf8_bin NOT NULL,
  `resourceIds` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `appSecret` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `scope` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `grantTypes` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `redirectUrl` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `authorities` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additionalInformation` varchar(4096) COLLATE utf8_bin DEFAULT NULL,
  `autoApproveScopes` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  PRIMARY KEY (`appId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Table structure for oauth_access_token
-- ----------------------------
DROP TABLE IF EXISTS `oauth_access_token`;
CREATE TABLE `oauth_access_token` (
  `token_id` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `token` blob,
  `authentication_id` varchar(128) COLLATE utf8_bin NOT NULL,
  `user_name` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `client_id` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `authentication` blob,
  `refresh_token` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  PRIMARY KEY (`authentication_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Table structure for oauth_approvals
-- ----------------------------
DROP TABLE IF EXISTS `oauth_approvals`;
CREATE TABLE `oauth_approvals` (
  `userId` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `clientId` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `scope` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `status` varchar(10) COLLATE utf8_bin DEFAULT NULL,
  `expiresAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `lastModifiedAt` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00'
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Table structure for oauth_client_details
-- ----------------------------
DROP TABLE IF EXISTS `oauth_client_details`;
CREATE TABLE `oauth_client_details` (
  `client_id` varchar(128) COLLATE utf8_bin NOT NULL,
  `resource_ids` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `client_secret` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `scope` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `authorized_grant_types` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `web_server_redirect_uri` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `authorities` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additional_information` varchar(4096) COLLATE utf8_bin DEFAULT NULL,
  `autoapprove` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Records of oauth_client_details
-- ----------------------------
BEGIN;
INSERT INTO `oauth_client_details` VALUES ('client_1', NULL, '{bcrypt}$2a$10$HBX6q6TndkgMxhSEdoFqWOUtctaJEMoXe49NWh8Owc.4MTunv.wXa', 'select', 'client_credentials,refresh_token', NULL, 'oauth2', NULL, NULL, NULL, NULL);
INSERT INTO `oauth_client_details` VALUES ('client_2', '', '{bcrypt}$2a$10$HBX6q6TndkgMxhSEdoFqWOUtctaJEMoXe49NWh8Owc.4MTunv.wXa', 'server', 'password,refresh_token', NULL, 'oauth2', NULL, NULL, NULL, NULL);
COMMIT;

-- ----------------------------
-- Table structure for oauth_client_token
-- ----------------------------
DROP TABLE IF EXISTS `oauth_client_token`;
CREATE TABLE `oauth_client_token` (
  `token_id` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `token` blob,
  `authentication_id` varchar(128) COLLATE utf8_bin NOT NULL,
  `user_name` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `client_id` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  PRIMARY KEY (`authentication_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Table structure for oauth_code
-- ----------------------------
DROP TABLE IF EXISTS `oauth_code`;
CREATE TABLE `oauth_code` (
  `code` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `authentication` blob
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Table structure for oauth_refresh_token
-- ----------------------------
DROP TABLE IF EXISTS `oauth_refresh_token`;
CREATE TABLE `oauth_refresh_token` (
  `token_id` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `token` blob,
  `authentication` blob
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Records of role
-- ----------------------------
BEGIN;
INSERT INTO `role` VALUES (1, 'USER');
INSERT INTO `role` VALUES (2, 'ADMIN');
INSERT INTO `role` VALUES (3, 'ROLE_ADMIN');
COMMIT;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `password` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `username` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UK_sb8bbouer5wak8vyiiy4pf2bx` (`username`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Records of user
-- ----------------------------
BEGIN;
INSERT INTO `user` VALUES (1, '{bcrypt}$2a$10$HBX6q6TndkgMxhSEdoFqWOUtctaJEMoXe49NWh8Owc.4MTunv.wXa', 'user_1');
INSERT INTO `user` VALUES (2, '{bcrypt}$2a$10$HBX6q6TndkgMxhSEdoFqWOUtctaJEMoXe49NWh8Owc.4MTunv.wXa', 'user_3');
INSERT INTO `user` VALUES (3, '{bcrypt}$2a$10$7qkIuNV0gLeCX8XVILhC3e0kVSNH0.kfLqYlk79vwwozb8YMAkhLi', 'user_4');
INSERT INTO `user` VALUES (4, '{bcrypt}$2a$10$P0zP/TVFw.A2kiOOgjJyF.NVWM1hU0WP/bm/KmWogA7TVUlIQApve', 'user_5');
INSERT INTO `user` VALUES (5, '{bcrypt}$2a$10$2dETIZ5llx5xY41GNVs1zuljRnntvi3JReCN3H7TEzB.CIO.IDIeC', 'user_6');
COMMIT;

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role` (
  `user_id` bigint(20) NOT NULL,
  `authorities_id` bigint(20) NOT NULL,
  KEY `FK2lybg7hi222csyc912id1arac` (`authorities_id`),
  KEY `FK859n2jvi8ivhui0rl0esws6o` (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Records of user_role
-- ----------------------------
BEGIN;
INSERT INTO `user_role` VALUES (4, 1);
INSERT INTO `user_role` VALUES (4, 2);
INSERT INTO `user_role` VALUES (4, 3);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
