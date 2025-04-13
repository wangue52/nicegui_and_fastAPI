-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Mar 23, 2025 at 09:05 AM
-- Server version: 8.0.30
-- PHP Version: 8.1.10

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `location`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int NOT NULL,
  `uuid` varchar(36) DEFAULT NULL,
  `username` varchar(50) DEFAULT NULL,
  `email` varchar(120) NOT NULL,
  `password_hash` varchar(512) DEFAULT NULL,
  `display_name` varchar(100) DEFAULT NULL,
  `avatar_url` varchar(500) DEFAULT NULL,
  `bio` text,
  `website` varchar(200) DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `preferred_language` varchar(5) DEFAULT NULL,
  `is_confirmed` tinyint(1) DEFAULT NULL,
  `confirmation_token` varchar(100) DEFAULT NULL,
  `password_reset_token` varchar(100) DEFAULT NULL,
  `two_factor_enabled` tinyint(1) DEFAULT NULL,
  `two_factor_secret` varchar(16) DEFAULT NULL,
  `failed_login_attempts` int DEFAULT NULL,
  `last_password_change` datetime DEFAULT NULL,
  `role_id` int DEFAULT NULL,
  `permissions` json DEFAULT NULL,
  `social_provider` varchar(20) DEFAULT NULL,
  `social_id` varchar(100) DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `last_activity` datetime DEFAULT NULL,
  `login_count` int DEFAULT NULL,
  `reputation_score` int DEFAULT NULL,
  `is_private` tinyint(1) DEFAULT NULL,
  `terms_accepted` tinyint(1) DEFAULT NULL,
  `newsletter_subscribed` tinyint(1) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  `is_deleted` tinyint(1) DEFAULT NULL,
  `deactivation_reason` text,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `uuid`, `username`, `email`, `password_hash`, `display_name`, `avatar_url`, `bio`, `website`, `location`, `preferred_language`, `is_confirmed`, `confirmation_token`, `password_reset_token`, `two_factor_enabled`, `two_factor_secret`, `failed_login_attempts`, `last_password_change`, `role_id`, `permissions`, `social_provider`, `social_id`, `last_login`, `last_activity`, `login_count`, `reputation_score`, `is_private`, `terms_accepted`, `newsletter_subscribed`, `is_active`, `is_deleted`, `deactivation_reason`, `created_at`, `updated_at`, `last_seen`) VALUES
(2, '925b984f627d4e061a5081a6bd6fb02b', 'wangue sonfack', 'wilfriedwangue8@gmail.com', 'scrypt:32768:8:1$NisBqtXW5YphMmkZ$23ad72a3566428d54de0d448e4c6ebf485d60355ea94a17de1894cb031db0cec888b0ba3ed5c95d49179db5bd712b6e50e96e2c5315a8a314372f5ff42038297', 'wangue sonfack', NULL, NULL, NULL, NULL, 'fr', 1, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 1, 1, 1, 0, NULL, '2025-03-16 15:18:45', NULL, '2025-03-02 17:29:10');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `ix_users_email` (`email`),
  ADD UNIQUE KEY `uuid` (`uuid`),
  ADD UNIQUE KEY `ix_users_username` (`username`),
  ADD KEY `role_id` (`role_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `users_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
