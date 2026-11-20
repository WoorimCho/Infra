-- Runs once, on first initialisation of the shared MySQL container.
-- One instance, one schema per service. `myuser` is created by the image from
-- MYSQL_USER / MYSQL_PASSWORD; it needs granting on the schemas beyond MYSQL_DATABASE.

CREATE DATABASE IF NOT EXISTS `mydatabase`;         -- monolith / BFF
CREATE DATABASE IF NOT EXISTS `ingredient_catalogue`;
CREATE DATABASE IF NOT EXISTS `recipe_catalogue`;
CREATE DATABASE IF NOT EXISTS `user_service`;

GRANT ALL PRIVILEGES ON `mydatabase`.*        TO 'myuser'@'%';
GRANT ALL PRIVILEGES ON `ingredient_catalogue`.* TO 'myuser'@'%';
GRANT ALL PRIVILEGES ON `recipe_catalogue`.*     TO 'myuser'@'%';
GRANT ALL PRIVILEGES ON `user_service`.*       TO 'myuser'@'%';
FLUSH PRIVILEGES;
