DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
    `uid` INTEGER NOT NULL UNIQUE,
    `idh` INTEGER NOT NULL,
    `idl` INTEGER NOT NULL,
    `home` TEXT NOT NULL,
    `shell` TEXT NOT NULL,
    `service` TEXT NOT NULL,
    CONSTRAINT `uk_id` UNIQUE(`idh`, `idl`)
);
