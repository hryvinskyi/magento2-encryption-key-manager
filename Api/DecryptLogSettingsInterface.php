<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Api;

use Magento\Framework\Exception\FileSystemException;
use Magento\Framework\Exception\RuntimeException;

/**
 * Whether decryptions under an old key are logged
 *
 * The switch lives in the deployment configuration (`bin/magento config:set --lock-env dev/debug/<field> 1`), not
 * in the database: the store decrypts while its configuration is still loading, so the switch cannot come from it.
 */
interface DecryptLogSettingsInterface
{
    /**
     * Path of the switch below the default scope of the deployment configuration's system section
     */
    public const CONFIG_PATH = 'dev/debug/log_old_key_decrypts';

    /**
     * Tell whether decryptions under an old key are logged
     *
     * @return bool true when the switch is on
     * @throws FileSystemException when the deployment configuration cannot be read
     * @throws RuntimeException when the deployment configuration is invalid
     */
    public function isEnabled(): bool;
}
