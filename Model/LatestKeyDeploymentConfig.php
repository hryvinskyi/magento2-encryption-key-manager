<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Model;

use Hryvinskyi\EncryptionKeyManager\Api\DeploymentKeysInterface;
use Magento\Framework\App\DeploymentConfig;

/**
 * The deployment configuration, except that the key ring reads as its active key alone
 *
 * Given to the factory of the keys that sign and verify JSON web tokens, so that a token signed with an older key of
 * the ring is refused as soon as a new key is appended. Releases that carry the fix for this do the same themselves;
 * there it changes nothing. The factory takes the configuration as this class, so the narrowing is a subclass.
 */
class LatestKeyDeploymentConfig extends DeploymentConfig
{
    /**
     * Read a value; the key ring yields its last entry only
     *
     * @param string|null $key the path, or null for the whole flattened configuration
     * @param mixed $defaultValue what to return when the path holds nothing
     * @return mixed the value
     * @throws \Magento\Framework\Exception\FileSystemException when the deployment configuration cannot be read
     * @throws \Magento\Framework\Exception\RuntimeException when the deployment configuration is invalid
     */
    public function get($key = null, $defaultValue = null)
    {
        $value = parent::get($key, $defaultValue);
        if ($key !== DeploymentKeysInterface::RING_PATH || !is_string($value)) {
            return $value;
        }
        $entries = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);
        if ($entries === false || $entries === []) {
            return $value;
        }

        return $entries[array_key_last($entries)];
    }
}
