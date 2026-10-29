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
use Magento\Framework\App\DeploymentConfig\Reader;

/**
 * The deployment configuration, except that the key ring reads as the pinned key alone
 *
 * The ring path answers with the pinned key whatever the files or the environment say: a `MAGENTO_DC_` variable
 * that overrides the store's ring must not move the pinned hashes with it. The encryptor takes its configuration as
 * this class's parent, so the substitution is a subclass.
 */
class PinnedKeyDeploymentConfig extends DeploymentConfig
{
    /**
     * @param Reader $reader reads the configuration files
     * @param string $pinnedKey the pinned key entry the ring path answers with
     */
    public function __construct(
        Reader $reader,
        private readonly string $pinnedKey
    ) {
        parent::__construct($reader);
    }

    /**
     * Read a value; the key ring yields the pinned key
     *
     * @param string|null $key the path, or null for the whole flattened configuration
     * @param mixed $defaultValue what to return when the path holds nothing
     * @return mixed the value
     * @throws \Magento\Framework\Exception\FileSystemException when the deployment configuration cannot be read
     * @throws \Magento\Framework\Exception\RuntimeException when the deployment configuration is invalid
     */
    public function get($key = null, $defaultValue = null)
    {
        return $key === DeploymentKeysInterface::RING_PATH ? $this->pinnedKey : parent::get($key, $defaultValue);
    }
}
