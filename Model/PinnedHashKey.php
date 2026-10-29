<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Model;

use Hryvinskyi\EncryptionKeyManager\Api\PinnedHashKeyInterface;
use Magento\Framework\App\DeploymentConfig;

/**
 * Reads the pinned key from the deployment configuration; a blank value is no pin
 */
class PinnedHashKey implements PinnedHashKeyInterface
{
    /**
     * @param DeploymentConfig $deploymentConfig the store's deployment configuration
     */
    public function __construct(
        private readonly DeploymentConfig $deploymentConfig
    ) {
    }

    /**
     * @inheritDoc
     */
    public function get(): ?string
    {
        $value = $this->deploymentConfig->get(self::CONFIG_PATH);
        if (!is_string($value)) {
            return null;
        }
        $key = trim($value);

        return $key === '' ? null : $key;
    }
}
