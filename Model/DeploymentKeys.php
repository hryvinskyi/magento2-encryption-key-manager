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
 * Reads the key ring and the kept keys from the deployment configuration
 */
class DeploymentKeys implements DeploymentKeysInterface
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
    public function ring(): array
    {
        return $this->entries(self::RING_PATH);
    }

    /**
     * @inheritDoc
     */
    public function invalidated(): array
    {
        return $this->entries(self::INVALIDATED_PATH);
    }

    /**
     * Split the list at a path into its entries
     *
     * @param string $path the deployment configuration path
     * @return list<string> the entries; empty when the path holds no string
     * @throws \Magento\Framework\Exception\FileSystemException when the deployment configuration cannot be read
     * @throws \Magento\Framework\Exception\RuntimeException when the deployment configuration is invalid
     */
    private function entries(string $path): array
    {
        $value = $this->deploymentConfig->get($path);
        if (!is_string($value)) {
            return [];
        }
        $entries = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);

        return $entries === false ? [] : $entries;
    }
}
