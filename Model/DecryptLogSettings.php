<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Model;

use Hryvinskyi\EncryptionKeyManager\Api\DecryptLogSettingsInterface;
use Magento\Framework\App\DeploymentConfig;

/**
 * Reads the decryption log switch from the default scope of the deployment configuration's system section
 */
class DecryptLogSettings implements DecryptLogSettingsInterface
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
    public function isEnabled(): bool
    {
        $value = $this->deploymentConfig->get('system/default/' . self::CONFIG_PATH);

        return is_bool($value) ? $value : is_scalar($value) && filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
}
