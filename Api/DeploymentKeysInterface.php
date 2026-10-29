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
 * The keys the deployment configuration holds: the key ring, and the keys taken out of it and kept aside
 *
 * Both are whitespace-separated lists of entries, read exactly as written: an entry is never decoded or trimmed
 * of anything but the whitespace that separates it from the next.
 */
interface DeploymentKeysInterface
{
    /**
     * Path of the key ring; its last entry is the active key
     */
    public const RING_PATH = 'crypt/key';

    /**
     * Path of the keys taken out of the ring and kept aside
     */
    public const INVALIDATED_PATH = 'crypt/invalidated_key';

    /**
     * Read the key ring
     *
     * @return list<string> the ring's entries by slot, the active key last; empty when no ring is configured
     * @throws FileSystemException when the deployment configuration cannot be read
     * @throws RuntimeException when the deployment configuration is invalid
     */
    public function ring(): array;

    /**
     * Read the keys taken out of the ring
     *
     * @return list<string> the kept keys in the order they were taken out; empty when there are none
     * @throws FileSystemException when the deployment configuration cannot be read
     * @throws RuntimeException when the deployment configuration is invalid
     */
    public function invalidated(): array;
}
