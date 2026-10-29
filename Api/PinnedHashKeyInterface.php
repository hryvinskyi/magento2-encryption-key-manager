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
 * The key that keyed hashes stay on while the key ring changes, when one is pinned
 *
 * The store hashes with its active key, the last of the ring, so appending a key changes every keyed hash. A hash
 * that names something lasting, such as the cache directory of a resized product image, is computed with the pinned
 * key instead and keeps its value through a rotation and after the old key leaves the ring.
 *
 * @api
 */
interface PinnedHashKeyInterface
{
    /**
     * Path of the pinned key in the deployment configuration
     */
    public const CONFIG_PATH = 'crypt/pinned_hash_key';

    /**
     * Read the pinned key
     *
     * @return string|null the key entry exactly as the ring held it, or null when no key is pinned
     * @throws FileSystemException when the deployment configuration cannot be read
     * @throws RuntimeException when the deployment configuration is invalid
     */
    public function get(): ?string;
}
