<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Api;

use Magento\Framework\Exception\LocalizedException;

/**
 * Pins keyed hashes to one key by writing it to the deployment configuration
 *
 * The key is copied from the ring or from the keys taken out of it, never typed in, so it is always one the store
 * has hashed with. A pin is written once: replacing it changes every pinned hash, so it needs to be asked for.
 * Neither method shows a key; each returns the key's fingerprint, the first 16 hexadecimal characters of the
 * SHA-256 of its bytes.
 *
 * @api
 */
interface HashKeyPinnerInterface
{
    /**
     * Pin keyed hashes to the key in a slot of the ring
     *
     * @param int|null $slot the ring slot, or null for the active key: the one the store hashes with now
     * @param bool $replace whether a key that is already pinned may be replaced
     * @return string the fingerprint of the pinned key
     * @throws LocalizedException when the slot holds no key or a retired key's placeholder, when a key is already
     *                            pinned and may not be replaced, or when the deployment configuration cannot be written
     */
    public function pinRingKey(?int $slot, bool $replace): string;

    /**
     * Pin keyed hashes to one of the keys taken out of the ring
     *
     * @param int $position the key's position among the kept keys, from 0 in the order they were taken out
     * @param bool $replace whether a key that is already pinned may be replaced
     * @return string the fingerprint of the pinned key
     * @throws LocalizedException when there is no kept key at that position or it is a retired key's placeholder,
     *                            when a key is already pinned and may not be replaced, or when the deployment
     *                            configuration cannot be written
     */
    public function pinInvalidatedKey(int $position, bool $replace): string;
}
