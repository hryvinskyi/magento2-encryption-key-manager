# Magento 2 encryption key manager

The runtime side of an encryption key rotation on Magento 2.4.4 to 2.4.6. The rotation itself (new key, re-encryption,
retire, rollback) is done by [magento2-encryption-key-rotator](https://github.com/hryvinskyi/magento2-encryption-key-rotator);
this module covers what has to happen inside Magento while the store runs.

- **Product image cache paths stay where they are.** Up to 2.4.6, Magento names the cache directory of every resized
  product image (`media/catalog/product/cache/<hash>/…`) with a keyed hash of the active key. Appending a key changes
  every name, and the whole image cache is generated again. With a pinned key the hash stays the one the store
  computed while that key was active, through the rotation and after the old key leaves the ring.
- **JSON web tokens are signed and verified with the newest key only**, so a token signed with an old key stops
  working as soon as a new key is appended. Releases with the fix for CVE-2024-34102 already do this; there it
  changes nothing.
- **Decryptions under an old key can be logged.** Between re-encrypting and retiring, every log line names code that
  still needs an old key. Off by default.

On 2.4.8 the image cache path no longer depends on the key and core already signs tokens with the newest key, so only
the decryption log does anything there.

## Install

```sh
composer require hryvinskyi/magento2-encryption-key-manager
bin/magento setup:upgrade
bin/magento setup:di:compile
```

## Pin the image hash key

The pin is the key the image cache paths were hashed with. Write it **before the first key is appended to the ring**,
or before the first request after a deploy that removes another way of pinning it:

```sh
# The store has never rotated: pin the active key, the one it hashes with now
bin/magento encryption:hash-key:pin

# An earlier rotation took the old key out of the ring and kept it in crypt/invalidated_key:
# pin that kept key by its position there, from 0
bin/magento encryption:hash-key:pin --invalidated=0
```

The command copies the key from `app/etc/env.php` to `crypt/pinned_hash_key` in the same file and prints its
fingerprint (the first 16 hex characters of the SHA-256 of the key bytes), never the key. `--slot=<n>` pins another
slot of the ring. A pin that is already there is kept unless `--replace` is given, since replacing it moves every
image to a new cache directory. A slot that holds a retired key's `invalid…` placeholder is refused.

Check it on the storefront: the image URLs of a category page keep their cache directory names.

The pinned key stays in `env.php` for good. It only feeds the keyed hash of image paths, which are public anyway;
nothing is decrypted with it. If your hosting provider keeps its own copy of `env.php`, give them the file after
pinning. If PHP-FPM's opcache does not revalidate `env.php`, reload PHP-FPM.

## Log decryptions under an old key

```sh
bin/magento config:set --lock-env dev/debug/log_old_key_decrypts 1
```

Lines go to `var/log/encryption_key_decrypts.log` with the value's key index, the active index, the call stack
without arguments and an id of that stack. The value and what it decrypts to are never logged. Switch it on after the
re-encryption and watch it for a few days before retiring the old keys: after a complete re-encryption it should stay
empty. It sees values in the `<index>:<version>:…` form only; the oldest one- and two-part forms, which name no key
index, are not logged. It checks every decryption under an old key, so switch it off afterwards:

```sh
bin/magento config:set --lock-env dev/debug/log_old_key_decrypts 0
```

## With the rotator

1. Install this module and pin the image hash key.
2. `key-rotator.phar rotate`.
3. Switch the decryption log on; nothing should appear. Switch it off.
4. `key-rotator.phar retire`, later `purge`.

## Licence

MIT.
